//! Durable at-least-once business tasks. Invoke [`drain`] from a scheduled,
//! IAM-only Lambda, or [`tick`] from a native loop. External providers must
//! honor the task idempotency key.
use super::{
    App, DOCUMENT,
    extensions::{Actor, Context},
};
use crate::ApiError;
use serde_json::{Value, json};
use uuid::Uuid;

/// Execute at most one queued task, recovering expired leases.
/// # Errors
/// Returns database errors. Handler failures are stored and retried with backoff.
pub async fn tick(app: &App) -> Result<bool, ApiError> {
    let token = Uuid::new_v4();
    let job:Option<(Uuid,String,Value,Value,String)>=sqlx::query_as("UPDATE app_tasks SET state='running',attempts=attempts+1,lease_token=$1,lease_until=now()+interval '120 seconds',updated=now() WHERE id=(SELECT id FROM app_tasks WHERE attempts<5 AND ((state='queued' AND available<=now()) OR (state='running' AND lease_until<=now())) ORDER BY available,created FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,name,input,actor,idempotency_key").bind(token).fetch_optional(&app.pool).await.map_err(ApiError::internal)?;
    let Some((id, name, input, actor, key)) = job else {
        sqlx::query("UPDATE app_tasks SET state='failed',error='Retry limit exhausted',updated=now() WHERE state='running' AND lease_until<=now() AND attempts>=5").execute(&app.pool).await.map_err(ApiError::internal)?;
        return Ok(false);
    };
    let work = async {
        let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
        // The application write lock is taken at the handler's first write, so
        // calls to outside services before it do not hold up the app's users.
        let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_tasks WHERE id=$1 AND lease_token=$2 AND lease_until>now() AND state='running')").bind(id).bind(token).fetch_one(&mut *tx).await.map_err(ApiError::internal)?;
        if !live {
            return Err(ApiError::Conflict("Task lease expired".into()));
        }
        // Scheduled tasks run as the app; others as the person whose write queued them.
        let actor = if actor["system"] == true {
            Actor::system()
        } else {
            let user: Value = sqlx::query_scalar(&format!(
                "SELECT {DOCUMENT} FROM app_records WHERE kind='users' AND id=$1"
            ))
            .bind(
                Uuid::parse_str(actor["id"].as_str().unwrap_or_default())
                    .map_err(ApiError::internal)?,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?
            .ok_or(ApiError::Forbidden)?;
            app.actor(&user).await?
        };
        let handler = app.registry.tasks.get(&name).ok_or(ApiError::NotFound)?;
        let result = handler
            .run(
                &mut Context::deferred(&mut tx, &app.registry, actor, app.pool.clone()),
                json!({"task_id":id,"idempotency_key":key,"data":input}),
            )
            .await?;
        let updated=sqlx::query("UPDATE app_tasks SET state='completed',result=$3,lease_until=NULL,error=NULL,updated=now() WHERE id=$1 AND lease_token=$2 AND lease_until>now()").bind(id).bind(token).bind(result).execute(&mut *tx).await.map_err(ApiError::internal)?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::Conflict("Task lease expired".into()));
        }
        tx.commit().await.map_err(ApiError::internal)
    };
    // A failure keeps the handler's own explanation, so whoever looks at the
    // queue sees why (an outside service refusing, a record that changed).
    let failure = match tokio::time::timeout(std::time::Duration::from_secs(60), work).await {
        Ok(Ok(())) => None,
        Ok(Err(ApiError::Validation(fields))) => {
            Some(format!("Validation failed: {}", json!(fields)))
        }
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some("Timed out after 60 seconds".to_owned()),
    };
    if let Some(failure) = failure {
        let failure: String = failure.chars().take(1000).collect();
        sqlx::query("UPDATE app_tasks SET state=CASE WHEN attempts>=5 THEN 'failed' ELSE 'queued' END,error=$3,available=now()+make_interval(secs=>least(300,power(2,attempts)::int)),lease_until=NULL,updated=now() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).bind(failure).execute(&app.pool).await.map_err(ApiError::internal)?;
    }
    Ok(true)
}

/// Queue each scheduled task for the current period, once. Periods are counted
/// from the Unix epoch in the database's clock, so every runner agrees.
///
/// # Errors
/// Returns database errors.
pub async fn enqueue_scheduled(app: &App) -> Result<(), ApiError> {
    for (task, every) in &app.registry.schedules {
        let seconds = i64::try_from(every.as_secs()).map_err(ApiError::internal)?;
        sqlx::query("INSERT INTO app_tasks(id,name,idempotency_key,input,actor) VALUES($1,$2,'schedule:'||floor(extract(epoch from now())/$3)::bigint,'{}'::jsonb,'{\"system\":true}'::jsonb) ON CONFLICT(name,idempotency_key) DO NOTHING")
            .bind(Uuid::new_v4())
            .bind(task)
            .bind(seconds)
            .execute(&app.pool)
            .await
            .map_err(ApiError::internal)?;
    }
    // Finished scheduled runs pile up; a week of them is history enough.
    sqlx::query("DELETE FROM app_tasks WHERE state='completed' AND idempotency_key LIKE 'schedule:%' AND updated<now()-interval '7 days'")
        .execute(&app.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// Queue the scheduled tasks that are due, then execute queued tasks one after
/// another until none is due or `budget` has passed, and return how many ran. A task started near the end of the budget
/// may run for up to 60 seconds more, so give the host that much headroom.
///
/// # Errors
/// Returns database errors from claiming work.
pub async fn drain(app: &App, budget: std::time::Duration) -> Result<usize, ApiError> {
    let started = std::time::Instant::now();
    enqueue_scheduled(app).await?;
    let mut processed = 0;
    while started.elapsed() < budget && tick(app).await? {
        processed += 1;
    }
    Ok(processed)
}
