//! Durable at-least-once business tasks. Invoke tick from a scheduled, IAM-only
//! Lambda or a native loop. External providers must honor the task idempotency key.
use super::{
    App, DOCUMENT,
    extensions::{Context, lock},
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
        lock(&mut tx).await?;
        let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_tasks WHERE id=$1 AND lease_token=$2 AND lease_until>now() AND state='running')").bind(id).bind(token).fetch_one(&mut *tx).await.map_err(ApiError::internal)?;
        if !live {
            return Err(ApiError::Conflict("Task lease expired".into()));
        }
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
        let handler = app.registry.tasks.get(&name).ok_or(ApiError::NotFound)?;
        let result = handler
            .run(
                &mut Context::new(&mut tx, &app.registry, app.actor(&user).await?),
                json!({"task_id":id,"idempotency_key":key,"data":input}),
            )
            .await?;
        let updated=sqlx::query("UPDATE app_tasks SET state='completed',result=$3,lease_until=NULL,error=NULL,updated=now() WHERE id=$1 AND lease_token=$2 AND lease_until>now()").bind(id).bind(token).bind(result).execute(&mut *tx).await.map_err(ApiError::internal)?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::Conflict("Task lease expired".into()));
        }
        tx.commit().await.map_err(ApiError::internal)
    };
    match tokio::time::timeout(std::time::Duration::from_secs(60), work).await {
        Ok(Ok(())) => {}
        _ => {
            sqlx::query("UPDATE app_tasks SET state=CASE WHEN attempts>=5 THEN 'failed' ELSE 'queued' END,error='Task execution failed; retry with the same idempotency key',available=now()+make_interval(secs=>least(300,power(2,attempts)::int)),lease_until=NULL,updated=now() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).execute(&app.pool).await.map_err(ApiError::internal)?;
        }
    }
    Ok(true)
}
