//! Writes to the built-in resources people administer: roles, and the roles a
//! user holds. Everything else built in stays read-only through the API.
//!
//! Superusers may always manage roles and users; anyone else needs a held
//! role whose access map grants the operation on `roles` or `users`.
use super::{App, DOCUMENT, extensions::Actor, public_record, singular};
use crate::{ApiError, FieldErrors};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

/// Role names that grants in code already mean something by.
const RESERVED_ROLES: [&str; 2] = ["*", "authenticated"];

fn invalid(field: &str, message: &str) -> ApiError {
    ApiError::Validation(FieldErrors::from([(field.into(), vec![message.into()])]))
}

/// Apply one write to a built-in record and return its public form.
///
/// # Errors
/// Rejects unsupported kinds and operations with 405, missing grants with
/// 403, and malformed input with field errors.
#[allow(clippy::too_many_lines)]
pub(super) async fn write(
    app: &App,
    connection: &mut PgConnection,
    actor: &Actor,
    kind: &str,
    id: Option<Uuid>,
    input: Value,
    method: &str,
) -> Result<Value, ApiError> {
    let operation = match method {
        "POST" => "create",
        "PATCH" | "PUT" => "update",
        _ => "delete",
    };
    if !super::core_supports(kind, operation) {
        return Err(ApiError::MethodNotAllowed(method.to_owned()));
    }
    if !actor.granted(kind, operation) {
        return Err(ApiError::Forbidden);
    }
    let input = match input {
        Value::Object(map) if map.len() == 1 && map.contains_key(singular(kind)) => {
            map.into_iter().next().map_or(Value::Null, |(_, v)| v)
        }
        other => other,
    };
    if !input.is_object() {
        return Err(ApiError::Parse("Expected a JSON object.".into()));
    }
    let record = match (kind, operation) {
        ("roles", "create") => {
            let id = Uuid::new_v4();
            let data = role_data(app, connection, id, &json!({"permissions":{}}), &input).await?;
            sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'roles',$2)")
                .bind(id)
                .bind(&data)
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            fetch(connection, kind, id).await?
        }
        ("roles", "update") => {
            let id = id.ok_or(ApiError::NotFound)?;
            let current = fetch(connection, kind, id).await?;
            let data = role_data(app, connection, id, &current, &input).await?;
            sqlx::query(
                "UPDATE app_records SET data=$2,updated=now() WHERE kind='roles' AND id=$1",
            )
            .bind(id)
            .bind(&data)
            .execute(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
            fetch(connection, kind, id).await?
        }
        ("dashboards" | "views", "create") => {
            let id = Uuid::new_v4();
            let data = page_data(app, kind, &json!({"data":{}}), &input)?;
            sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,$2,$3)")
                .bind(id)
                .bind(kind)
                .bind(&data)
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            fetch(connection, kind, id).await?
        }
        ("dashboards" | "views", "update") => {
            let id = id.ok_or(ApiError::NotFound)?;
            let current = raw(connection, kind, id).await?;
            let data = page_data(app, kind, &current, &input)?;
            sqlx::query("UPDATE app_records SET data=$3,updated=now() WHERE kind=$2 AND id=$1")
                .bind(id)
                .bind(kind)
                .bind(&data)
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            fetch(connection, kind, id).await?
        }
        ("dashboards" | "views", "delete") => {
            let id = id.ok_or(ApiError::NotFound)?;
            let current = fetch(connection, kind, id).await?;
            sqlx::query("DELETE FROM app_records WHERE kind=$2 AND id=$1")
                .bind(id)
                .bind(kind)
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            current
        }
        ("roles", "delete") => {
            let id = id.ok_or(ApiError::NotFound)?;
            let current = fetch(connection, kind, id).await?;
            // Users keep working with their remaining roles.
            sqlx::query("UPDATE app_records SET data=jsonb_set(data,'{data,roles}',(data->'data'->'roles') - $1::text),updated=now() WHERE kind='users' AND data->'data'->'roles' ? $1::text")
                .bind(id.to_string())
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            sqlx::query("DELETE FROM app_records WHERE kind='roles' AND id=$1")
                .bind(id)
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            current
        }
        _ => {
            let id = id.ok_or(ApiError::NotFound)?;
            let mut data = raw(connection, kind, id).await?["data"].take();
            if let Some(name) = input.get("name") {
                let name = name.as_str().map(str::trim).filter(|n| !n.is_empty());
                let Some(name) = name.filter(|n| n.chars().count() <= 200) else {
                    return Err(invalid("name", "Name must be 1 to 200 characters."));
                };
                sqlx::query("UPDATE app_records SET data=jsonb_set(data,'{name}',$2),updated=now() WHERE kind='users' AND id=$1")
                    .bind(id)
                    .bind(json!(name))
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
            }
            if let Some(roles) = input.get("roles") {
                let ids = role_ids(connection, roles).await?;
                if data.is_null() {
                    data = json!({});
                }
                data["roles"] = json!(ids);
                sqlx::query("UPDATE app_records SET data=jsonb_set(data,'{data}',$2),updated=now() WHERE kind='users' AND id=$1")
                    .bind(id)
                    .bind(&data)
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
            }
            fetch(connection, kind, id).await?
        }
    };
    Ok(record)
}

async fn raw(connection: &mut PgConnection, kind: &str, id: Uuid) -> Result<Value, ApiError> {
    sqlx::query_scalar(&format!(
        "SELECT {DOCUMENT} FROM app_records WHERE kind=$1 AND id=$2"
    ))
    .bind(kind)
    .bind(id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?
    .ok_or(ApiError::NotFound)
}
async fn fetch(connection: &mut PgConnection, kind: &str, id: Uuid) -> Result<Value, ApiError> {
    Ok(public_record(kind, raw(connection, kind, id).await?))
}

/// The stored form of a role after applying `input` to `current`.
async fn role_data(
    app: &App,
    connection: &mut PgConnection,
    id: Uuid,
    current: &Value,
    input: &Value,
) -> Result<Value, ApiError> {
    let name = input.get("name").or_else(|| current.get("name"));
    let name = name
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.chars().count() <= 100)
        .ok_or_else(|| invalid("name", "Name must be 1 to 100 characters."))?;
    if RESERVED_ROLES.contains(&name) {
        return Err(invalid("name", "This name is reserved."));
    }
    let taken: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_records WHERE kind='roles' AND id<>$1 AND lower(data->>'name')=lower($2))")
        .bind(id).bind(name).fetch_one(&mut *connection).await.map_err(ApiError::internal)?;
    if taken {
        return Err(invalid("name", "A role with this name already exists."));
    }
    let permissions = input
        .get("permissions")
        .or_else(|| current.get("permissions"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    crate::parse_access_map(&permissions, &app.access_targets())
        .map_err(|message| invalid("permissions", &message))?;
    let mut record = json!({"name":name,"permissions":permissions});
    for key in ["managed", "description"] {
        if let Some(value) = current.get(key) {
            record[key] = value.clone();
        }
    }
    Ok(record)
}

/// The stored form of a dashboard or a saved view: a name, free-form `data`
/// the admin owns, and for views the resource they belong to.
fn page_data(app: &App, kind: &str, current: &Value, input: &Value) -> Result<Value, ApiError> {
    let name = input
        .get("name")
        .or_else(|| current.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.chars().count() <= 200)
        .ok_or_else(|| invalid("name", "Name must be 1 to 200 characters."))?;
    let data = input
        .get("data")
        .or_else(|| current.get("data"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !data.is_object() || data.to_string().len() > 64_000 {
        return Err(invalid("data", "Data must be an object up to 64 KB."));
    }
    let mut record = json!({"name":name,"data":data});
    if kind == "views" {
        let resource = input
            .get("resource")
            .or_else(|| current.get("resource"))
            .and_then(Value::as_str)
            .filter(|r| super::KINDS.contains(r) || app.registry.models.contains_key(*r))
            .ok_or_else(|| invalid("resource", "Choose one of this app's resources."))?;
        record["resource"] = json!(resource);
    }
    Ok(record)
}

/// Every operation on every resource: what the managed Admin role grants.
pub(crate) fn admin_access_map(app_models: impl Iterator<Item = String>) -> Value {
    let all = json!({"list":true,"read":true,"create":true,"update":true,"delete":true});
    let mut map = serde_json::Map::new();
    for kind in super::KINDS {
        map.insert(
            kind.into(),
            match kind {
                "roles" | "dashboards" | "views" => all.clone(),
                "users" => json!({"list":true,"read":true,"update":true}),
                _ => json!({"list":true,"read":true}),
            },
        );
    }
    for model in app_models {
        map.insert(model, all.clone());
    }
    Value::Object(map)
}

/// The Admin role that grants everything, created on first use and kept in step
/// with the registered models. The name is fixed; other roles are the owner's.
pub async fn ensure_admin_role(
    connection: &mut PgConnection,
    models: impl Iterator<Item = String>,
) -> Result<Uuid, ApiError> {
    let permissions = admin_access_map(models);
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM app_records WHERE kind='roles' AND lower(data->>'name')='admin' ORDER BY created,id LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    let id = existing.unwrap_or_else(Uuid::new_v4);
    sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'roles',$2) ON CONFLICT(id) DO UPDATE SET data=jsonb_set(app_records.data,'{permissions}',$3),updated=now() WHERE app_records.data->'permissions' IS DISTINCT FROM $3")
        .bind(id)
        .bind(json!({"name":"Admin","permissions":permissions,"managed":true,"description":"Full access to every resource. Managed by the app; make other roles for narrower access."}))
        .bind(&permissions)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(id)
}

/// Give a signing-in superuser the Admin role, so the owner's own record shows
/// and carries the access the platform already guarantees them.
pub(crate) async fn admit_superuser(
    app: &App,
    connection: &mut PgConnection,
    user: Uuid,
    email: &str,
) -> Result<(), ApiError> {
    if !app.superusers.contains(&email.trim().to_ascii_lowercase()) {
        return Ok(());
    }
    let admin = ensure_admin_role(connection, app.registry.models.keys().cloned()).await?;
    sqlx::query("UPDATE app_records SET data=jsonb_set(data,'{data,roles}',coalesce(data->'data'->'roles','[]'::jsonb)||to_jsonb($2::text)),updated=now() WHERE kind='users' AND id=$1 AND NOT coalesce(data->'data'->'roles','[]'::jsonb) ? $2::text")
        .bind(user)
        .bind(admin.to_string())
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// Validate the role ids assigned to a user: each must be an existing role.
async fn role_ids(connection: &mut PgConnection, value: &Value) -> Result<Vec<String>, ApiError> {
    let Some(items) = value.as_array() else {
        return Err(invalid("roles", "Roles must be a list of role ids."));
    };
    let mut ids = Vec::new();
    for item in items {
        let id = item
            .as_str()
            .or_else(|| item["id"].as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| invalid("roles", "Roles must be a list of role ids."))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let known: i64 =
        sqlx::query_scalar("SELECT count(*) FROM app_records WHERE kind='roles' AND id=ANY($1)")
            .bind(&ids)
            .fetch_one(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
    if usize::try_from(known).unwrap_or_default() != ids.len() {
        return Err(invalid("roles", "Unknown role."));
    }
    Ok(ids.iter().map(Uuid::to_string).collect())
}
