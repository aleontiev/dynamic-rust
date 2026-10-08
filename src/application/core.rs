//! Writes to the built-in resources people administer: roles, and the users
//! who may sign in and the roles they hold. Everything else built in stays
//! read-only through the API.
//!
//! Superusers may always manage roles and users; anyone else needs a held
//! role whose access map grants the operation on `roles` or `users`.
use super::{App, DOCUMENT, extensions::Actor, public_record, singular};
use crate::{ApiError, FieldErrors};
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::collections::BTreeSet;
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
        ("users", "create") => {
            // Adding a person is how they come to be able to sign in.
            let email = input
                .get("email")
                .and_then(Value::as_str)
                .map(super::magic_auth::email)
                .transpose()
                .map_err(|_| invalid("email", "Enter a valid email address."))?
                .ok_or_else(|| invalid("email", "Enter a valid email address."))?;
            let taken: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_records WHERE kind='users' AND lower(data->>'email')=$1)")
                .bind(&email).fetch_one(&mut *connection).await.map_err(ApiError::internal)?;
            if taken {
                return Err(invalid(
                    "email",
                    "A user with this email address already exists.",
                ));
            }
            let name = input
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(&email);
            if name.chars().count() > 200 {
                return Err(invalid("name", "Name must be 1 to 200 characters."));
            }
            let roles = match input.get("roles") {
                Some(roles) => role_ids(connection, roles).await?,
                None => vec![],
            };
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
                .bind(id)
                .bind(json!({"name":name,"email":email,"data":{"roles":roles}}))
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            fetch(connection, kind, id).await?
        }
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
            // The stored record, so what the public form leaves out is kept.
            let current = raw(connection, kind, id).await?;
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
        ("users", "delete") => {
            // Removing a person ends their sessions and sign-in identities; the
            // records they made stay. Nobody removes themselves.
            let id = id.ok_or(ApiError::NotFound)?;
            if actor.id == id.to_string() {
                return Err(invalid("id", "You cannot remove your own account."));
            }
            let current = fetch(connection, kind, id).await?;
            sqlx::query("DELETE FROM app_sessions WHERE user_id=$1")
                .bind(id)
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            sqlx::query("DELETE FROM app_records WHERE kind IN ('identities','identity_verifications') AND data->>'user'=$1")
                .bind(id.to_string())
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            // Their own connections to services go with them; the provider the
            // code registers stops naming them.
            for field in super::integrations::user_links(&app.registry) {
                sqlx::query("DELETE FROM app_integration_secrets WHERE provider IN (SELECT (data->>'integration')||':'||id FROM app_records WHERE kind='providers' AND data->>$1=$2 AND data->>'primary'='false')")
                    .bind(&field)
                    .bind(id.to_string())
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
                sqlx::query("DELETE FROM app_records WHERE kind='providers' AND data->>$1=$2 AND data->>'primary'='false'")
                    .bind(&field)
                    .bind(id.to_string())
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
                sqlx::query("UPDATE app_records SET data=data-$1::text,updated=now() WHERE kind='providers' AND data->>$1=$2")
                    .bind(&field)
                    .bind(id.to_string())
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
            }
            sqlx::query("DELETE FROM app_records WHERE kind='users' AND id=$1")
                .bind(id)
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
    crate::parse_access_map_with_actions(
        &permissions,
        &app.access_targets(),
        &app.registry.action_targets(),
    )
    .map_err(|message| invalid("permissions", &message))?;
    let mut record = json!({"name":name,"permissions":permissions});
    // A role the app ships keeps which one it is and the defaults it was given,
    // which is how a later release tells whether anyone has changed it.
    for key in [
        "shipped",
        "description",
        "default_permissions",
        "managed",
        "admin_defaults_version",
        "admin_known",
    ] {
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

/// Every operation on every resource and every action: the default Admin role.
pub(crate) fn admin_access_map(registry: &super::extensions::Registry) -> Value {
    let all = json!({"list":true,"read":true,"create":true,"update":true,"delete":true});
    let mut map = serde_json::Map::new();
    for kind in super::KINDS {
        map.insert(
            kind.into(),
            match kind {
                "roles" | "dashboards" | "views" | "users" => all.clone(),
                _ => json!({"list":true,"read":true}),
            },
        );
    }
    for model in registry.models.keys() {
        map.insert(model.clone(), all.clone());
    }
    // Every action on every record.
    for (model, action) in registry.actions.keys() {
        if let Some(rules) = map.get_mut(model).and_then(Value::as_object_mut) {
            rules.insert(action.clone(), json!(true));
        }
    }
    Value::Object(map)
}

/// The version of [`admin_access_map`]'s defaults recorded on the Admin role.
/// Version 1 kept providers read-only and could not grant actions.
const ADMIN_DEFAULTS_VERSION: i64 = 2;

/// The built-in resources of version 1, when providers were one of them.
const LEGACY_KINDS: [&str; 7] = [
    "users",
    "identities",
    "identity_verifications",
    "roles",
    "dashboards",
    "views",
    "providers",
];

/// Whether an Admin role still holds the version 1 defaults, which the runtime
/// rewrote on every start: roles, users, dashboards and views in full, the
/// other built-ins read-only, and every model in full.
fn legacy_admin_map(permissions: &Value) -> bool {
    let all = json!({"list":true,"read":true,"create":true,"update":true,"delete":true});
    let Some(map) = permissions.as_object() else {
        return false;
    };
    LEGACY_KINDS.iter().all(|kind| {
        map.get(*kind)
            == Some(
                &if matches!(*kind, "roles" | "users" | "dashboards" | "views") {
                    all.clone()
                } else {
                    json!({"list":true,"read":true})
                },
            )
    }) && map
        .iter()
        .all(|(name, rules)| LEGACY_KINDS.contains(&name.as_str()) || rules == &all)
}

/// What the Admin role is granted, one entry per resource and per action
/// (`model.action`), so it can tell what the app has gained since.
fn admin_targets(registry: &super::extensions::Registry) -> BTreeSet<String> {
    super::KINDS
        .iter()
        .map(|kind| (*kind).to_owned())
        .chain(registry.models.keys().cloned())
        .chain(
            registry
                .actions
                .keys()
                .map(|(model, action)| format!("{model}.{action}")),
        )
        .collect()
}

/// What the default Admin role says about itself.
const ADMIN_DESCRIPTION: &str =
    "Full access to every resource. An ordinary role: change it, or make narrower ones.";

/// The roles the app ships: those it registers ([`Registry::role`]), and an
/// Admin granting every operation on every resource and every action unless it
/// registers its own role of that name.
fn shipped_roles(registry: &super::extensions::Registry) -> Vec<(String, Value, Option<&str>)> {
    let mut roles: Vec<(String, Value, Option<&str>)> = registry
        .roles
        .iter()
        .map(|(name, permissions)| (name.clone(), permissions.clone(), None))
        .collect();
    if !registry
        .roles
        .keys()
        .any(|name| name.eq_ignore_ascii_case("admin"))
    {
        roles.push((
            "Admin".into(),
            admin_access_map(registry),
            Some(ADMIN_DESCRIPTION),
        ));
    }
    roles
}

/// An Admin role kept by earlier versions, which granted it whatever the app
/// gained even after an owner narrowed it: grant that one last time, then make
/// it an ordinary shipped role holding today's defaults. Left untouched, it
/// keeps following the app; narrowed, it stays as the owner left it.
fn adopt_legacy_admin(data: &mut Value, registry: &super::extensions::Registry) {
    let defaults = admin_access_map(registry);
    let targets = admin_targets(registry);
    if data["admin_defaults_version"].as_i64().unwrap_or(1) < ADMIN_DEFAULTS_VERSION {
        if legacy_admin_map(&data["permissions"]) {
            data["permissions"] = defaults.clone();
        }
    } else {
        let known: BTreeSet<String> = data["admin_known"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|target| target.as_str().map(str::to_owned))
            .collect();
        if !data["permissions"].is_object() {
            data["permissions"] = json!({});
        }
        for target in targets.difference(&known) {
            let permissions = &mut data["permissions"];
            match target.split_once('.') {
                Some((model, action)) => {
                    if !permissions[model].is_object() {
                        permissions[model] = json!({});
                    }
                    permissions[model][action] = json!(true);
                }
                None => permissions[target.as_str()] = defaults[target.as_str()].clone(),
            }
        }
    }
    // What the app no longer has can't be granted: drop it, so the map can be
    // saved again from Roles.
    if let Some(permissions) = data["permissions"].as_object_mut() {
        permissions.retain(|model, _| targets.contains(model));
        for (model, rules) in permissions.iter_mut() {
            if let Some(rules) = rules.as_object_mut() {
                rules.retain(|operation, _| {
                    crate::ACCESS_OPERATIONS.contains(&operation.as_str())
                        || operation == crate::FIELD_RULES
                        || targets.contains(&format!("{model}.{operation}"))
                });
            }
        }
    }
    if let Some(object) = data.as_object_mut() {
        for key in ["managed", "admin_defaults_version", "admin_known"] {
            object.remove(key);
        }
    }
    data["default_permissions"] = defaults;
    data["description"] = json!(ADMIN_DESCRIPTION);
}

/// Drop from every role what the app no longer has — a resource, an action, a
/// field a field rule names — so the rest still applies and the role can be
/// saved again from Roles.
async fn prune_roles(
    connection: &mut PgConnection,
    targets: &crate::AccessTargets,
    actions: &crate::ActionTargets,
) -> Result<(), ApiError> {
    let stored: Vec<(Uuid, Value)> =
        sqlx::query_as("SELECT id,data->'permissions' FROM app_records WHERE kind='roles'")
            .fetch_all(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
    for (id, permissions) in stored {
        let Some(map) = permissions.as_object() else {
            continue;
        };
        let mut pruned = map.clone();
        pruned.retain(|resource, _| targets.contains_key(resource));
        for (resource, rules) in &mut pruned {
            let Some(rules) = rules.as_object_mut() else {
                continue;
            };
            rules.retain(|operation, _| {
                crate::ACCESS_OPERATIONS.contains(&operation.as_str())
                    || operation == crate::FIELD_RULES
                    || actions
                        .get(resource)
                        .is_some_and(|names| names.contains(operation))
            });
            let fields = targets.get(resource).cloned().flatten();
            if let Some(rules) = rules
                .get_mut(crate::FIELD_RULES)
                .and_then(Value::as_object_mut)
            {
                rules.retain(|field, _| fields.as_ref().is_some_and(|known| known.contains(field)));
            }
        }
        if pruned != *map {
            sqlx::query("UPDATE app_records SET data=jsonb_set(data,'{permissions}',$2),updated=now() WHERE kind='roles' AND id=$1")
                .bind(id)
                .bind(Value::Object(pruned))
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
        }
    }
    Ok(())
}

/// Create the roles the app ships and keep their maps in step with the code
/// while nobody has changed them. They are ordinary role records: an
/// administrator may change, rename or delete one, and that lasts. Each is
/// created once (a deleted one stays deleted), found again by the name the code
/// gives it (`shipped`) however it was renamed, and updated only while it
/// still holds the defaults it was last given.
///
/// # Errors
/// Rejects maps that name unknown resources, fields, operations or actions.
pub async fn ensure_roles(
    connection: &mut PgConnection,
    registry: &super::extensions::Registry,
) -> Result<(), ApiError> {
    let mut targets = registry.access_targets();
    for kind in super::KINDS {
        targets.insert(kind.into(), None);
    }
    let actions = registry.action_targets();
    prune_roles(connection, &targets, &actions).await?;
    for (name, permissions, description) in shipped_roles(registry) {
        crate::parse_access_map_with_actions(&permissions, &targets, &actions)
            .map_err(|message| ApiError::Parse(format!("Role {name}: {message}")))?;
        let key = name.to_lowercase();
        let existing: Option<(Uuid, Value)> = sqlx::query_as(
            "SELECT id,data FROM app_records WHERE kind='roles' AND (lower(data->>'shipped')=$1 OR (NOT data ? 'shipped' AND lower(data->>'name')=$1)) ORDER BY (data ? 'shipped') DESC,created,id LIMIT 1",
        )
        .bind(&key)
        .fetch_optional(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        // Remembered apart from the role, so deleting the role is remembered too.
        let created: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind='shipped_roles' AND data->>'role'=$1)",
        )
        .bind(&key)
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        match existing {
            // An administrator deleted it.
            None if created => continue,
            None => {
                let mut data = json!({"name":name,"permissions":permissions,"default_permissions":permissions,"shipped":name});
                if let Some(description) = description {
                    data["description"] = json!(description);
                }
                sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'roles',$2)")
                    .bind(Uuid::new_v4())
                    .bind(&data)
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
            }
            Some((id, data)) => {
                let mut changed = data.clone();
                if changed["managed"] == true {
                    adopt_legacy_admin(&mut changed, registry);
                }
                if !changed["shipped"].is_string() {
                    changed["shipped"] = json!(name);
                }
                if changed.get("default_permissions") == changed.get("permissions")
                    && changed.get("permissions") != Some(&permissions)
                {
                    changed["permissions"] = permissions.clone();
                    changed["default_permissions"] = permissions.clone();
                }
                if changed != data {
                    sqlx::query(
                        "UPDATE app_records SET data=$2,updated=now() WHERE kind='roles' AND id=$1",
                    )
                    .bind(id)
                    .bind(&changed)
                    .execute(&mut *connection)
                    .await
                    .map_err(ApiError::internal)?;
                }
            }
        }
        if !created {
            sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'shipped_roles',$2)")
                .bind(Uuid::new_v4())
                .bind(json!({"role":key}))
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
        }
    }
    Ok(())
}

/// Whether an email address may sign in: the app's superusers always may, and
/// so may anyone an administrator has added as a user. Sign-in never creates
/// an account for anyone else, so a stranger who knows the app's address gets
/// no further than the sign-in page.
pub(crate) async fn member(
    app: &App,
    connection: &mut PgConnection,
    email: &str,
) -> Result<bool, ApiError> {
    let email = email.trim().to_ascii_lowercase();
    if app.superusers.contains(&email) {
        return Ok(true);
    }
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind='users' AND lower(data->>'email')=$1)",
    )
    .bind(&email)
    .fetch_one(&mut *connection)
    .await
    .map_err(ApiError::internal)
}

/// Give a signing-in superuser the app's Admin role when it has one, so the
/// owner's own record shows it. Their access never depends on it: superusers
/// pass every grant, row filter, action rule and field rule.
pub(crate) async fn admit_superuser(
    app: &App,
    connection: &mut PgConnection,
    user: Uuid,
    email: &str,
) -> Result<(), ApiError> {
    if !app.superusers.contains(&email.trim().to_ascii_lowercase()) {
        return Ok(());
    }
    // An app that never migrates (the shared core runtime) gets its shipped
    // roles here, once, as migrating would give them.
    ensure_roles(connection, &app.registry).await?;
    let admin: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM app_records WHERE kind='roles' AND (lower(data->>'shipped')='admin' OR (NOT data ? 'shipped' AND lower(data->>'name')='admin')) ORDER BY (data ? 'shipped') DESC,created,id LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    let Some(admin) = admin else {
        return Ok(());
    };
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
