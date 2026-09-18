//! Shared, read-only core-object runtime. Each deployed app has its own database
//! and email magic-link sign-in. No Dreamy platform tables or keys are exposed.
use crate::{ApiDocument, ApiError, FilterOperator, PageMeta, QueryFeatures};
use axum::{
    Json, Router,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, postgres::PgPoolOptions};
use std::{collections::BTreeSet, sync::Arc};
use uuid::Uuid;
mod extension_api;
pub mod extensions;
pub mod task_runner;

mod core;
pub mod google_auth;
mod magic_auth;
pub mod operator;
mod preview;
pub use google_auth::GoogleAuth;

const KINDS: [&str; 7] = [
    "users",
    "identities",
    "identity_verifications",
    "roles",
    "dashboards",
    "views",
    "providers",
];
const DOCUMENT: &str = "data || jsonb_build_object('id',id,'created',created,'updated',updated)";
#[derive(Clone)]
pub struct App {
    pub registry: Arc<extensions::Registry>,
    pub pool: PgPool,
    pub name: String,
    pub origin: String,
    pub preview_origins: Vec<String>,
    pub mail_from: String,
    pub mail_region: String,
    pub mail_api_key: Option<String>,
    pub google_auth: Option<GoogleAuth>,
    pub branding: Value,
    /// Private integration-test transport; never configured from environment or app data.
    pub mail_endpoint: Option<String>,
    pub revision: String,
    /// Lower-cased emails that bypass model grants, row filters and action
    /// roles: the platform sets the project owners here so a new app is usable
    /// before anyone holds a custom role. Never taken from app data.
    pub superusers: BTreeSet<String>,
    /// Shared secret the publishing platform uses to open short-lived sessions
    /// for named users through `/api/operator/session`; absent disables it.
    pub operator_secret: Option<String>,
}
impl App {
    /// The actor for a signed-in user record: the superuser flag applied and
    /// the roles the user holds loaded, so their access maps apply to this
    /// request. A role deleted since it was assigned is simply not held.
    ///
    /// # Errors
    /// Returns database failures while loading the user's roles.
    pub async fn actor(&self, user: &Value) -> Result<extensions::Actor, ApiError> {
        let mut actor = extensions::Actor::for_user(user, &self.superusers);
        let ids = extensions::Actor::role_ids(user);
        if ids.is_empty() {
            actor.admit();
            return Ok(actor);
        }
        let roles: Vec<(String, Value)> = sqlx::query_as(
            "SELECT data->>'name',coalesce(data->'permissions','{}'::jsonb) FROM app_records WHERE kind='roles' AND id=ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await
        .map_err(ApiError::internal)?;
        let targets = self.access_targets();
        for (name, permissions) in roles {
            // Maps are validated when saved; anything unreadable grants nothing.
            let access = crate::parse_access_map(&permissions, &targets).unwrap_or_default();
            actor.hold(&name, access);
        }
        actor.admit();
        Ok(actor)
    }
    /// What a role's access map may name: registered models with their fields,
    /// and the built-in resources, which take only `true` or `false`.
    #[must_use]
    pub fn access_targets(&self) -> crate::AccessTargets {
        let mut targets = self.registry.access_targets();
        for kind in KINDS {
            targets.insert(kind.into(), None);
        }
        targets
    }
}
/// Parse `APP_SUPERUSER_EMAILS`: comma, semicolon or whitespace separated, case-insensitive.
#[must_use]
pub fn parse_superusers(value: &str) -> BTreeSet<String> {
    value
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(|email| email.trim().to_ascii_lowercase())
        .filter(|email| email.contains('@'))
        .collect()
}
fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn random() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}
fn redirect(url: &str, name: &str, value: &str, age: u32) -> Result<Response, ApiError> {
    let mut response = Redirect::to(url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{name}={value}; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age={age}")
            .parse()
            .map_err(ApiError::internal)?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(response)
}
async fn user(app: &App, headers: &HeaderMap) -> Result<Value, ApiError> {
    let token = cookie(headers, "dream_preview")
        .or_else(|| cookie(headers, "dream_app"))
        .ok_or(ApiError::Unauthenticated)?;
    let record=sqlx::query_scalar(&format!("SELECT {DOCUMENT} FROM app_records WHERE kind='users' AND id=(SELECT user_id FROM app_sessions WHERE digest=$1 AND expires>now())"))
        .bind(hash(&token)).fetch_optional(&app.pool).await.map_err(ApiError::internal)?.ok_or(ApiError::Unauthenticated)?;
    Ok(public_record("users", record))
}
fn public_record(kind: &str, mut record: Value) -> Value {
    if let Some(object) = record.as_object_mut() {
        if kind == "users" {
            // Held roles are a first-class field; the rest of `data` is the app's.
            let roles = object
                .get_mut("data")
                .and_then(Value::as_object_mut)
                .and_then(|data| data.remove("roles"))
                .unwrap_or_else(|| json!([]));
            object.insert("roles".into(), roles);
        }
        object.retain(|name, _| fields(kind).iter().any(|(field, _)| field == name));
    }
    record
}
fn project_record(kind: &str, record: Value, features: &QueryFeatures) -> Value {
    let mut record = public_record(kind, record);
    if let Some(object) = record.as_object_mut() {
        let exclude_all = features.exclude.iter().any(|field| field == "*");
        let include_all = features.include.iter().any(|field| field == "*");
        object.retain(|field, _| {
            field == "id"
                || ((!exclude_all || include_all || features.include.contains(field))
                    && !features.exclude.contains(field))
        });
    }
    record
}
fn singular(kind: &str) -> &str {
    match kind {
        "identities" => "identity",
        "identity_verifications" => "identity_verification",
        "users" => "user",
        "roles" => "role",
        "dashboards" => "dashboard",
        "views" => "view",
        _ => "provider",
    }
}
fn fields(kind: &str) -> Vec<(&str, &str)> {
    let mut result = vec![
        ("id", "uuid"),
        ("created", "datetime"),
        ("updated", "datetime"),
    ];
    result.extend(match kind {
        "users" => vec![
            ("name", "string"),
            ("email", "email"),
            ("photo", "image upload"),
            ("roles", "list"),
            ("data", "json"),
        ],
        "identities" => vec![
            ("name", "string"),
            ("user", "uuid"),
            ("provider", "string"),
            ("subject", "string"),
        ],
        "identity_verifications" => vec![
            ("name", "string"),
            ("user", "uuid"),
            ("verified", "boolean"),
            ("method", "string"),
        ],
        "roles" => vec![("name", "string"), ("permissions", "permissions")],
        "providers" => vec![
            ("name", "string"),
            ("kind", "string"),
            ("enabled", "boolean"),
        ],
        "views" => vec![("name", "string"), ("resource", "string"), ("data", "json")],
        _ => vec![("name", "string"), ("data", "json")],
    });
    result
}
/// Navigation section for a built-in resource. An empty section keeps the
/// resource fully usable — routable, searchable, and linkable from relations —
/// while leaving it out of the admin's navigation drawer, the same convention
/// Dynamic REST used. Identities, verifications, dashboards, and views are
/// plumbing that an app's own users rarely browse directly, so only the three
/// resources people administer are listed by default.
fn section(kind: &str) -> &'static str {
    match kind {
        "identities" | "identity_verifications" | "dashboards" | "views" => "",
        _ => "Core",
    }
}
/// Which built-in fields a person may change on an existing record, given what
/// their roles grant.
fn writable(kind: &str, field: &str, actor: &extensions::Actor) -> bool {
    match (kind, field) {
        ("roles", "name" | "permissions") => actor.granted("roles", "update"),
        ("users", "name" | "roles") => actor.granted("users", "update"),
        ("dashboards", "name" | "data") | ("views", "name" | "resource" | "data") => {
            actor.granted(kind, "update")
        }
        _ => false,
    }
}
/// Which built-in fields a person may set when adding a record. A user's email
/// is set once, when an administrator adds them; it then belongs to sign-in.
fn creatable(kind: &str, field: &str, actor: &extensions::Actor) -> bool {
    match (kind, field) {
        ("users", "name" | "email" | "roles") => actor.granted("users", "create"),
        ("roles", "name" | "permissions") => actor.granted("roles", "create"),
        ("dashboards", "name" | "data") | ("views", "name" | "resource" | "data") => {
            actor.granted(kind, "create")
        }
        _ => false,
    }
}
/// The write operations the API supports on a built-in resource.
pub(crate) fn core_supports(kind: &str, operation: &str) -> bool {
    matches!(
        (kind, operation),
        (
            "roles" | "dashboards" | "views" | "users",
            "create" | "update" | "delete"
        )
    )
}
/// The roles that exist, as choices for a user's `roles` field.
async fn role_choices(app: &App) -> Result<Vec<Value>, ApiError> {
    let roles: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id,coalesce(data->>'name','') FROM app_records WHERE kind='roles' ORDER BY lower(data->>'name'),id",
    )
    .fetch_all(&app.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(roles
        .into_iter()
        .map(|(id, name)| json!({"id":id,"label":name}))
        .collect())
}
fn schema(app: &App, kind: &str, actor: &extensions::Actor, roles: &[Value]) -> Value {
    let icon = match kind {
        "users" => "account-group",
        "identities" => "card-account-details-outline",
        "identity_verifications" => "shield-check-outline",
        "roles" => "shield-account-outline",
        "dashboards" => "view-dashboard-outline",
        "views" => "table-eye",
        _ => "connection",
    };
    let fields:Map<String,Value>=fields(kind).into_iter().map(|(name,typ)|{
        let write=writable(kind,name,actor);
        let create=creatable(kind,name,actor);
        let editable=write||create;
        let required=editable && (name=="name" || (kind=="users" && name=="email"));
        let mut field=json!({"name":name,"label":crate::python_title(&name.replace('_'," ")),"type":typ,"read_only":!editable,"required":required,"nullable":!editable,"null":!editable,"many":typ=="relation","ui":true,"hidden":false,"deferred":false,"sortable":filterable(kind,name),"filterable":filterable(kind,name)});
        match (kind,name) {
            ("users","roles")=>{
                field["related_resource"]=json!("roles");
                field["choices"]=json!(roles);
                field["description"]=json!("The roles this user holds; each role's permissions apply.");
            }
            ("roles","permissions")=>{
                field["description"]=json!("What this role may do, per resource and operation. A rule is allowed, denied, or a condition the records must meet.");
                field["resources"]=access_resources(app);
            }
            _=>{}
        }
        (name.into(),field)
    }).collect();
    let readable = actor.core_readable(kind);
    let permissions: Map<String, Value> = fields
        .keys()
        .map(|name| {
            let write = writable(kind, name, actor);
            let create = creatable(kind, name, actor);
            (
                name.clone(),
                json!({"read":true,"create":create,"write":{"create":create,"update":write}}),
            )
        })
        .collect();
    let field_names: Vec<_> = fields.keys().cloned().collect();
    let operations: Map<String, Value> = ["create", "update", "delete"]
        .into_iter()
        .map(|operation| {
            let supported = core_supports(kind, operation);
            (
                operation.into(),
                json!(supported && actor.granted(kind, operation)),
            )
        })
        .collect();
    json!({"type":"resource","name":kind,"singular":singular(kind),"singular_name":singular(kind),"label":crate::python_title(&kind.replace('_'," ")),"icon":icon,"url":format!("/api/admin/{kind}/"),"id_field":"id","name_field":"name","section":section(kind),"fields":fields,"permissions":{"list":readable,"read":readable,"create":operations["create"],"update":operations["update"],"delete":operations["delete"],"fields":permissions},"features":{"detail":true},"sections":[{"name":"details","label":"Details","fields":field_names}],"list_fields":["name","created"]})
}
/// Built-in fields the list endpoint can filter and sort by.
fn filterable(kind: &str, field: &str) -> bool {
    !fields(kind).iter().any(|(name, typ)| {
        *name == field && ["json", "list", "permissions", "image upload"].contains(typ)
    })
}
/// The resources an access map may name, for the permissions editor: their
/// labels, and whether rules on them may carry conditions.
fn access_resources(app: &App) -> Value {
    let mut resources: Map<String, Value> = KINDS
        .iter()
        .filter(|kind| !matches!(**kind, "identities" | "identity_verifications"))
        .map(|kind| {
            (
                (*kind).to_string(),
                json!({"label":crate::python_title(&kind.replace('_'," ")),"conditional":false}),
            )
        })
        .collect();
    for (name, model) in &app.registry.models {
        // Resources without grants are open to everyone; a rule adds nothing.
        if model.resource.role_grants.is_empty() {
            continue;
        }
        let label = model
            .resource
            .metadata
            .as_ref()
            .and_then(|m| m["label"].as_str())
            .map_or_else(
                || crate::python_title(&name.replace('_', " ")),
                str::to_owned,
            );
        resources.insert(name.clone(), json!({"label":label,"conditional":true}));
    }
    Value::Object(resources)
}
async fn metadata(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let roles = role_choices(&app).await?;
    let mut resources: Map<String, Value> = KINDS
        .iter()
        .filter(|k| actor.core_readable(k))
        .map(|k| ((*k).to_string(), schema(&app, k, &actor, &roles)))
        .collect();
    for (name, model) in &app.registry.models {
        let resource = app
            .registry
            .resource_for(name, &actor)
            .unwrap_or_else(|| model.resource.clone());
        if crate::operation_granted(&resource, Some(actor.principal()), "list", true) {
            resources.insert(
                name.clone(),
                extensions::metadata(model, &actor, &app.registry),
            );
        }
    }
    // Someone without a role sees no resources; the admin tells them to ask an
    // administrator for one rather than showing an empty app.
    Ok(Json(
        json!({"type":"namespace","name":"app","label":app.name,"resources":resources,"access":if actor.is_member() {"member"} else {"none"}}),
    ))
}
async fn options(
    State(app): State<App>,
    headers: HeaderMap,
    Path(kind): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    if let Some(model) = app.registry.models.get(&kind) {
        let resource = app
            .registry
            .resource_for(&kind, &actor)
            .unwrap_or_else(|| model.resource.clone());
        if !crate::operation_granted(&resource, Some(actor.principal()), "list", true) {
            return Err(ApiError::Forbidden);
        }
        return Ok(Json(extensions::metadata(model, &actor, &app.registry)));
    }
    if !KINDS.contains(&kind.as_str()) {
        return Err(ApiError::NotFound);
    }
    if !actor.core_readable(&kind) {
        return Err(ApiError::Forbidden);
    }
    Ok(Json(schema(
        &app,
        &kind,
        &actor,
        &role_choices(&app).await?,
    )))
}
fn expression(query: &mut QueryBuilder<'_, Postgres>, field: &str) {
    if ["id", "created", "updated"].contains(&field) {
        query.push(format!("{field}::text"));
    } else {
        query.push("data->>").push_bind(field.to_owned());
    }
}
fn filters(
    query: &mut QueryBuilder<'_, Postgres>,
    kind: &str,
    features: &QueryFeatures,
) -> Result<(), ApiError> {
    query
        .push(" FROM app_records WHERE kind=")
        .push_bind(kind.to_owned());
    for filter in &features.filters {
        if !fields(kind).iter().any(|(f, _)| *f == filter.field)
            || !filterable(kind, &filter.field)
            || filter.field_reference
            || !filter.relation.is_empty()
            || !matches!(
                filter.operator,
                FilterOperator::Eq
                    | FilterOperator::In
                    | FilterOperator::IContains
                    | FilterOperator::IsNull
            )
        {
            return Err(ApiError::Parse("Unsupported resource filter.".into()));
        }
        query.push(if filter.exclude {
            " AND NOT ("
        } else {
            " AND ("
        });
        if filter.operator == FilterOperator::IsNull {
            let expected = filter
                .values
                .first()
                .and_then(|value| FilterOperator::null_expected(value))
                .ok_or_else(|| ApiError::Parse("isnull expects true/false or 1/0.".into()))?;
            expression(query, &filter.field);
            query.push(if expected { " IS NULL" } else { " IS NOT NULL" });
            query.push(")");
            continue;
        }
        for (index, value) in filter.values.iter().enumerate() {
            if index > 0 {
                query.push(" OR ");
            }
            expression(query, &filter.field);
            if filter.operator == FilterOperator::IContains {
                query.push(" ILIKE ").push_bind(format!(
                    "%{}%",
                    value
                        .replace('\\', "\\\\")
                        .replace('%', "\\%")
                        .replace('_', "\\_")
                ));
            } else {
                query.push(" = ").push_bind(value.clone());
            }
        }
        query.push(")");
    }
    Ok(())
}
async fn list(
    State(app): State<App>,
    headers: HeaderMap,
    Path(kind): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Json<ApiDocument>, ApiError> {
    let person = user(&app, &headers).await?;
    if app.registry.models.contains_key(&kind) {
        return extension_api::list(app, headers, kind, raw).await;
    }
    // Optional admin metadata is absent from the core-only foundation.
    if ["guides", "guide_completions"].contains(&kind.as_str()) {
        return Ok(Json(ApiDocument::many(
            kind,
            vec![],
            PageMeta::new(1, 50, 0),
        )));
    }
    if !KINDS.contains(&kind.as_str()) {
        return Err(ApiError::NotFound);
    }
    if !app.actor(&person).await?.core_readable(&kind) {
        return Err(ApiError::Forbidden);
    }
    let features = QueryFeatures::parse(raw.as_deref().unwrap_or(""), 10000)?;
    let mut count = QueryBuilder::<Postgres>::new("SELECT count(*)");
    filters(&mut count, &kind, &features)?;
    let total: i64 = count
        .build_query_scalar()
        .fetch_one(&app.pool)
        .await
        .map_err(ApiError::internal)?;
    let mut query = QueryBuilder::<Postgres>::new(format!("SELECT {DOCUMENT}"));
    filters(&mut query, &kind, &features)?;
    query.push(" ORDER BY ");
    for sort in &features.sort {
        if !fields(&kind).iter().any(|(f, _)| *f == sort.field) || !filterable(&kind, &sort.field) {
            return Err(ApiError::Parse("Unknown sort field.".into()));
        }
        expression(&mut query, &sort.field);
        query.push(if sort.descending { " DESC, " } else { " ASC, " });
    }
    query
        .push("created,id LIMIT ")
        .push_bind(i64::from(features.per_page))
        .push(" OFFSET ")
        .push_bind(i64::from(features.page - 1) * i64::from(features.per_page));
    let mut records: Vec<Value> = query
        .build_query_scalar()
        .fetch_all(&app.pool)
        .await
        .map_err(ApiError::internal)?;
    for record in &mut records {
        *record = project_record(&kind, record.take(), &features);
    }
    Ok(Json(ApiDocument::many(
        kind,
        records,
        PageMeta::new(
            features.page,
            features.per_page,
            u64::try_from(total).map_err(ApiError::internal)?,
        ),
    )))
}
async fn retrieve(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
    RawQuery(raw): RawQuery,
) -> Result<Json<ApiDocument>, ApiError> {
    let person = user(&app, &headers).await?;
    if app.registry.models.contains_key(&kind) {
        return extension_api::retrieve(app, headers, kind, id, raw).await;
    }
    if !KINDS.contains(&kind.as_str()) {
        return Err(ApiError::NotFound);
    }
    // A person may always read their own record; anything else takes a grant.
    let own = kind == "users" && person["id"].as_str() == Some(&id.to_string());
    if !own && !app.actor(&person).await?.core_readable(&kind) {
        return Err(ApiError::Forbidden);
    }
    let record = sqlx::query_scalar(&format!(
        "SELECT {DOCUMENT} FROM app_records WHERE kind=$1 AND id=$2"
    ))
    .bind(&kind)
    .bind(id)
    .fetch_optional(&app.pool)
    .await
    .map_err(ApiError::internal)?
    .ok_or(ApiError::NotFound)?;
    let features = QueryFeatures::parse(raw.as_deref().unwrap_or(""), 10000)?;
    Ok(Json(ApiDocument::one(
        singular(&kind),
        project_record(&kind, record, &features),
    )))
}
async fn me(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({"user":user(&app,&headers).await?})))
}
async fn s3(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    user(&app, &headers).await?;
    Ok(Json(json!({})))
}
/// The page to return to after signing in: a path on this app, given either as
/// a path or as an absolute URL on the app's origin, and never an API page.
/// An admin ends a session with `/api/logout/?next=/api/login/?next=<page>`,
/// so a login URL wrapping the page is unwrapped once.
pub(crate) fn next_path(app: &App, value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value.len() > 2000 {
        return None;
    }
    let base = url::Url::parse(&format!("{}/", app.origin)).ok()?;
    let url = base.join(value).ok()?;
    if url.origin() != base.origin()
        || url.path().starts_with("/api/") && url.path() != "/api/login/"
    {
        return None;
    }
    if url.path() == "/api/login/" {
        let inner = url
            .query_pairs()
            .find(|(key, _)| key == "next")
            .map(|(_, v)| v.into_owned());
        return next_path(app, inner.as_deref());
    }
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    (path.starts_with('/') && !path.starts_with("//")).then_some(path)
}
/// `/api/login/`, remembering the page to return to when there is one.
pub(crate) fn login_url(app: &App, next: Option<&str>) -> String {
    match next_path(app, next) {
        Some(path) => format!(
            "{}/api/login/?next={}",
            app.origin,
            url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>()
        ),
        None => format!("{}/api/login/", app.origin),
    }
}
#[derive(Deserialize)]
struct Logout {
    next: Option<String>,
}
async fn logout(
    State(app): State<App>,
    headers: HeaderMap,
    axum::extract::Query(input): axum::extract::Query<Logout>,
) -> Result<Response, ApiError> {
    for token in [
        cookie(&headers, "dream_preview"),
        cookie(&headers, "dream_app"),
    ]
    .into_iter()
    .flatten()
    {
        sqlx::query("DELETE FROM app_sessions WHERE digest=$1")
            .bind(hash(&token))
            .execute(&app.pool)
            .await
            .map_err(ApiError::internal)?;
    }
    let mut response = redirect(&login_url(&app, input.next.as_deref()), "dream_app", "", 0)?;
    response.headers_mut().append(
        header::SET_COOKIE,
        "dream_preview=; Path=/api; HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
/// Writes to built-in resources: roles, and the roles users hold.
async fn core_write(
    app: &App,
    headers: &HeaderMap,
    kind: &str,
    id: Option<Uuid>,
    input: Value,
    method: &str,
) -> Result<Value, ApiError> {
    let actor = app.actor(&user(app, headers).await?).await?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    extensions::lock(&mut tx).await?;
    let record = core::write(app, &mut tx, &actor, kind, id, input, method).await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(record)
}
/// Built-in resources answer 405 before any body is read, so an unsupported
/// write never fails on its content type first.
fn body(input: Option<Json<Value>>) -> Result<Json<Value>, ApiError> {
    input.ok_or_else(|| ApiError::Parse("Expected a JSON body.".into()))
}
async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Path(kind): Path<String>,
    input: Option<Json<Value>>,
) -> Result<(StatusCode, Json<ApiDocument>), ApiError> {
    if !KINDS.contains(&kind.as_str()) {
        return extension_api::create(State(app), headers, Path(kind), body(input)?).await;
    }
    let input = input.map_or(Value::Null, |Json(value)| value);
    let record = core_write(&app, &headers, &kind, None, input, "POST").await?;
    Ok((
        StatusCode::CREATED,
        Json(ApiDocument::one(singular(&kind), record)),
    ))
}
async fn update(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
    input: Option<Json<Value>>,
) -> Result<Json<ApiDocument>, ApiError> {
    if !KINDS.contains(&kind.as_str()) {
        return extension_api::update(State(app), headers, Path((kind, id)), body(input)?).await;
    }
    let input = input.map_or(Value::Null, |Json(value)| value);
    let record = core_write(&app, &headers, &kind, Some(id), input, "PATCH").await?;
    Ok(Json(ApiDocument::one(singular(&kind), record)))
}
async fn replace(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
    input: Option<Json<Value>>,
) -> Result<Json<ApiDocument>, ApiError> {
    if !KINDS.contains(&kind.as_str()) {
        return extension_api::replace(State(app), headers, Path((kind, id)), body(input)?).await;
    }
    let input = input.map_or(Value::Null, |Json(value)| value);
    let record = core_write(&app, &headers, &kind, Some(id), input, "PUT").await?;
    Ok(Json(ApiDocument::one(singular(&kind), record)))
}
async fn delete(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    if !KINDS.contains(&kind.as_str()) {
        return extension_api::delete(State(app), headers, Path((kind, id))).await;
    }
    core_write(&app, &headers, &kind, Some(id), json!({}), "DELETE").await?;
    Ok(StatusCode::NO_CONTENT)
}
pub fn router(app: App) -> Router {
    let routes=Router::new().route("/health",get(|State(app):State<App>|async move{Json(json!({"status":"ok","service":"dreamy-app","name":app.name,"revision":app.revision}))}))
        .route("/login/",get(magic_auth::login)).route("/logout/",get(logout))
        .route("/preview/auth",get(preview::shell)).route("/preview/finish",get(preview::shell))
        .route("/preview/script.js",get(preview::script))
        .route("/preview/issue",axum::routing::post(preview::issue)).route("/preview/redeem",axum::routing::post(preview::redeem))
        .route("/auth/magic-link",axum::routing::post(magic_auth::request_link))
        .route("/auth/verify",axum::routing::post(magic_auth::verify))
        .route("/operator/session",axum::routing::post(operator::session))
        .route("/auth/google",get(google_auth::start))
        .route("/auth/google/callback",get(google_auth::callback))
        .route("/admin/",get(metadata).options(metadata)).route("/admin/users/me/",get(me))
        .route("/admin/{kind}/",get(list).options(options).post(create))
        .route("/admin/{kind}/{id}/",get(retrieve).patch(update).put(replace).delete(delete))
        .route("/admin/{kind}/{id}/actions/{action}/",axum::routing::post(extension_api::action))
        .route("/admin/{kind}/{id}/{field}/",get(extension_api::related))
        .route("/v0/s3/",get(s3)).with_state(app);
    Router::new().nest("/api", routes)
}
/// Construct the core router from environment configuration.
/// # Errors
/// Returns invalid configuration and database setup errors.
pub fn from_env() -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    if std::env::var("APP_BOOTSTRAP").as_deref() == Ok("true") {
        return Ok(Router::new().route(
            "/",
            axum::routing::post(|| async {
                bootstrap().await.map(|()| Json(json!({"status":"ready"})))
            }),
        ));
    }
    Ok(router(configured(extensions::Registry::default())?))
}
/// Configure a registered app; call registry.migrate before serving requests.
/// # Errors
/// Returns invalid environment, origin, auth or database configuration errors.
pub fn configured(
    registry: extensions::Registry,
) -> Result<App, Box<dyn std::error::Error + Send + Sync>> {
    let configured_origin = url::Url::parse(&std::env::var("APP_ORIGIN")?)?;
    if configured_origin.scheme() != "https"
        || configured_origin.host_str().is_none()
        || !configured_origin.username().is_empty()
        || configured_origin.password().is_some()
        || configured_origin.path() != "/"
        || configured_origin.query().is_some()
        || configured_origin.fragment().is_some()
    {
        return Err("APP_ORIGIN must use HTTPS and contain only an origin".into());
    }
    let origin = configured_origin.origin().ascii_serialization();
    Ok(App {
        registry: Arc::new(registry),
        pool: PgPoolOptions::new()
            .max_connections(3)
            .connect_lazy(&std::env::var("DATABASE_URL")?)?,
        name: std::env::var("APP_NAME")?,
        origin,
        preview_origins: preview::parse_origins(
            &std::env::var("APP_PREVIEW_ORIGINS").unwrap_or_default(),
        )?,
        mail_from: std::env::var("APP_MAIL_FROM")?,
        mail_region: std::env::var("APP_MAIL_REGION").unwrap_or_else(|_| "eu-west-1".into()),
        mail_api_key: std::env::var("APP_MAIL_API_KEY")
            .ok()
            .filter(|value| !value.is_empty()),
        google_auth: google_auth::from_env()?,
        branding: serde_json::from_str(
            &std::env::var("APP_BRANDING").unwrap_or_else(|_| "{}".into()),
        )?,
        mail_endpoint: None,
        revision: std::env::var("APP_REVISION")?,
        superusers: parse_superusers(&std::env::var("APP_SUPERUSER_EMAILS").unwrap_or_default()),
        operator_secret: operator::secret_from_env()?,
    })
}
async fn bootstrap() -> Result<(), ApiError> {
    let get = |name| std::env::var(name).map_err(ApiError::internal);
    let name = get("APP_DATABASE")?;
    let username = get("APP_DATABASE_USER")?;
    let password = get("APP_DATABASE_PASSWORD")?;
    if name.len() > 63
        || username.len() > 63
        || ![&name, &username].iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        || password.len() < 32
        || !password.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(ApiError::Parse(
            "Invalid database bootstrap configuration.".into(),
        ));
    }
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&get("ADMIN_DATABASE_URL")?)
        .await
        .map_err(ApiError::internal)?;
    let mut conn = admin.acquire().await.map_err(ApiError::internal)?;
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,0))")
        .bind(&name)
        .execute(&mut *conn)
        .await
        .map_err(ApiError::internal)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)")
        .bind(&username)
        .fetch_one(&mut *conn)
        .await
        .map_err(ApiError::internal)?;
    if !exists {
        sqlx::query(&format!("CREATE ROLE \"{username}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE")).execute(&mut *conn).await.map_err(ApiError::internal)?;
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&mut *conn)
            .await
            .map_err(ApiError::internal)?;
    if !exists {
        sqlx::query(&format!("CREATE DATABASE \"{name}\" OWNER \"{username}\""))
            .execute(&mut *conn)
            .await
            .map_err(ApiError::internal)?;
    }
    sqlx::query(&format!(
        "REVOKE CONNECT ON DATABASE \"{name}\" FROM PUBLIC"
    ))
    .execute(&mut *conn)
    .await
    .map_err(ApiError::internal)?;
    sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,0))")
        .bind(&name)
        .execute(&mut *conn)
        .await
        .map_err(ApiError::internal)?;
    drop(conn);
    admin.close().await;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&get("DATABASE_URL")?)
        .await
        .map_err(ApiError::internal)?;
    sqlx::raw_sql(include_str!("templates/app-schema.sql"))
        .execute(&pool)
        .await
        .map_err(ApiError::internal)?;
    for (id, kind, data) in [
        (
            "00000000-0000-0000-0000-000000000001",
            "roles",
            json!({"name":"Viewer","permissions":{"list":true,"read":true,"create":false,"update":false,"delete":false}}),
        ),
        (
            "00000000-0000-0000-0000-000000000002",
            "providers",
            json!({"name":"Email sign-in","kind":"email_magic_link","enabled":true}),
        ),
    ] {
        sqlx::query(
            "INSERT INTO app_records(id,kind,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,updated=now()",
        )
        .bind(Uuid::parse_str(id).unwrap())
        .bind(kind)
        .bind(data)
        .execute(&pool)
        .await
        .map_err(ApiError::internal)?;
    }
    pool.close().await;
    Ok(())
}
