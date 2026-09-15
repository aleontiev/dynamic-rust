//! Shared, read-only core-object runtime. Each deployed app has its own database
//! and email magic-link sign-in. No Dreamy platform tables or keys are exposed.
use crate::{ApiDocument, ApiError, FilterOperator, PageMeta, QueryFeatures};
use axum::{
    Json, Router,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, postgres::PgPoolOptions};
use std::{collections::BTreeSet, sync::Arc};
use uuid::Uuid;
mod extension_api;
pub mod extensions;
pub mod task_runner;

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
    /// The actor for a signed-in user record, with the superuser flag applied.
    #[must_use]
    pub fn actor(&self, user: &Value) -> extensions::Actor {
        extensions::Actor::for_user(user, &self.superusers)
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
        "users" => vec![("name", "string"), ("email", "email"), ("data", "json")],
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
        "roles" => vec![("name", "string"), ("permissions", "json")],
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
fn schema(kind: &str) -> Value {
    let icon = match kind {
        "users" => "account-group",
        "identities" => "card-account-details-outline",
        "identity_verifications" => "shield-check-outline",
        "roles" => "shield-account-outline",
        "dashboards" => "view-dashboard-outline",
        "views" => "table-eye",
        _ => "connection",
    };
    let fields:Map<String,Value>=fields(kind).into_iter().map(|(name,typ)|(name.into(),json!({"name":name,"label":crate::python_title(&name.replace('_'," ")),"type":typ,"read_only":true,"required":false,"nullable":true,"null":true,"many":false,"ui":true,"hidden":false,"deferred":false,"sortable":true,"filterable":typ!="json"}))).collect();
    let permissions: Map<String, Value> = fields
        .keys()
        .map(|name| {
            (
                name.clone(),
                json!({"read":true,"create":false,"write":false}),
            )
        })
        .collect();
    let field_names: Vec<_> = fields.keys().cloned().collect();
    json!({"type":"resource","name":kind,"singular":singular(kind),"singular_name":singular(kind),"label":crate::python_title(&kind.replace('_'," ")),"icon":icon,"url":format!("/api/admin/{kind}/"),"id_field":"id","name_field":"name","section":section(kind),"fields":fields,"permissions":{"list":true,"read":true,"create":false,"update":false,"delete":false,"fields":permissions},"features":{"detail":true},"sections":[{"name":"details","label":"Details","fields":field_names}],"list_fields":["name","created"]})
}
async fn metadata(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?);
    let mut resources: Map<String, Value> = KINDS
        .iter()
        .map(|k| ((*k).to_string(), schema(k)))
        .collect();
    for (name, model) in &app.registry.models {
        if crate::operation_granted(&model.resource, Some(actor.principal()), "list", true) {
            resources.insert(
                name.clone(),
                extensions::metadata(model, &actor, &app.registry),
            );
        }
    }
    Ok(Json(
        json!({"type":"namespace","name":"app","label":app.name,"resources":resources}),
    ))
}
async fn options(
    State(app): State<App>,
    headers: HeaderMap,
    Path(kind): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?);
    if let Some(model) = app.registry.models.get(&kind) {
        if !crate::operation_granted(&model.resource, Some(actor.principal()), "list", true) {
            return Err(ApiError::Forbidden);
        }
        return Ok(Json(extensions::metadata(model, &actor, &app.registry)));
    }
    if !KINDS.contains(&kind.as_str()) {
        return Err(ApiError::NotFound);
    }
    Ok(Json(schema(&kind)))
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
    user(&app, &headers).await?;
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
        if !fields(&kind).iter().any(|(f, _)| *f == sort.field) {
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
    user(&app, &headers).await?;
    if app.registry.models.contains_key(&kind) {
        return extension_api::retrieve(app, headers, kind, id, raw).await;
    }
    if !KINDS.contains(&kind.as_str()) {
        return Err(ApiError::NotFound);
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
async fn logout(State(app): State<App>, headers: HeaderMap) -> Result<Response, ApiError> {
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
    let mut response = redirect(&format!("{}/api/login/", app.origin), "dream_app", "", 0)?;
    response.headers_mut().append(
        header::SET_COOKIE,
        "dream_preview=; Path=/api; HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
async fn core_readonly(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let core = request
        .uri()
        .path()
        .strip_prefix("/api/admin/")
        .and_then(|p| p.split('/').next())
        .is_some_and(|kind| KINDS.contains(&kind));
    if core && !matches!(request.method().as_str(), "GET" | "OPTIONS") {
        return ApiError::MethodNotAllowed(request.method().to_string()).into_response();
    }
    next.run(request).await
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
        .route("/admin/{kind}/",get(list).options(options).post(extension_api::create))
        .route("/admin/{kind}/{id}/",get(retrieve).patch(extension_api::update).put(extension_api::replace).delete(extension_api::delete))
        .route("/admin/{kind}/{id}/actions/{action}/",axum::routing::post(extension_api::action))
        .route("/v0/s3/",get(s3)).with_state(app);
    Router::new()
        .nest("/api", routes)
        .layer(axum::middleware::from_fn(core_readonly))
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
