#![allow(clippy::too_many_lines, clippy::items_after_statements)]
#![cfg(feature = "application")]
//! Services an administrator connects with a token, at a base URL chosen per
//! stage, and records pulled from them in step by `external_id`.
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::get,
};
use dynamic_rust::{
    ApiError, FieldKind,
    application::{
        App,
        extensions::{Auth, Context, Handler, Integration, Model, Registry, handler},
        router, task_runner,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

/// Pulls every collection from the ledger, page by page, the way a sync of a
/// Dynamic REST API does.
struct PullCollections;
#[handler]
impl Handler for PullCollections {
    async fn run(&self, ctx: &mut Context<'_>, _: Value) -> Result<Value, ApiError> {
        let ledger = ctx.integration("ledger").await?;
        let mut page = 1;
        let mut pulled = 0;
        loop {
            let body: Value = ledger
                .get(&format!("/v0/collections/?page={page}&per_page=2"))
                .send()
                .await
                .map_err(ApiError::internal)?
                .error_for_status()
                .map_err(ApiError::internal)?
                .json()
                .await
                .map_err(ApiError::internal)?;
            for remote in body["collections"].as_array().cloned().unwrap_or_default() {
                ctx.upsert_external(
                    "collections",
                    &remote["id"].to_string(),
                    json!({"name":remote["name"],"amount":remote["amount"]}),
                )
                .await?;
                pulled += 1;
            }
            if page >= body["meta"]["total_pages"].as_u64().unwrap_or(1) {
                break;
            }
            page += 1;
        }
        Ok(json!({"pulled":pulled}))
    }
}
/// Tries to sync into a model that does not track outside ids.
struct PullNotes;
#[handler]
impl Handler for PullNotes {
    async fn run(&self, ctx: &mut Context<'_>, _: Value) -> Result<Value, ApiError> {
        ctx.upsert_external("notes", "1", json!({"name":"x"})).await
    }
}

fn ledger(base: &str) -> Integration {
    Integration::token("ledger", "Ledger API")
        .describe("Pulls collections from the ledger.")
        .token_header("Authorization", "JWT {token}")
        .base_url("https://api.ledger.example")
        .stage_base_url("dev", base)
        .check("/v0/me/")
}
fn registry(base: &str) -> Registry {
    let mut registry = Registry::default();
    let all = ["list", "read", "create", "update", "delete"];
    registry
        .model(
            Model::new("collections", "collection")
                .field("name", FieldKind::String)
                .field("amount", FieldKind::String)
                .external_id()
                .grant("clerk", &all),
        )
        .unwrap();
    registry
        .model(
            Model::new("notes", "note")
                .field("name", FieldKind::String)
                .grant("clerk", &all),
        )
        .unwrap();
    registry.task("pull_collections", PullCollections).unwrap();
    registry.task("pull_notes", PullNotes).unwrap();
    registry.integration(ledger(base)).unwrap();
    registry
}

#[test]
fn token_integrations_reject_mistakes() {
    let mut registry = Registry::default();
    for integration in [
        Integration::token("a", "A").token_header("Bad Header", "{token}"),
        Integration::token("b", "B").token_header("Authorization", "Bearer"),
        Integration::token("c", "C").check("v0/me/"),
        Integration::token("d", "D").base_url("http://api.example.com"),
        Integration::token("e", "E").base_url("https://user:pw@api.example.com"),
        Integration::token("f", "F").stage_base_url("Dev Stage", "https://api.example.com"),
    ] {
        let name = integration.name.clone();
        assert!(registry.integration(integration).is_err(), "{name}");
    }
    registry
        .integration(
            Integration::token("ok", "Ok")
                .token_header("X-Api-Key", "{token}")
                .base_url("https://api.example.com/")
                .stage_base_url("dev", "https://api.example.dev")
                .check("/v0/me/"),
        )
        .unwrap();
    let ok = &registry.integrations["ok"];
    assert_eq!(ok.base_url.as_deref(), Some("https://api.example.com"));
    assert_eq!(ok.auth, Auth::Token);
    // Without APP_STAGE the app runs as dev.
    assert_eq!(
        ok.default_base_url().as_deref(),
        Some("https://api.example.dev")
    );
}

#[derive(Default)]
struct Ledger {
    authorization: Vec<String>,
    names: Vec<&'static str>,
}
type Shared = Arc<Mutex<Ledger>>;
fn authorized(service: &Shared, headers: &HeaderMap) -> bool {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let ok = header == "JWT good-token";
    service.lock().unwrap().authorization.push(header);
    ok
}
async fn me(State(service): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if authorized(&service, &headers) {
        (StatusCode::OK, Json(json!({"user":{"id":1}})))
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail":"Bad token"})),
        )
    }
}
async fn collections(
    State(service): State<Shared>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&service, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    let names = service.lock().unwrap().names.clone();
    let page: usize = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let rows: Vec<Value> = names
        .iter()
        .enumerate()
        .skip((page - 1) * 2)
        .take(2)
        .map(|(i, name)| json!({"id":i + 1,"name":name,"amount":format!("{}.00", (i + 1) * 10)}))
        .collect();
    (
        StatusCode::OK,
        Json(
            json!({"collections":rows,"meta":{"page":page,"per_page":2,"total_results":names.len(),"total_pages":names.len().div_ceil(2)}}),
        ),
    )
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (u16, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie);
    if !body.is_null() {
        builder = builder.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(if body.is_null() {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn isolated_pool() -> PgPool {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("tokens_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    PgPoolOptions::new()
        .max_connections(6)
        .after_connect(move |conn, _| {
            let query = format!("SET search_path TO {schema}");
            Box::pin(async move {
                sqlx::query(&query).execute(conn).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap()
}
async fn enqueue(pool: &PgPool, name: &str, key: &str) {
    sqlx::query(
        "INSERT INTO app_tasks(id,name,idempotency_key,input,actor) VALUES($1,$2,$3,'{}',$4)",
    )
    .bind(Uuid::new_v4())
    .bind(name)
    .bind(key)
    .bind(json!({"system":true}))
    .execute(pool)
    .await
    .unwrap();
}
async fn task(pool: &PgPool, key: &str) -> (String, Option<String>) {
    sqlx::query_as("SELECT state,error FROM app_tasks WHERE idempotency_key=$1")
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn token_providers_connect_by_checking_the_token_and_syncs_keep_outside_ids() {
    let service: Shared = Arc::default();
    service.lock().unwrap().names = vec!["Kampala", "Jinja", "Gulu"];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mock = Router::new()
        .route("/v0/me/", get(me))
        .route("/v0/collections/", get(collections))
        .with_state(service.clone());
    tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

    let pool = isolated_pool().await;
    let registry = registry(&base);
    registry.migrate(&pool).await.unwrap();
    registry.migrate(&pool).await.unwrap();
    let mut users = std::collections::BTreeMap::new();
    for (name, roles) in [("owner", json!([])), ("clerk", json!(["clerk"]))] {
        let id = Uuid::new_v4();
        users.insert(name, id);
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":name,"email":format!("{name}@example.com"),"data":{"roles":roles}}))
            .execute(&pool)
            .await
            .unwrap();
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(format!("{name}-token").as_bytes()));
        sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '1 hour')")
            .bind(digest)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    let state = App {
        pool: pool.clone(),
        registry: Arc::new(registry),
        name: "Collections".into(),
        origin: "https://example.com".into(),
        preview_origins: vec![],
        mail_from: "noreply@example.com".into(),
        mail_region: "us-east-1".into(),
        mail_api_key: None,
        google_auth: None,
        branding: json!({}),
        mail_endpoint: None,
        revision: "test".into(),
        superusers: dynamic_rust::application::parse_superusers("owner@example.com"),
        operator_secret: None,
    };
    let app = router(state.clone());
    let (owner, clerk) = ("dream_app=owner-token", "dream_app=clerk-token");

    // The admin shows each kind of provider only its own fields.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/providers/", owner, Value::Null).await;
    let fields = &meta["fields"];
    assert_eq!(fields["token"]["secret"], true);
    assert_eq!(fields["token"]["depends"], json!({"kind":"token"}));
    // Only the provider the code registers holds an OAuth client.
    assert_eq!(
        fields["client_id"]["depends"],
        json!({"kind":"oauth2","primary":true})
    );
    assert_eq!(
        fields["redirect_uri"]["depends"],
        json!({"kind":"oauth2","primary":true})
    );
    assert_eq!(
        fields["base_url"]["depends"],
        json!({"integration.isnull":false})
    );
    assert_eq!(fields["base_url"]["read_only"], false);
    assert_eq!(fields["default_base_url"]["read_only"], true);

    // The integration is a provider waiting for its token, at the dev URL.
    let (status, listed) = request(&app, "GET", "/api/admin/providers/", owner, Value::Null).await;
    assert_eq!(status, 200, "{listed}");
    let provider = listed["providers"][0].clone();
    assert_eq!(provider["kind"], "token");
    assert_eq!(provider["status"], "needs_credentials");
    assert_eq!(provider["token"], Value::Null, "nothing saved yet");
    assert_eq!(provider["default_base_url"], base);
    assert!(provider["redirect_uri"].is_null());
    let detail = format!("/api/admin/providers/{}/", provider["id"].as_str().unwrap());
    let connect = format!("{detail}actions/connect/");

    // Until it is connected, syncs fail and say why.
    enqueue(&pool, "pull_collections", "early").await;
    task_runner::drain(&state, Duration::from_secs(10))
        .await
        .unwrap();
    let (_, error) = task(&pool, "early").await;
    assert!(error.unwrap().contains("Ledger API is not connected"));
    let (status, _) = request(&app, "POST", &connect, owner, json!({})).await;
    assert_eq!(status, 409, "no token yet");

    // A token provider takes a token and a base URL, never client credentials.
    for (input, field) in [
        (json!({"client_id":"abc"}), "client_id"),
        (json!({"client_secret":"abc"}), "client_secret"),
        (json!({"base_url":"http://api.ledger.example"}), "base_url"),
        (
            json!({"base_url":"https://api.ledger.example/?tenant=1"}),
            "base_url",
        ),
        (json!({"token":5}), "token"),
    ] {
        let (status, body) = request(&app, "PATCH", &detail, owner, input.clone()).await;
        assert_eq!(status, 400, "{input} {body}");
        assert!(
            !body[field].is_null() || body.to_string().contains(field),
            "{body}"
        );
    }
    // Only people whose roles reach providers may set it.
    let (status, _) = request(&app, "PATCH", &detail, clerk, json!({"token":"stolen"})).await;
    assert_eq!(status, 403);

    // A wrong token is refused when connecting, and the provider says why.
    let (status, saved) =
        request(&app, "PATCH", &detail, owner, json!({"token":"bad-token"})).await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["provider"]["status"], "disconnected");
    assert_eq!(saved["provider"]["token"], "Saved");
    let (status, refused) = request(&app, "POST", &connect, owner, json!({"next":"/"})).await;
    assert_eq!(status, 409);
    assert!(refused.to_string().contains("401"), "{refused}");
    let (_, shown) = request(&app, "GET", &detail, owner, Value::Null).await;
    assert_eq!(shown["provider"]["status"], "error");
    assert!(
        shown["provider"]["error"]
            .as_str()
            .unwrap()
            .contains("Check the token")
    );

    // The right token connects, sent the way the service expects.
    request(&app, "PATCH", &detail, owner, json!({"token":"good-token"})).await;
    let (status, connected) = request(&app, "POST", &connect, owner, json!({})).await;
    assert_eq!(status, 200, "{connected}");
    assert_eq!(connected["provider"]["status"], "connected");
    assert!(connected["provider"]["connected_at"].is_string());
    assert_eq!(
        service.lock().unwrap().authorization.last().unwrap(),
        "JWT good-token"
    );
    // The token is never returned or kept on the record.
    let (_, listed) = request(&app, "GET", "/api/admin/providers/", owner, Value::Null).await;
    assert!(!listed.to_string().contains("good-token"));
    let stored: String =
        sqlx::query_scalar("SELECT data::text FROM app_records WHERE kind='providers'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!stored.contains("good-token"));

    // A sync pulls every page and keeps each record's outside id.
    enqueue(&pool, "pull_collections", "first").await;
    task_runner::drain(&state, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(task(&pool, "first").await, ("completed".into(), None));
    let rows = |pool: PgPool| async move {
        sqlx::query_as::<_, (String, String, String)>(
            "SELECT data->>'external_id',data->>'name',data->>'amount' FROM app_records WHERE kind='collections' ORDER BY data->>'external_id'",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    assert_eq!(
        rows(pool.clone()).await,
        vec![
            ("1".into(), "Kampala".into(), "10.00".into()),
            ("2".into(), "Jinja".into(), "20.00".into()),
            ("3".into(), "Gulu".into(), "30.00".into()),
        ]
    );
    // Pulling again updates in place: no duplicates.
    service.lock().unwrap().names = vec!["Kampala Central", "Jinja", "Gulu", "Mbale"];
    enqueue(&pool, "pull_collections", "second").await;
    task_runner::drain(&state, Duration::from_secs(10))
        .await
        .unwrap();
    let synced = rows(pool.clone()).await;
    assert_eq!(synced.len(), 4);
    assert_eq!(
        synced[0],
        ("1".into(), "Kampala Central".into(), "10.00".into())
    );

    // People see the outside id but cannot set or change it.
    let (status, created) = request(
        &app,
        "POST",
        "/api/admin/collections/",
        clerk,
        json!({"name":"Typed in","external_id":"99"}),
    )
    .await;
    assert!(
        status == 400 || created["collection"]["external_id"].is_null(),
        "{created}"
    );
    let (_, listed) = request(&app, "GET", "/api/admin/collections/", clerk, Value::Null).await;
    assert!(
        listed["collections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["external_id"] == "2")
    );
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/collections/",
        clerk,
        Value::Null,
    )
    .await;
    assert_eq!(meta["fields"]["external_id"]["read_only"], true);

    // A model that does not track outside ids cannot be synced into.
    enqueue(&pool, "pull_notes", "notes").await;
    task_runner::drain(&state, Duration::from_secs(10))
        .await
        .unwrap();
    assert!(
        task(&pool, "notes")
            .await
            .1
            .unwrap()
            .contains("external_id")
    );

    // Another base URL (a tenant, a sandbox) needs connecting again, then is used.
    let (status, moved) = request(
        &app,
        "PATCH",
        &detail,
        owner,
        json!({"base_url":format!("{base}/")}),
    )
    .await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["provider"]["base_url"], base);
    assert_eq!(moved["provider"]["status"], "disconnected");
    let (status, _) = request(&app, "POST", &connect, owner, json!({})).await;
    assert_eq!(status, 200);
    // Clearing it goes back to the default, connected again.
    let (_, cleared) = request(&app, "PATCH", &detail, owner, json!({"base_url":""})).await;
    assert!(cleared["provider"]["base_url"].is_null());
    assert_eq!(cleared["provider"]["status"], "disconnected");
    let (status, _) = request(&app, "POST", &connect, owner, json!({})).await;
    assert_eq!(status, 200);

    // Disconnecting forgets the token.
    let (status, disconnected) = request(
        &app,
        "POST",
        &format!("{detail}actions/disconnect/"),
        owner,
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{disconnected}");
    let (_, shown) = request(&app, "GET", &detail, owner, Value::Null).await;
    assert_eq!(shown["provider"]["status"], "needs_credentials");
    assert_eq!(shown["provider"]["token"], Value::Null);
    let secret: Option<String> = sqlx::query_scalar(
        "SELECT client_secret FROM app_integration_secrets WHERE provider='ledger'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(secret.is_none());
}
