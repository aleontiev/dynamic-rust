#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::similar_names
)]
#![cfg(feature = "application")]
//! Record actions as the admin sees and runs them, OAuth integrations kept as
//! `providers` records, and tasks that call outside services.
use axum::{
    Form, Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::{get, post},
};
use dynamic_rust::{
    ApiError, FieldKind,
    application::{
        App,
        extensions::{Context, Handler, Hook, Integration, Model, Registry, Storage, handler},
        router, task_runner,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

/// Orders start as drafts; only actions move them on.
struct Drafts;
#[handler]
impl Hook for Drafts {
    async fn before(
        &self,
        _: &mut Context<'_>,
        operation: &str,
        _: Option<&Value>,
        record: &mut Value,
    ) -> Result<(), ApiError> {
        if operation == "create" {
            record["state"] = json!("draft");
        }
        Ok(())
    }
}
struct SetState(&'static str);
#[handler]
impl Handler for SetState {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        let id = Uuid::parse_str(input["id"].as_str().unwrap()).unwrap();
        let mut patch = json!({"state":self.0});
        if let Some(reason) = input["data"]["reason"].as_str() {
            patch["note"] = json!(reason);
        }
        // Running the action is the permission; the person need not be able to
        // edit the order, and `state` is read-only for everyone.
        ctx.elevated().update("orders", id, patch).await
    }
}
/// Reads the connected company from the outside service and records it.
struct FetchCompany;
#[handler]
impl Handler for FetchCompany {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        let books = ctx.integration("books").await?;
        let url = format!(
            "{}/v3/company/{}",
            input["data"]["base"].as_str().unwrap(),
            books.account["realmId"].as_str().unwrap()
        );
        let company: Value = books
            .get(&url)
            .send()
            .await
            .map_err(ApiError::internal)?
            .error_for_status()
            .map_err(ApiError::internal)?
            .json()
            .await
            .map_err(ApiError::internal)?;
        ctx.create(
            "events",
            json!({"name":format!("{}:{}", input["idempotency_key"].as_str().unwrap(), company["name"].as_str().unwrap())}),
        )
        .await
    }
}
/// Calls an outside service that is slow to answer, then writes.
struct SlowCall;
#[handler]
impl Handler for SlowCall {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        let status = ctx
            .http()
            .get(input["data"]["url"].as_str().unwrap())
            .send()
            .await
            .map_err(ApiError::internal)?
            .status();
        ctx.create("events", json!({"name":format!("slow:{status}")}))
            .await
    }
}

/// Records who it ran as, for scheduled runs.
struct Heartbeat;
#[handler]
impl Handler for Heartbeat {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        ctx.create(
            "events",
            json!({"name":format!("{}:{}:{}", input["idempotency_key"].as_str().unwrap(), ctx.actor.is_superuser, ctx.actor.id)}),
        )
        .await
    }
}
fn registry(service: &str, storage: Storage) -> Registry {
    let mut registry = Registry::default();
    registry.storage(storage);
    let all = ["list", "read", "create", "update", "delete"];
    registry
        .model(
            Model::new("suppliers", "supplier")
                .field("name", FieldKind::String)
                .required("name")
                .grant("buyer", &all),
        )
        .unwrap();
    registry
        .model(
            Model::new("orders", "order")
                .field("name", FieldKind::String)
                .field("state", FieldKind::String)
                .readonly("state")
                .field("note", FieldKind::String)
                .readonly("note")
                .field("approver", FieldKind::Uuid)
                .grant("buyer", &all)
                .grant("viewer", &["list", "read"])
                .hook(Drafts),
        )
        .unwrap();
    registry
        .model(
            Model::new("events", "event")
                .field("name", FieldKind::String)
                .grant("buyer", &all),
        )
        .unwrap();
    registry
        .action("orders", "approve", &["buyer"], SetState("approved"))
        .unwrap();
    registry
        .action("orders", "reject", &["buyer"], SetState("rejected"))
        .unwrap();
    registry
        .action("orders", "reopen", &["buyer"], SetState("draft"))
        .unwrap();
    registry
        .describe_action(
            "orders",
            "approve",
            json!({"label":"Approve order","icon":"check","confirm":"Approve this order?","when":{"state":"draft"}}),
        )
        .unwrap();
    registry
        .describe_action(
            "orders",
            "reject",
            json!({"when":{"state__in":["draft","approved"]},"parameters":{
                "reason":{"type":"string","required":true,"label":"Why","description":"Shown to the requester."},
                "severity":{"type":"string","choices":["low",{"id":"high","label":"High"}]},
                "follow_up":{"type":"date"}}}),
        )
        .unwrap();
    registry.task("fetch_company", FetchCompany).unwrap();
    registry.task("slow_call", SlowCall).unwrap();
    registry.task("heartbeat", Heartbeat).unwrap();
    registry
        .integration(
            Integration::oauth2("books", "Books Online")
                .describe("Keeps suppliers and bills in step with the books.")
                .authorize_url("https://books.example/connect")
                .token_url(&format!("{service}/token"))
                .scopes(&["accounting", "openid"])
                .authorize_param("prompt", "consent")
                .account_params(&["realmId"]),
        )
        .unwrap();
    registry
}

#[test]
fn describing_actions_and_integrations_rejects_mistakes() {
    let mut registry = registry("http://127.0.0.1:9", Storage::Records);
    for (name, details) in [
        ("missing", json!({"label":"Nope"})),
        ("approve", json!({"colour":"red"})),
        ("approve", json!({"when":{"total":5}})),
        ("approve", json!({"when":{"state__gt":"a"}})),
        ("approve", json!({"when":{"state__in":"draft"}})),
        (
            "approve",
            json!({"parameters":{"reason":{"type":"relation"}}}),
        ),
        (
            "approve",
            json!({"parameters":{"reason":{"required":"yes"}}}),
        ),
        ("approve", json!({"parameters":{"Bad Name":{}}})),
        ("approve", json!({"label":5})),
    ] {
        assert!(
            registry
                .describe_action("orders", name, details.clone())
                .is_err(),
            "{name} {details}"
        );
    }
    for integration in [
        Integration::oauth2("books", "Again")
            .authorize_url("https://a.example/")
            .token_url("https://a.example/t"),
        Integration::oauth2("Bad Name", "Bad")
            .authorize_url("https://a.example/")
            .token_url("https://a.example/t"),
        Integration::oauth2("plain", "Plain")
            .authorize_url("http://a.example/")
            .token_url("https://a.example/t"),
        Integration::oauth2("missing", "Missing"),
    ] {
        assert!(registry.integration(integration).is_err());
    }
}

/// What the stand-in for the outside service has seen and will answer.
#[derive(Default)]
struct Service {
    access: String,
    refresh: String,
    issued: u32,
    refuse_refresh: bool,
    token_requests: Vec<BTreeMap<String, String>>,
    authorization: Vec<String>,
    app: OnceLock<Router>,
}
type Shared = Arc<Mutex<Service>>;

async fn token(
    State(service): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    use base64::Engine;
    let mut service = service.lock().unwrap();
    service.token_requests.push(form.clone());
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("client-123:secret-xyz")
    );
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_client"})),
        );
    }
    let valid = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            form.get("code").map(String::as_str) == Some("good-code")
                && form.get("redirect_uri").map(String::as_str)
                    == Some("https://example.com/api/integrations/books/callback")
        }
        Some("refresh_token") => {
            !service.refuse_refresh && form.get("refresh_token") == Some(&service.refresh)
        }
        _ => false,
    };
    if !valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant","error_description":"Token revoked"})),
        );
    }
    service.issued += 1;
    service.access = format!("access-{}", service.issued);
    service.refresh = format!("refresh-{}", service.issued);
    (
        StatusCode::OK,
        Json(
            json!({"access_token":service.access,"refresh_token":service.refresh,"expires_in":3600,"token_type":"bearer"}),
        ),
    )
}
async fn company(State(service): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let mut service = service.lock().unwrap();
    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    service.authorization.push(authorization.clone());
    if authorization != format!("Bearer {}", service.access) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (StatusCode::OK, Json(json!({"name":"Acme"})))
}
/// Answers only after the app has accepted a write from someone else, which it
/// cannot while the calling task holds the application write lock.
async fn slow(State(service): State<Shared>) -> StatusCode {
    let app = service.lock().unwrap().app.get().unwrap().clone();
    let (status, _) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        "dream_app=buyer-token",
        json!({"name":"Written meanwhile"}),
    )
    .await;
    StatusCode::from_u16(status).unwrap()
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> (u16, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (u16, Value) {
    let body = (!body.is_null()).then_some(body);
    let (status, _, value) = send(app, method, path, cookie, body).await;
    (status, value)
}

async fn isolated_pool(prefix: &str) -> PgPool {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
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

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn actions_integrations_and_outside_calls_follow_roles_in_records() {
    actions_integrations_and_outside_calls_follow_roles(Storage::Records).await;
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn actions_integrations_and_outside_calls_follow_roles_in_tables() {
    actions_integrations_and_outside_calls_follow_roles(Storage::Tables).await;
}
async fn actions_integrations_and_outside_calls_follow_roles(storage: Storage) {
    let service: Shared = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mock = Router::new()
        .route("/token", post(token))
        .route("/v3/company/{realm}", get(company))
        .route("/slow", get(slow))
        .with_state(service.clone());
    tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

    let pool = isolated_pool("integrations").await;
    let registry = registry(&base, storage);
    registry.migrate(&pool).await.unwrap();
    registry.migrate(&pool).await.unwrap();
    let mut users = BTreeMap::new();
    for (name, roles) in [
        ("owner", json!([])),
        ("buyer", json!(["buyer"])),
        ("viewer", json!(["viewer"])),
        ("auditor", json!([])),
        ("integrator", json!([])),
        ("approver", json!([])),
        ("newcomer", json!([])),
    ] {
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
        name: "Procurement".into(),
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
    service.lock().unwrap().app.set(app.clone()).unwrap();
    let cookie = |name: &str| format!("dream_app={name}-token");
    let (owner, buyer, viewer, auditor, integrator, approver, newcomer) = (
        cookie("owner"),
        cookie("buyer"),
        cookie("viewer"),
        cookie("auditor"),
        cookie("integrator"),
        cookie("approver"),
        cookie("newcomer"),
    );

    // --- Record actions -------------------------------------------------------
    // The admin gets everything it needs to show and run each action.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/orders/", &buyer, Value::Null).await;
    let actions: BTreeMap<String, Value> = meta["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["name"].as_str().unwrap().to_owned(), a.clone()))
        .collect();
    assert_eq!(
        actions["approve"],
        json!({"name":"approve","label":"Approve order","icon":"check","confirm":"Approve this order?",
               "method":"post","methods":["POST"],"detail":true,
               "url":"/api/admin/orders/:id/actions/approve/","when":{"instance.state":"draft"}})
    );
    assert_eq!(actions["reopen"]["label"], "Reopen");
    assert!(actions["reopen"].get("when").is_none());
    let reject = &actions["reject"];
    assert_eq!(
        reject["when"],
        json!({"instance.state.in":["draft","approved"]})
    );
    assert_eq!(reject["parameters"]["reason"]["label"], "Why");
    assert_eq!(reject["parameters"]["reason"]["required"], true);
    assert_eq!(reject["parameters"]["reason"]["type"], "string");
    assert_eq!(
        reject["parameters"]["severity"]["choices"],
        json!([{"id":"low","label":"low"},{"id":"high","label":"High"}])
    );
    assert_eq!(reject["parameters"]["follow_up"]["type"], "date");
    assert_eq!(reject["parameters"]["follow_up"]["required"], false);
    // A role the actions are not granted to sees none and may run none.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/orders/", &viewer, Value::Null).await;
    assert_eq!(meta["actions"], json!([]));
    let (_, order) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        &buyer,
        json!({"name":"PO-1"}),
    )
    .await;
    // A field the record does not hold yet comes back as null, not missing.
    assert!(order["order"].as_object().unwrap().contains_key("note"));
    assert!(order["order"]["note"].is_null());
    let order_id = order["order"]["id"].as_str().unwrap().to_owned();
    let run = |name: &str| format!("/api/admin/orders/{order_id}/actions/{name}/");
    assert_eq!(
        send(&app, "POST", &run("approve"), &viewer, None).await.0,
        403
    );
    assert_eq!(
        send(&app, "POST", &run("approve"), &newcomer, None).await.0,
        403
    );
    // The admin posts actions without parameters with no body at all.
    let (status, _, body) = send(&app, "POST", &run("approve"), &buyer, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "approved");
    // `when` is enforced, not just used to hide the button.
    let (status, _, body) = send(&app, "POST", &run("approve"), &buyer, None).await;
    assert_eq!(status, 409, "{body}");
    // Required parameters must be present and non-empty.
    let (status, _, body) = send(
        &app,
        "POST",
        &run("reject"),
        &buyer,
        Some(json!({"reason":"  "})),
    )
    .await;
    assert_eq!(status, 400);
    assert!(body.to_string().contains("reason"), "{body}");
    assert_eq!(
        send(
            &app,
            "POST",
            &run("reject"),
            &buyer,
            Some(json!("not json"))
        )
        .await
        .0,
        400
    );
    let (status, _, body) = send(
        &app,
        "POST",
        &run("reject"),
        &buyer,
        Some(json!({"reason":"Over budget"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["note"], "Over budget");
    // The owner is a superuser and may run any action.
    assert_eq!(
        send(&app, "POST", &run("reopen"), &owner, Some(json!({})))
            .await
            .0,
        200
    );

    // --- Actions granted by a stored role's permission map ---------------------
    // The permissions editor learns which actions each resource offers.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/roles/", &owner, Value::Null).await;
    let offered = &meta["fields"]["permissions"]["resources"];
    assert_eq!(
        offered["orders"]["actions"],
        json!([{"name":"approve","label":"Approve order"},{"name":"reject","label":"Reject"},{"name":"reopen","label":"Reopen"}])
    );
    assert!(offered["suppliers"]["actions"].is_null());
    // The managed Admin role holds every action, and may manage providers.
    let (_, roles) = request(&app, "GET", "/api/admin/roles/", &owner, Value::Null).await;
    let admin_role = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Admin")
        .unwrap()
        .clone();
    assert_eq!(admin_role["permissions"]["orders"]["approve"], true);
    assert_eq!(admin_role["permissions"]["orders"]["reject"], true);
    assert_eq!(
        admin_role["permissions"]["providers"],
        json!({"list":true,"read":true,"create":true,"update":true,"delete":true})
    );
    // Maps may name only registered actions of that resource.
    for permissions in [
        json!({"orders":{"ship":true}}),
        json!({"suppliers":{"approve":true}}),
        json!({"orders":{"approve":{"colour":"red"}}}),
    ] {
        let (status, body) = request(
            &app,
            "POST",
            "/api/admin/roles/",
            &owner,
            json!({"name":"Broken","permissions":permissions}),
        )
        .await;
        assert_eq!(status, 400, "{permissions} {body}");
    }
    // An approver may see orders and approve those assigned to them, and no others.
    let (status, role) = request(
        &app,
        "POST",
        "/api/admin/roles/",
        &owner,
        json!({"name":"Approver","permissions":{"orders":{"list":true,"read":true,"approve":{"approver":"$user.id"}}}}),
    )
    .await;
    assert_eq!(status, 201, "{role}");
    let (status, _) = request(
        &app,
        "PATCH",
        &format!("/api/admin/users/{}/", users["approver"]),
        &owner,
        json!({"roles":[role["role"]["id"]]}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/orders/",
        &approver,
        Value::Null,
    )
    .await;
    let names: Vec<_> = meta["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].clone())
        .collect();
    assert_eq!(
        names,
        vec![json!("approve")],
        "only the granted action shows"
    );
    let mine = request(
        &app,
        "POST",
        "/api/admin/orders/",
        &buyer,
        json!({"name":"PO-2","approver":users["approver"]}),
    )
    .await
    .1["order"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let theirs = request(
        &app,
        "POST",
        "/api/admin/orders/",
        &buyer,
        json!({"name":"PO-3","approver":users["buyer"]}),
    )
    .await
    .1["order"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let act = |id: &str, name: &str| format!("/api/admin/orders/{id}/actions/{name}/");
    assert_eq!(
        send(&app, "POST", &act(&theirs, "approve"), &approver, None)
            .await
            .0,
        403,
        "not assigned to them"
    );
    assert_eq!(
        send(
            &app,
            "POST",
            &act(&mine, "reject"),
            &approver,
            Some(json!({"reason":"no"}))
        )
        .await
        .0,
        403,
        "not granted"
    );
    let (status, _, body) = send(&app, "POST", &act(&mine, "approve"), &approver, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "approved");
    // Only the workflow moves an order: even a buyer, who may edit orders,
    // cannot set its state.
    let (status, body) = request(
        &app,
        "PATCH",
        &format!("/api/admin/orders/{theirs}/"),
        &buyer,
        json!({"state":"approved"}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    // The role grants reading orders, not changing them directly.
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{theirs}/"),
            &approver,
            json!({"state":"approved"})
        )
        .await
        .0,
        403
    );

    // --- Providers and who may see or manage them ------------------------------
    let (status, providers) =
        request(&app, "GET", "/api/admin/providers/", &owner, Value::Null).await;
    assert_eq!(status, 200);
    let providers = providers["providers"].as_array().unwrap().clone();
    assert_eq!(providers.len(), 1, "migrating twice keeps one record");
    let provider = &providers[0];
    let provider_id = provider["id"].as_str().unwrap().to_owned();
    assert_eq!(provider["name"], "Books Online");
    assert_eq!(provider["integration"], "books");
    assert_eq!(provider["kind"], "oauth2");
    assert_eq!(provider["status"], "needs_credentials");
    assert_eq!(provider["enabled"], true);
    assert_eq!(provider["client_secret"], "");
    assert_eq!(
        provider["redirect_uri"],
        "https://example.com/api/integrations/books/callback"
    );
    assert_eq!(
        provider["description"],
        "Keeps suppliers and bills in step with the books."
    );
    let detail = format!("/api/admin/providers/{provider_id}/");
    let connect = format!("{detail}actions/connect/");
    let disconnect = format!("{detail}actions/disconnect/");
    // People without a role, and members whose roles do not reach providers,
    // cannot see them.
    assert_eq!(
        request(&app, "GET", "/api/admin/providers/", &newcomer, Value::Null)
            .await
            .0,
        403
    );
    assert_eq!(
        request(&app, "GET", "/api/admin/providers/", &buyer, Value::Null)
            .await
            .0,
        403
    );
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", &buyer, Value::Null).await;
    assert!(meta["resources"]["providers"].is_null());
    assert_eq!(send(&app, "POST", &connect, &buyer, None).await.0, 403);
    // Stored roles: one that may look, one that may manage.
    for (role, permissions, holder) in [
        (
            "Auditor",
            json!({"providers":{"list":true,"read":true}}),
            "auditor",
        ),
        (
            "Integrator",
            json!({"providers":{"list":true,"read":true,"update":true}}),
            "integrator",
        ),
    ] {
        let (status, created) = request(
            &app,
            "POST",
            "/api/admin/roles/",
            &owner,
            json!({"name":role,"permissions":permissions}),
        )
        .await;
        assert_eq!(status, 201, "{created}");
        let (status, _) = request(
            &app,
            "PATCH",
            &format!("/api/admin/users/{}/", users[holder]),
            &owner,
            json!({"roles":[created["role"]["id"]]}),
        )
        .await;
        assert_eq!(status, 200);
    }
    let (status, _) = request(&app, "GET", &detail, &auditor, Value::Null).await;
    assert_eq!(status, 200);
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/providers/",
        &auditor,
        Value::Null,
    )
    .await;
    assert_eq!(meta["actions"], json!([]));
    assert_eq!(meta["permissions"]["update"], false);
    assert_eq!(meta["fields"]["client_id"]["read_only"], true);
    assert_eq!(
        request(&app, "PATCH", &detail, &auditor, json!({"client_id":"x"}))
            .await
            .0,
        403
    );
    assert_eq!(send(&app, "POST", &connect, &auditor, None).await.0, 403);
    assert_eq!(send(&app, "POST", &disconnect, &auditor, None).await.0, 403);
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/providers/",
        &integrator,
        Value::Null,
    )
    .await;
    assert_eq!(meta["permissions"]["update"], true);
    assert_eq!(meta["permissions"]["create"], false);
    assert_eq!(meta["permissions"]["delete"], false);
    assert_eq!(meta["fields"]["client_id"]["read_only"], false);
    assert_eq!(meta["fields"]["client_secret"]["read_only"], false);
    assert_eq!(meta["fields"]["status"]["read_only"], true);
    assert_eq!(meta["fields"]["redirect_uri"]["read_only"], true);
    assert_eq!(meta["fields"]["integration"]["read_only"], true);
    let names: Vec<_> = meta["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("connect"), json!("disconnect")]);
    // The integrator may not add or remove providers; the owner may add one by
    // hand, but not remove one the code registered, nor change its kind.
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/providers/",
            &integrator,
            json!({"name":"Mail","kind":"email"})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(&app, "DELETE", &detail, &integrator, Value::Null)
            .await
            .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/providers/",
            &owner,
            json!({"name":"x"})
        )
        .await
        .0,
        400
    );
    let (status, body) = request(&app, "DELETE", &detail, &owner, Value::Null).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        request(&app, "PATCH", &detail, &integrator, json!({"kind":"email"}))
            .await
            .0,
        400
    );
    let (status, renamed) =
        request(&app, "PATCH", &detail, &integrator, json!({"name":"Books"})).await;
    assert_eq!(status, 200, "{renamed}");
    assert_eq!(renamed["provider"]["name"], "Books");
    assert_eq!(renamed["provider"]["integration"], "books");
    let (status, mail) = request(
        &app,
        "POST",
        "/api/admin/providers/",
        &owner,
        json!({"name":"Mail","kind":"email"}),
    )
    .await;
    assert_eq!(status, 201, "{mail}");
    let mail_path = format!(
        "/api/admin/providers/{}/",
        mail["provider"]["id"].as_str().unwrap()
    );
    assert!(mail["provider"]["redirect_uri"].is_null());
    assert_eq!(
        request(&app, "PATCH", &mail_path, &owner, json!({"client_id":"x"}))
            .await
            .0,
        400,
        "only integrations take credentials"
    );
    assert_eq!(
        request(&app, "DELETE", &mail_path, &owner, Value::Null)
            .await
            .0,
        204
    );

    // --- Connecting -------------------------------------------------------------
    let (status, _, body) = send(&app, "POST", &connect, &integrator, None).await;
    assert_eq!(status, 409, "credentials come first: {body}");
    let (status, saved) = request(
        &app,
        "PATCH",
        &detail,
        &integrator,
        json!({"client_id":" client-123 ","client_secret":"secret-xyz","status":"connected"}),
    )
    .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["provider"]["client_id"], "client-123");
    assert_eq!(saved["provider"]["client_secret"], "Saved");
    assert_eq!(
        saved["provider"]["status"], "disconnected",
        "status is not writable"
    );
    let stored: String =
        sqlx::query_scalar("SELECT data::text FROM app_records WHERE kind='providers'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !stored.contains("secret-xyz"),
        "the secret stays off the record"
    );
    let (_, listed) = request(&app, "GET", "/api/admin/providers/", &auditor, Value::Null).await;
    assert_eq!(listed["providers"][0]["client_secret"], "Saved");
    assert!(!listed.to_string().contains("secret-xyz"));
    // Leaving the secret blank (as a form does) keeps it.
    let (status, _) = request(
        &app,
        "PATCH",
        &detail,
        &integrator,
        json!({"client_secret":"","enabled":true}),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _, body) = send(
        &app,
        "POST",
        &connect,
        &integrator,
        Some(json!({"next":"https://example.com/orders/?page=2"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let authorize = url::Url::parse(body["redirect"].as_str().unwrap()).unwrap();
    assert_eq!(authorize.host_str(), Some("books.example"));
    let query: BTreeMap<String, String> = authorize.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "client-123");
    assert_eq!(
        query["redirect_uri"],
        "https://example.com/api/integrations/books/callback"
    );
    assert_eq!(query["scope"], "accounting openid");
    assert_eq!(query["prompt"], "consent");
    let state_token = query["state"].clone();
    let callback = |params: &str| format!("/api/integrations/books/callback?{params}");
    assert_eq!(
        send(
            &app,
            "GET",
            &callback("state=forged&code=good-code"),
            "",
            None
        )
        .await
        .0,
        400
    );
    let (status, headers, _) = send(
        &app,
        "GET",
        &callback(&format!("state={state_token}&code=good-code&realmId=9130")),
        "",
        None,
    )
    .await;
    assert!((300..400).contains(&status), "{status}");
    assert_eq!(headers["location"], "https://example.com/orders/?page=2");
    // A state is single-use.
    assert_eq!(
        send(
            &app,
            "GET",
            &callback(&format!("state={state_token}&code=good-code")),
            "",
            None
        )
        .await
        .0,
        400
    );
    let (_, record) = request(&app, "GET", &detail, &auditor, Value::Null).await;
    let record = &record["provider"];
    assert_eq!(record["status"], "connected");
    assert_eq!(record["account"], json!({"realmId":"9130"}));
    assert!(record["connected_at"].is_string());
    assert!(record["error"].is_null());
    assert!(
        !record.to_string().contains("access-1"),
        "tokens are never returned"
    );

    // --- Using the connection from a task --------------------------------------
    async fn enqueue(pool: &PgPool, name: &str, key: &str, actor: Uuid, input: Value) {
        sqlx::query(
            "INSERT INTO app_tasks(id,name,idempotency_key,input,actor) VALUES($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(name)
        .bind(key)
        .bind(input)
        .bind(json!({"id":actor}))
        .execute(pool)
        .await
        .unwrap();
    }
    async fn events(pool: &PgPool, storage: Storage) -> Vec<String> {
        sqlx::query_scalar(match storage {
            Storage::Records => {
                "SELECT data->>'name' FROM app_records WHERE kind='events' ORDER BY created"
            }
            Storage::Tables => "SELECT name FROM events ORDER BY created",
        })
        .fetch_all(pool)
        .await
        .unwrap()
    }
    // Anyone's task may use the app's connection: a buyer has no providers grant.
    enqueue(
        &pool,
        "fetch_company",
        "first",
        users["buyer"],
        json!({"base":base}),
    )
    .await;
    enqueue(
        &pool,
        "fetch_company",
        "second",
        users["buyer"],
        json!({"base":base}),
    )
    .await;
    assert_eq!(
        task_runner::drain(&state, Duration::from_secs(10))
            .await
            .unwrap(),
        2,
        "drain runs every due task"
    );
    assert_eq!(
        events(&pool, storage).await,
        vec!["first:Acme", "second:Acme"]
    );
    assert_eq!(
        service.lock().unwrap().authorization,
        vec!["Bearer access-1", "Bearer access-1"]
    );
    assert_eq!(
        task_runner::drain(&state, Duration::from_secs(10))
            .await
            .unwrap(),
        0
    );

    // An access token about to expire is refreshed first, and a rotated refresh
    // token is kept.
    sqlx::query("UPDATE app_integration_secrets SET expires=now()+interval '30 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    enqueue(
        &pool,
        "fetch_company",
        "third",
        users["buyer"],
        json!({"base":base}),
    )
    .await;
    assert_eq!(
        task_runner::drain(&state, Duration::from_secs(10))
            .await
            .unwrap(),
        1
    );
    assert_eq!(events(&pool, storage).await.last().unwrap(), "third:Acme");
    let (access, refresh): (String, String) = sqlx::query_as(
        "SELECT access_token,refresh_token FROM app_integration_secrets WHERE provider='books'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (access.as_str(), refresh.as_str()),
        ("access-2", "refresh-2")
    );
    assert_eq!(
        service.lock().unwrap().token_requests.last().unwrap()["refresh_token"],
        "refresh-1"
    );

    // When the service refuses to refresh, the task fails and the provider says
    // why, even though the task's own transaction rolled back.
    service.lock().unwrap().refuse_refresh = true;
    sqlx::query("UPDATE app_integration_secrets SET expires=now()")
        .execute(&pool)
        .await
        .unwrap();
    enqueue(
        &pool,
        "fetch_company",
        "fourth",
        users["buyer"],
        json!({"base":base}),
    )
    .await;
    task_runner::drain(&state, Duration::from_secs(10))
        .await
        .unwrap();
    let (state_name, error): (String, Option<String>) =
        sqlx::query_as("SELECT state,error FROM app_tasks WHERE idempotency_key='fourth'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state_name, "queued", "{error:?}");
    assert!(
        error
            .as_deref()
            .unwrap_or_default()
            .contains("Token revoked"),
        "the queue keeps why the task failed: {error:?}"
    );
    let (_, record) = request(&app, "GET", &detail, &integrator, Value::Null).await;
    assert_eq!(record["provider"]["status"], "error");
    assert!(
        record["provider"]["error"]
            .as_str()
            .unwrap()
            .contains("Token revoked")
    );
    assert!(
        !events(&pool, storage)
            .await
            .contains(&"fourth:Acme".to_owned())
    );
    sqlx::query("DELETE FROM app_tasks WHERE idempotency_key='fourth'")
        .execute(&pool)
        .await
        .unwrap();

    // A refused authorization leaves the reason on the provider.
    let (_, _, body) = send(&app, "POST", &connect, &integrator, None).await;
    let state_token: String = url::Url::parse(body["redirect"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let (status, headers, _) = send(
        &app,
        "GET",
        &callback(&format!(
            "state={state_token}&error=access_denied&error_description=The+user+said+no"
        )),
        "",
        None,
    )
    .await;
    assert!((300..400).contains(&status));
    assert_eq!(
        headers["location"],
        format!("https://example.com/providers/{provider_id}/")
    );
    let (_, record) = request(&app, "GET", &detail, &integrator, Value::Null).await;
    assert!(
        record["provider"]["error"]
            .as_str()
            .unwrap()
            .contains("The user said no")
    );

    // Disconnecting drops the tokens; tasks then say it is not connected.
    let (status, _, body) = send(&app, "POST", &disconnect, &integrator, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["provider"]["status"], "disconnected");
    let token: Option<String> = sqlx::query_scalar(
        "SELECT access_token FROM app_integration_secrets WHERE provider='books'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(token.is_none());
    let mut tx = pool.begin().await.unwrap();
    let actor = state
        .actor(
            &json!({"id":users["buyer"].to_string(),"email":"buyer@example.com","roles":["buyer"]}),
        )
        .await
        .unwrap();
    let mut context = Context::new(&mut tx, &state.registry, actor);
    let refused = context.integration("books").await.unwrap_err();
    assert!(refused.to_string().contains("not connected"), "{refused}");
    assert!(context.integration("unknown").await.is_err());
    drop(context);
    tx.rollback().await.unwrap();
    // Replacing the client clears a connection made with the old one.
    sqlx::query("UPDATE app_integration_secrets SET access_token='stale'")
        .execute(&pool)
        .await
        .unwrap();
    let (_, saved) = request(
        &app,
        "PATCH",
        &detail,
        &integrator,
        json!({"client_id":"client-456"}),
    )
    .await;
    assert_eq!(saved["provider"]["status"], "disconnected");
    let token: Option<String> = sqlx::query_scalar(
        "SELECT access_token FROM app_integration_secrets WHERE provider='books'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(token.is_none());
    let (_, saved) = request(&app, "PATCH", &detail, &integrator, json!({"client_id":""})).await;
    assert_eq!(saved["provider"]["status"], "needs_credentials");

    // --- Outside calls do not hold the application write lock ------------------
    enqueue(
        &pool,
        "slow_call",
        "slow",
        users["buyer"],
        json!({"url":format!("{base}/slow")}),
    )
    .await;
    let drained = tokio::time::timeout(
        Duration::from_secs(20),
        task_runner::drain(&state, Duration::from_secs(5)),
    )
    .await
    .expect("a task waiting on an outside service must not block other writers");
    assert_eq!(drained.unwrap(), 1);
    assert_eq!(
        events(&pool, storage).await.last().unwrap(),
        "slow:201 Created"
    );
    let written: i64 = sqlx::query_scalar(match storage {
        Storage::Records => "SELECT count(*) FROM app_records WHERE kind='suppliers' AND data->>'name'='Written meanwhile'",
        Storage::Tables => "SELECT count(*) FROM suppliers WHERE name='Written meanwhile'",
    })
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(written, 1);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn shipped_roles_are_checked_created_and_keep_an_administrators_changes_in_records() {
    shipped_roles_are_checked_created_and_keep_an_administrators_changes(Storage::Records).await;
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn shipped_roles_are_checked_created_and_keep_an_administrators_changes_in_tables() {
    shipped_roles_are_checked_created_and_keep_an_administrators_changes(Storage::Tables).await;
}
async fn shipped_roles_are_checked_created_and_keep_an_administrators_changes(storage: Storage) {
    let pool = isolated_pool("shipped_roles").await;
    let base = "http://127.0.0.1:9";
    let mut registry = registry(base, storage);
    for name in ["", "authenticated", "*", "admin", " ADMIN "] {
        assert!(registry.role(name, json!({})).is_err(), "{name:?}");
    }
    assert!(registry.role("Clerk", json!(["orders"])).is_err());
    let clerk = json!({"orders":{"list":true,"read":true,"approve":{"approver":"$user.id"}}});
    let auditor = json!({"orders":{"list":true,"read":true}});
    registry.role("Clerk", clerk.clone()).unwrap();
    registry.role("Auditor", auditor.clone()).unwrap();
    assert!(
        registry.role("clerk", json!({})).is_err(),
        "names are case-insensitive"
    );
    registry.migrate(&pool).await.unwrap();
    registry.migrate(&pool).await.unwrap();
    let roles = |pool: PgPool| async move {
        let rows: Vec<(String, Value)> = sqlx::query_as(
            "SELECT data->>'name',data->'permissions' FROM app_records WHERE kind='roles' ORDER BY data->>'name'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        rows.into_iter().collect::<BTreeMap<_, _>>()
    };
    let saved = roles(pool.clone()).await;
    assert_eq!(
        saved.len(),
        3,
        "Admin, Auditor and Clerk, once each: {saved:?}"
    );
    assert_eq!(saved["Clerk"], clerk);
    assert_eq!(saved["Auditor"], auditor);

    // An administrator narrows the Auditor role through the API.
    let owner = Uuid::new_v4();
    sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
        .bind(owner)
        .bind(json!({"name":"owner","email":"owner@example.com","data":{"roles":[]}}))
        .execute(&pool)
        .await
        .unwrap();
    {
        use sha2::{Digest, Sha256};
        sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '1 hour')")
            .bind(format!("{:x}", Sha256::digest(b"owner-token")))
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
    }
    let state = App {
        pool: pool.clone(),
        registry: Arc::new(registry),
        name: "Procurement".into(),
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
    let (_, listed) = request(
        &app,
        "GET",
        "/api/admin/roles/",
        "dream_app=owner-token",
        Value::Null,
    )
    .await;
    let auditor_id = listed["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["name"] == "Auditor")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!listed.to_string().contains("default_permissions"));
    let narrowed = json!({"orders":{"list":true}});
    let (status, _) = request(
        &app,
        "PATCH",
        &format!("/api/admin/roles/{auditor_id}/"),
        "dream_app=owner-token",
        json!({"permissions":narrowed}),
    )
    .await;
    assert_eq!(status, 200);

    // The next release widens both defaults: the untouched Clerk follows, the
    // narrowed Auditor keeps the administrator's version.
    let mut next = registry_with_roles(
        base,
        storage,
        &[
            (
                "Clerk",
                json!({"orders":{"list":true,"read":true,"approve":true,"reject":true}}),
            ),
            (
                "Auditor",
                json!({"orders":{"list":true,"read":true},"suppliers":{"list":true}}),
            ),
        ],
    );
    next.migrate(&pool).await.unwrap();
    let saved = roles(pool.clone()).await;
    assert_eq!(saved["Clerk"]["orders"]["reject"], true);
    assert_eq!(saved["Auditor"], narrowed);

    // A map the app's code gets wrong stops the release instead of granting nothing.
    for wrong in [
        json!({"invoices":{"list":true}}),
        json!({"orders":{"ship":true}}),
        json!({"orders":{"read":{"colour":"red"}}}),
        json!({"users":{"list":{"name":"x"}}}),
    ] {
        next = registry_with_roles(base, storage, &[("Broken", wrong.clone())]);
        let error = next.migrate(&pool).await.unwrap_err();
        assert!(error.to_string().contains("Broken"), "{wrong} {error}");
    }
}

fn registry_with_roles(service: &str, storage: Storage, roles: &[(&str, Value)]) -> Registry {
    let mut registry = registry(service, storage);
    for (name, permissions) in roles {
        registry.role(name, permissions.clone()).unwrap();
    }
    registry
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn scheduled_tasks_run_once_per_period_as_the_app_in_records() {
    scheduled_tasks_run_once_per_period_as_the_app(Storage::Records).await;
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn scheduled_tasks_run_once_per_period_as_the_app_in_tables() {
    scheduled_tasks_run_once_per_period_as_the_app(Storage::Tables).await;
}
async fn scheduled_tasks_run_once_per_period_as_the_app(storage: Storage) {
    let mut registry = registry("http://127.0.0.1:9", storage);
    for (task, every) in [
        ("missing", 60),
        ("heartbeat", 59),
        ("heartbeat", 8 * 24 * 3600),
    ] {
        assert!(
            registry.schedule(task, Duration::from_secs(every)).is_err(),
            "{task} {every}"
        );
    }
    registry
        .schedule("heartbeat", Duration::from_secs(300))
        .unwrap();
    assert!(
        registry
            .schedule("heartbeat", Duration::from_secs(600))
            .is_err()
    );
    let pool = isolated_pool("schedules").await;
    registry.migrate(&pool).await.unwrap();
    let app = App {
        pool: pool.clone(),
        registry: Arc::new(registry),
        name: "Procurement".into(),
        origin: "https://example.com".into(),
        preview_origins: vec![],
        mail_from: "noreply@example.com".into(),
        mail_region: "us-east-1".into(),
        mail_api_key: None,
        google_auth: None,
        branding: json!({}),
        mail_endpoint: None,
        revision: "test".into(),
        superusers: dynamic_rust::application::parse_superusers(""),
        operator_secret: None,
    };
    assert_eq!(
        task_runner::drain(&app, Duration::from_secs(5))
            .await
            .unwrap(),
        1
    );
    // The same period queues nothing new.
    assert_eq!(
        task_runner::drain(&app, Duration::from_secs(5))
            .await
            .unwrap(),
        0
    );
    let ran: Vec<String> = sqlx::query_scalar(match storage {
        Storage::Records => "SELECT data->>'name' FROM app_records WHERE kind='events'",
        Storage::Tables => "SELECT name FROM events",
    })
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(ran.len(), 1);
    assert!(ran[0].starts_with("schedule:"), "{ran:?}");
    assert!(
        ran[0].ends_with(":true:"),
        "runs as the app itself: {ran:?}"
    );
    // A finished run older than a week is cleared away.
    sqlx::query("UPDATE app_tasks SET updated=now()-interval '8 days'")
        .execute(&pool)
        .await
        .unwrap();
    task_runner::enqueue_scheduled(&app).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM app_tasks WHERE state='completed'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
