#![allow(clippy::too_many_lines, clippy::items_after_statements)]
#![cfg(feature = "application")]
//! Providers are an ordinary model: an app links them to the records they
//! serve (each entity's own books, each person's own account), roles reach
//! them with conditions like any model, and code is routed to the right one.
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Form, State},
    http::{HeaderMap, Request, StatusCode},
    routing::{get, post},
};
use dynamic_rust::{
    FieldKind,
    application::{
        App,
        extensions::{Actor, Context, Integration, Model, Registry, lock},
        router,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use uuid::Uuid;

fn registry(base: &str) -> Registry {
    let mut registry = Registry::default();
    registry
        .model(
            Model::new("entities", "entity")
                .field("name", FieldKind::String)
                .grant("clerk", &["list", "read", "create", "update", "delete"]),
        )
        .unwrap();
    registry
        .extend("providers", |providers| {
            providers
                .relation("entity", "entities")
                .label("entity", "Entity")
                .describe("entity", "The entity whose books this connection reaches.")
                .relation("user", "users")
                .label("user", "Person")
                .describe("user", "The person whose account this connection uses.")
        })
        .unwrap();
    registry
        .integration(
            Integration::oauth2("books", "Books")
                .authorize_url(&format!("{base}/authorize"))
                .token_url(&format!("{base}/oauth/token"))
                .account_params(&["companyId"])
                .client_secret_in_body()
                .base_url(base)
                .per("entity"),
        )
        .unwrap();
    registry
        .integration(
            Integration::token("ledger", "Ledger")
                .token_header("Authorization", "JWT {token}")
                .base_url(base)
                .check("/v0/me/")
                .per("user"),
        )
        .unwrap();
    registry
}

#[derive(Default)]
struct Service {
    seen: Vec<String>,
}
type Shared = Arc<Mutex<Service>>;
async fn me(State(service): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    service.lock().unwrap().seen.push(header.clone());
    if header.starts_with("JWT token-") {
        (StatusCode::OK, Json(json!({"ok":true})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({})))
    }
}
/// Each authorization code becomes its own access token.
async fn token(Form(form): Form<BTreeMap<String, String>>) -> (StatusCode, Json<Value>) {
    if form.get("client_id").map(String::as_str) != Some("client-1")
        || form.get("client_secret").map(String::as_str) != Some("secret-1")
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_client"})),
        );
    }
    let code = form.get("code").cloned().unwrap_or_default();
    (
        StatusCode::OK,
        Json(
            json!({"access_token":format!("access-{code}"),"refresh_token":format!("refresh-{code}"),"expires_in":3600}),
        ),
    )
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (u16, Value, HeaderMap) {
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
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        headers,
    )
}
async fn isolated_pool() -> PgPool {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("links_{}", Uuid::new_v4().simple());
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
/// The access token code reaches for `record`, or why it cannot.
async fn routed(
    pool: &PgPool,
    registry: &Registry,
    name: &str,
    record: Uuid,
) -> Result<String, String> {
    let mut tx = pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    let mut context = Context::new(&mut tx, registry, Actor::system());
    let result = context
        .integration_for(name, record)
        .await
        .map(|connection| connection.access_token)
        .map_err(|error| error.to_string());
    tx.rollback().await.unwrap();
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn integrations_connected_per_record_need_a_relation_on_providers() {
    let pool = isolated_pool().await;
    let mut registry = Registry::default();
    registry
        .integration(Integration::token("ledger", "Ledger").per("account"))
        .unwrap();
    let error = registry.migrate(&pool).await.unwrap_err().to_string();
    assert!(error.contains("add a relation field account"), "{error}");
    // Extending providers keeps fields unique and the model's name.
    assert!(
        registry
            .extend("providers", |providers| providers
                .field("status", FieldKind::String))
            .is_err()
    );
    assert!(
        registry.models["providers"]
            .resource
            .field("status")
            .is_some()
    );
    assert!(registry.extend("nothing", |model| model).is_err());
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn connections_serve_records_and_people_and_code_is_routed_to_them() {
    let service: Shared = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mock = Router::new()
        .route("/v0/me/", get(me))
        .route("/oauth/token", post(token))
        .with_state(service.clone());
    tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

    let pool = isolated_pool().await;
    let registry = registry(&base);
    registry.migrate(&pool).await.unwrap();
    registry.migrate(&pool).await.unwrap();
    let mut entities = BTreeMap::new();
    for name in ["A", "B", "C"] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'entities',$2)")
            .bind(id)
            .bind(json!({"name":format!("Entity {name}")}))
            .execute(&pool)
            .await
            .unwrap();
        entities.insert(name, id);
    }
    let mut users = BTreeMap::new();
    for name in ["owner", "alice", "bob"] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":name,"email":format!("{name}@example.com"),"data":{"roles":[]}}))
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
        users.insert(name, id);
    }
    let state = App {
        pool: pool.clone(),
        registry: Arc::new(registry.clone()),
        name: "Group".into(),
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
    let app = router(state);
    let (owner, alice, bob) = (
        "dream_app=owner-token",
        "dream_app=alice-token",
        "dream_app=bob-token",
    );

    // The code registers one provider per service; an app's own fields join the model.
    let (status, listed, _) = request(
        &app,
        "GET",
        "/api/admin/providers/?filter{primary}=true",
        owner,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{listed}");
    let main: BTreeMap<String, Value> = listed["providers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["integration"].is_string())
        .map(|p| (p["integration"].as_str().unwrap().to_owned(), p.clone()))
        .collect();
    assert_eq!(main.len(), 2, "{listed}");
    let books = format!(
        "/api/admin/providers/{}/",
        main["books"]["id"].as_str().unwrap()
    );
    let (_, meta, _) = request(&app, "OPTIONS", "/api/admin/providers/", owner, Value::Null).await;
    assert_eq!(meta["fields"]["entity"]["type"], "one");
    assert_eq!(meta["fields"]["entity"]["related"], "entities");
    assert_eq!(meta["section"], "Core");

    // --- Each entity's own books ----------------------------------------------------
    let (status, body, _) = request(
        &app,
        "PATCH",
        &books,
        owner,
        json!({"client_id":"client-1","client_secret":"secret-1"}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let add = |entity: &str, extra: Value| {
        let mut input = json!({"integration":"books","entity":entities[entity]});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().cloned().unwrap_or_default());
        input
    };
    let (status, a, _) = request(
        &app,
        "POST",
        "/api/admin/providers/",
        owner,
        add("A", json!({})),
    )
    .await;
    assert_eq!(status, 201, "{a}");
    let a = a["provider"].clone();
    assert_eq!(a["name"], "Books (Entity A)");
    assert_eq!(a["primary"], false);
    assert_eq!(a["kind"], "oauth2");
    assert_eq!(
        a["status"], "disconnected",
        "the main provider's client is ready"
    );
    for (input, field) in [
        (add("A", json!({})), "entity"),
        (json!({"integration":"books"}), "entity"),
        (add("B", json!({"client_id":"other"})), "client_id"),
        (
            json!({"integration":"nothing","entity":entities["B"]}),
            "integration",
        ),
    ] {
        let (status, body, _) =
            request(&app, "POST", "/api/admin/providers/", owner, input.clone()).await;
        assert_eq!(status, 400, "{input} {body}");
        assert!(body.to_string().contains(field), "{body}");
    }
    let a_path = format!("/api/admin/providers/{}/", a["id"].as_str().unwrap());
    let (status, body, _) = request(
        &app,
        "PATCH",
        &a_path,
        owner,
        json!({"client_secret":"other"}),
    )
    .await;
    assert_eq!(
        status, 400,
        "a connection uses the main provider's client: {body}"
    );
    let (status, b, _) = request(
        &app,
        "POST",
        "/api/admin/providers/",
        owner,
        add("B", json!({})),
    )
    .await;
    assert_eq!(status, 201, "{b}");
    let b_path = format!(
        "/api/admin/providers/{}/",
        b["provider"]["id"].as_str().unwrap()
    );

    // Connecting one signs in with the shared client and keeps its own tokens.
    let connect = |path: &str, code: &str, realm: &str| {
        let app = app.clone();
        let path = format!("{path}actions/connect/");
        let (code, realm) = (code.to_owned(), realm.to_owned());
        async move {
            let (status, body, _) = request(&app, "POST", &path, owner, json!({})).await;
            assert_eq!(status, 200, "{body}");
            let authorize = url::Url::parse(body["redirect"].as_str().unwrap()).unwrap();
            let query: BTreeMap<String, String> = authorize.query_pairs().into_owned().collect();
            assert_eq!(query["client_id"], "client-1");
            assert_eq!(
                query["redirect_uri"],
                "https://example.com/api/integrations/books/callback"
            );
            let (status, _, headers) = request(
                &app,
                "GET",
                &format!(
                    "/api/integrations/books/callback?state={}&code={code}&companyId={realm}",
                    query["state"]
                ),
                "",
                Value::Null,
            )
            .await;
            assert!((300..400).contains(&status), "{status}");
            headers
        }
    };
    connect(&a_path, "a", "111").await;
    connect(&b_path, "b", "222").await;
    let (_, shown, _) = request(&app, "GET", &a_path, owner, Value::Null).await;
    assert_eq!(shown["provider"]["status"], "connected");
    assert_eq!(shown["provider"]["account"], json!({"companyId":"111"}));
    assert!(
        shown["provider"]["redirect_uri"].is_null(),
        "only the main provider registers one"
    );

    // Code reaches each entity's books, and no other's.
    assert_eq!(
        routed(&pool, &registry, "books", entities["A"]).await,
        Ok("access-a".into())
    );
    assert_eq!(
        routed(&pool, &registry, "books", entities["B"]).await,
        Ok("access-b".into())
    );
    let missing = routed(&pool, &registry, "books", entities["C"])
        .await
        .unwrap_err();
    assert!(
        missing.contains("no connection for this entity"),
        "{missing}"
    );
    let mut tx = pool.begin().await.unwrap();
    let mut context = Context::new(&mut tx, &registry, Actor::system());
    let main_error = context.integration("books").await.unwrap_err().to_string();
    assert!(main_error.contains("not connected"), "{main_error}");
    let one = context
        .integration_for("nothing", entities["A"])
        .await
        .unwrap_err();
    assert!(one.to_string().contains("Unknown integration"));
    // Code may add a record's connection, waiting to be connected; asking
    // again finds the same one.
    lock(context.connection).await.unwrap();
    let c = context
        .add_connection("books", entities["C"])
        .await
        .unwrap();
    assert_eq!(
        context
            .add_connection("books", entities["C"])
            .await
            .unwrap(),
        c
    );
    tx.commit().await.unwrap();
    let (_, shown, _) = request(
        &app,
        "GET",
        &format!("/api/admin/providers/{c}/"),
        owner,
        Value::Null,
    )
    .await;
    assert_eq!(shown["provider"]["name"], "Books (Entity C)");
    assert_eq!(shown["provider"]["status"], "disconnected");

    // An entity with a connection stays until the connection goes.
    let (status, _, _) = request(
        &app,
        "DELETE",
        &format!("/api/admin/entities/{}/", entities["A"]),
        owner,
        Value::Null,
    )
    .await;
    assert_eq!(status, 409);
    // A new client on the main provider clears every connection's tokens.
    let (status, _, _) = request(
        &app,
        "PATCH",
        &books,
        owner,
        json!({"client_secret":"secret-2"}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, shown, _) = request(&app, "GET", &a_path, owner, Value::Null).await;
    assert_eq!(shown["provider"]["status"], "disconnected");
    assert!(
        routed(&pool, &registry, "books", entities["A"])
            .await
            .is_err()
    );
    // Removing a connection removes its tokens; the main provider stays.
    let (status, _, _) = request(&app, "DELETE", &a_path, owner, Value::Null).await;
    assert_eq!(status, 204);
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM app_integration_secrets WHERE provider LIKE 'books:%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kept, 1, "only B's tokens are left");
    assert_eq!(
        request(&app, "DELETE", &books, owner, Value::Null).await.0,
        409
    );

    // --- Each person's own account, through ordinary role rules ----------------------
    let mine = json!({"user":"$user.id"});
    let (status, role, _) = request(
        &app,
        "POST",
        "/api/admin/roles/",
        owner,
        json!({"name":"Member","permissions":{"providers":{
            "list":mine,"read":mine,"create":mine,"update":mine,"delete":mine,
            "connect":mine,"disconnect":mine,
            "fields":{"base_url":{"write_only":true}}}}}),
    )
    .await;
    assert_eq!(status, 201, "{role}");
    for person in ["alice", "bob"] {
        let (status, _, _) = request(
            &app,
            "PATCH",
            &format!("/api/admin/users/{}/", users[person]),
            owner,
            json!({"roles":[role["role"]["id"]]}),
        )
        .await;
        assert_eq!(status, 200);
    }
    // Someone adding their own connection serves themselves; nobody else's.
    let (status, theirs, _) = request(
        &app,
        "POST",
        "/api/admin/providers/",
        alice,
        json!({"integration":"ledger","user":users["bob"]}),
    )
    .await;
    assert_eq!(status, 403, "{theirs}");
    let (status, own, _) = request(
        &app,
        "POST",
        "/api/admin/providers/",
        alice,
        json!({"integration":"ledger","token":"token-alice"}),
    )
    .await;
    assert_eq!(status, 201, "{own}");
    let own = own["provider"].clone();
    assert_eq!(own["user"], users["alice"].to_string());
    assert_eq!(own["token"], "Saved");
    assert_eq!(own["status"], "disconnected");
    assert!(
        own.get("base_url").is_none(),
        "this role hides the base URL: {own}"
    );
    let own_path = format!("/api/admin/providers/{}/", own["id"].as_str().unwrap());
    let (status, bobs, _) = request(
        &app,
        "POST",
        "/api/admin/providers/",
        bob,
        json!({"integration":"ledger"}),
    )
    .await;
    assert_eq!(status, 201, "{bobs}");
    let bobs_path = format!(
        "/api/admin/providers/{}/",
        bobs["provider"]["id"].as_str().unwrap()
    );
    // Each sees and manages only their own.
    let (_, listed, _) = request(&app, "GET", "/api/admin/providers/", alice, Value::Null).await;
    assert_eq!(listed["providers"].as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(
        request(&app, "GET", &bobs_path, alice, Value::Null).await.0,
        404
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{bobs_path}actions/connect/"),
            alice,
            json!({})
        )
        .await
        .0,
        404
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &own_path,
            alice,
            json!({"user":users["owner"]})
        )
        .await
        .0,
        403,
        "a connection cannot be handed to someone else"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &own_path,
            owner,
            json!({"user":users["bob"]})
        )
        .await
        .0,
        400,
        "nor can anyone have two connections to one service"
    );
    let (status, connected, _) = request(
        &app,
        "POST",
        &format!("{own_path}actions/connect/"),
        alice,
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{connected}");
    assert_eq!(connected["provider"]["status"], "connected");
    assert_eq!(
        service.lock().unwrap().seen.last().unwrap(),
        "JWT token-alice"
    );
    assert_eq!(
        routed(&pool, &registry, "ledger", users["alice"]).await,
        Ok("token-alice".into())
    );
    assert!(
        routed(&pool, &registry, "ledger", users["bob"])
            .await
            .is_err()
    );
    // An administrator still sees everything, the base URL included.
    let (_, listed, _) = request(&app, "GET", "/api/admin/providers/", owner, Value::Null).await;
    assert!(listed["providers"][0].get("base_url").is_some());

    // Removing a person removes their own connections and tokens.
    let (status, _, _) = request(
        &app,
        "DELETE",
        &format!("/api/admin/users/{}/", users["alice"]),
        owner,
        Value::Null,
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(
        request(&app, "GET", &own_path, owner, Value::Null).await.0,
        404
    );
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM app_integration_secrets WHERE provider LIKE 'ledger:%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}
