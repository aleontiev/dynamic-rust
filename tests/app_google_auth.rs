#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::similar_names
)]
#![cfg(feature = "application")]
//! Private loopback broker contract tests; no Google token bypass in the app.
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dynamic_rust::application::{App, GoogleAuth, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use uuid::Uuid;

fn opaque() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
#[derive(Default)]
struct Broker {
    profile: Value,
    codes: HashMap<String, (Value, Value)>,
    issued: Vec<(String, String)>,
    exchanges: usize,
    reject_requests: bool,
    redirect: Option<String>,
}
struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    config: App,
    app: Router,
    broker: Arc<Mutex<Broker>>,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DREAM_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let schema = format!("app_google_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let search = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |conn, _| {
                let query = format!("SET search_path TO {search}");
                Box::pin(async move {
                    sqlx::query(&query).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&std::env::var("DREAM_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../src/application/templates/app-schema.sql"))
            .execute(&pool)
            .await
            .unwrap();
        let broker = Arc::new(Mutex::new(Broker {
            profile: json!({"provider":"google","sub":"google-subject-one","email":"viewer@gmail.com","email_verified":true,"name":"Google Viewer"}),
            ..Broker::default()
        }));
        let requests = broker.clone();
        let tokens = broker.clone();
        let routes=Router::new().route("/v1/requests",axum::routing::post(move|Json(body):Json<Value>|{
            let shared=requests.clone();async move {
                let mut broker=shared.lock().unwrap();
                if broker.reject_requests || body["client_secret"]!="private-fixture-secret" { return (StatusCode::UNAUTHORIZED,Json(json!({"error":"private error payload"}))); }
                assert!(body.get("code_verifier").is_none());
                let code=opaque();let state=body["state"].as_str().unwrap().to_owned();
                let profile=broker.profile.clone();broker.codes.insert(code.clone(),(body,profile));broker.issued.push((state,code));
                (StatusCode::OK,Json(json!({"authorization_url":broker.redirect.as_deref().unwrap_or("https://accounts.google.com/o/oauth2/v2/auth?fixture=1")})))
            }
        })).route("/v1/token",axum::routing::post(move|Json(body):Json<Value>|{
            let shared=tokens.clone();async move {
                let mut broker=shared.lock().unwrap();broker.exchanges+=1;
                let code=body["code"].as_str().unwrap();
                let entry=broker.codes.get(code).cloned();
                if let Some((request,profile))=entry {
                    let challenge=URL_SAFE_NO_PAD.encode(Sha256::digest(body["code_verifier"].as_str().unwrap().as_bytes()));
                    if body["client_id"]==request["client_id"] && body["client_secret"]=="private-fixture-secret" && request["code_challenge"]==challenge {
                        broker.codes.remove(code);return (StatusCode::OK,Json(profile));
                    }
                }
                (StatusCode::UNAUTHORIZED,Json(json!({"error":"private token payload"})))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        let config = App {
            registry: std::sync::Arc::default(),
            pool: pool.clone(),
            name: "Google test app".into(),
            preview_origins: vec![],
            origin: "https://app.example.org".into(),
            mail_from: "unused@example.org".into(),
            mail_region: "eu-west-1".into(),
            mail_api_key: None,
            google_auth: Some(GoogleAuth {
                broker_url: "https://auth.dreamy.so".into(),
                client_id: "project:dev".into(),
                client_secret: "private-fixture-secret".into(),
                test_endpoint: Some(endpoint),
            }),
            branding: json!({}),
            mail_endpoint: None,
            revision: "fixture".into(),
            superusers: std::collections::BTreeSet::default(),
            operator_secret: None,
        };
        let app = router(config.clone());
        Self {
            admin,
            pool,
            schema,
            config,
            app,
            broker,
            server,
        }
    }
    async fn start(&self, app: &Router) -> (String, String, String) {
        self.start_at(app, "/api/auth/google").await
    }
    async fn start_at(&self, app: &Router, path: &str) -> (String, String, String) {
        let (status, headers, _) = call(app, path, None).await;
        assert_eq!(status, 303);
        assert!(
            headers["location"]
                .to_str()
                .unwrap()
                .starts_with("https://accounts.google.com/")
        );
        let cookie = headers["set-cookie"].to_str().unwrap();
        assert!(cookie.contains("HttpOnly; Secure; SameSite=Lax; Max-Age=600"));
        let cookie = cookie.split(';').next().unwrap().to_owned();
        let state = cookie.strip_prefix("dream_google=").unwrap().to_owned();
        let code = self
            .broker
            .lock()
            .unwrap()
            .issued
            .iter()
            .find(|(s, _)| s == &state)
            .unwrap()
            .1
            .clone();
        (state, code, cookie)
    }
    fn profile(&self, subject: &str, email: &str, hd: Option<&str>) {
        self.broker.lock().unwrap().profile = json!({"provider":"google","sub":subject,"email":email,"email_verified":true,"name":"Google Viewer","hd":hd});
    }
    async fn user(&self, email: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":"Magic viewer","email":email,"data":{}}))
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'identities',$2)")
            .bind(Uuid::new_v4())
            .bind(
                json!({"provider":"email_magic_link","subject":format!("email:{email}"),"user":id}),
            )
            .execute(&self.pool)
            .await
            .unwrap();
        id
    }
    async fn close(self) {
        self.server.abort();
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}
async fn call(app: &Router, path: &str, cookie: Option<&str>) -> (u16, HeaderMap, Value) {
    let mut request = Request::builder().uri(path);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
    )
}
fn callback(state: &str, code: &str) -> String {
    format!("/api/auth/google/callback?state={state}&code={code}")
}
fn failed(headers: &HeaderMap, reason: &str) {
    assert_eq!(
        headers["location"],
        format!("https://app.example.org/api/login/?google_error={reason}")
    );
    assert!(
        !headers
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("dream_app="))
    );
}
fn session(headers: &HeaderMap) -> String {
    headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| v.starts_with("dream_app="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn google_sign_in_binds_state_pkce_identity_session_and_logout() {
    let f = Fixture::new().await;
    let (_, _, html) = call(&f.app, "/api/login/", None).await;
    assert!(html.as_str().unwrap().contains("Continue with Google"));
    assert!(!html.as_str().unwrap().contains("private-fixture-secret"));
    let mut disabled = f.config.clone();
    disabled.google_auth = None;
    let (_, _, html) = call(&router(disabled), "/api/login/", None).await;
    assert!(!html.as_str().unwrap().contains("Continue with Google"));
    let (state, code, cookie) = f.start(&f.app).await;
    let (stored, verifier): (String, String) =
        sqlx::query_as("SELECT digest,verifier FROM app_google_states")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(stored, digest(&state));
    assert_ne!(stored, state);
    assert_eq!(verifier.len(), 64);
    let (_, h, _) = call(&f.app, &callback(&state, &code), None).await;
    failed(&h, "expired");
    assert_eq!(f.broker.lock().unwrap().exchanges, 0);
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some("dream_google=wrong")).await;
    failed(&h, "expired");
    let (status, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    assert_eq!(status, 303);
    assert_eq!(h["location"], "https://app.example.org");
    let session = session(&h);
    let (status, _, me) = call(&f.app, "/api/admin/users/me/", Some(&session)).await;
    assert_eq!(status, 200);
    assert_eq!(me["user"]["email"], "viewer@gmail.com");
    assert!(
        h.get_all("set-cookie")
            .iter()
            .any(|h| h.to_str().unwrap().contains("Max-Age=43200"))
    );
    let identity: Value =
        sqlx::query_scalar("SELECT data FROM app_records WHERE kind='identities'")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(identity["provider"], "google");
    assert_eq!(identity["subject"], "google-subject-one");
    let verification: Value =
        sqlx::query_scalar("SELECT data FROM app_records WHERE kind='identity_verifications'")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(verification["method"], "google");
    assert_eq!(verification["verified"], true);
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    failed(&h, "expired");
    assert_eq!(f.broker.lock().unwrap().exchanges, 1);
    // A return page given when starting comes back with the session; anything off this app does not.
    for (next, location) in [
        (
            "%2Forders%2F%3Fpage%3D2",
            "https://app.example.org/orders/?page=2",
        ),
        (
            "https%3A%2F%2Fevil.example.org%2F",
            "https://app.example.org",
        ),
    ] {
        let (state, code, cookie) = f
            .start_at(&f.app, &format!("/api/auth/google?next={next}"))
            .await;
        let (status, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
        assert_eq!(status, 303);
        assert_eq!(h["location"], location, "{next}");
    }
    let (_, h, _) = call(&f.app, "/api/logout/", Some(&session)).await;
    assert_eq!(h["location"], "https://app.example.org/api/login/");
    assert_eq!(
        call(&f.app, "/api/admin/users/me/", Some(&session)).await.0,
        401
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn google_expiry_cancellation_and_failed_exchange_consume_local_state() {
    let f = Fixture::new().await;
    let (state, code, cookie) = f.start(&f.app).await;
    sqlx::query("UPDATE app_google_states SET expires=now()-interval '1 second'")
        .execute(&f.pool)
        .await
        .unwrap();
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    failed(&h, "expired");
    assert_eq!(f.broker.lock().unwrap().exchanges, 0);
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(
        &f.app,
        &format!("/api/auth/google/callback?state={state}&error=private_payload"),
        Some(&cookie),
    )
    .await;
    failed(&h, "cancelled");
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    failed(&h, "expired");
    let (state, _, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&f.app, &callback(&state, &opaque()), Some(&cookie)).await;
    failed(&h, "unavailable");
    let (_, h, _) = call(&f.app, &callback(&state, &opaque()), Some(&cookie)).await;
    failed(&h, "expired");
    assert_eq!(f.broker.lock().unwrap().exchanges, 1);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn google_rejects_cross_client_code_pkce_swaps_and_code_replay() {
    let f = Fixture::new().await;
    let mut other = f.config.clone();
    other.google_auth.as_mut().unwrap().client_id = "project:production".into();
    let other = router(other);
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&other, &callback(&state, &code), Some(&cookie)).await;
    failed(&h, "expired");
    assert_eq!(f.broker.lock().unwrap().exchanges, 0);
    let (other_state, _, other_cookie) = f.start(&other).await;
    let (_, h, _) = call(&other, &callback(&other_state, &code), Some(&other_cookie)).await;
    failed(&h, "unavailable");
    let (second_state, _, second_cookie) = f.start(&f.app).await;
    let (_, h, _) = call(
        &f.app,
        &callback(&second_state, &code),
        Some(&second_cookie),
    )
    .await;
    failed(&h, "unavailable");
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    assert_eq!(h["location"], "https://app.example.org");
    let (third_state, _, third_cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&f.app, &callback(&third_state, &code), Some(&third_cookie)).await;
    failed(&h, "unavailable");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_sessions")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn google_links_only_authoritative_email_and_preserves_stable_subject() {
    let f = Fixture::new().await;
    for (email, hd, allowed) in [
        ("viewer@gmail.com", None, true),
        ("staff@example.org", Some("example.org"), true),
        ("external@example.net", None, false),
    ] {
        let existing = f.user(email).await;
        f.profile(email, email, hd);
        let (state, code, cookie) = f.start(&f.app).await;
        let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
        if allowed {
            let (_, _, me) = call(&f.app, "/api/admin/users/me/", Some(&session(&h))).await;
            assert_eq!(me["user"]["id"], existing.to_string());
        } else {
            failed(&h, "email_link");
        }
    }
    // New external-email users can sign in; future sign-ins use sub, even if email changes.
    f.profile("stable-external", "new@example.net", None);
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    let (_, _, first) = call(&f.app, "/api/admin/users/me/", Some(&session(&h))).await;
    f.profile("stable-external", "external@example.net", None);
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    let (_, _, second) = call(&f.app, "/api/admin/users/me/", Some(&session(&h))).await;
    assert_eq!(first["user"]["id"], second["user"]["id"]);
    assert_eq!(second["user"]["email"], "new@example.net");
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn google_sign_in_sets_a_missing_profile_photo_from_a_google_host_only() {
    let f = Fixture::new().await;
    let photo = "https://lh3.googleusercontent.com/a/ACg8ocK=s96-c";
    let sign_in = |subject: &str, email: &str, picture: Value| {
        f.broker.lock().unwrap().profile = json!({"provider":"google","sub":subject,"email":email,"email_verified":true,"name":"Google Viewer","picture":picture});
    };
    // A new person: the photo Google shows for them becomes theirs.
    sign_in("photo-one", "photo@gmail.com", json!(photo));
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    let (_, _, me) = call(&f.app, "/api/admin/users/me/", Some(&session(&h))).await;
    assert_eq!(me["user"]["photo"], photo);
    // A photo already set is kept, whatever Google sends now.
    sign_in(
        "photo-one",
        "photo@gmail.com",
        json!("https://lh3.googleusercontent.com/a/other=s96-c"),
    );
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    let (_, _, me) = call(&f.app, "/api/admin/users/me/", Some(&session(&h))).await;
    assert_eq!(me["user"]["photo"], photo);
    // Only https URLs on Google's image hosts are stored.
    for (subject, email, picture) in [
        (
            "photo-two",
            "plain@gmail.com",
            json!("http://lh3.googleusercontent.com/a/x"),
        ),
        (
            "photo-three",
            "elsewhere@gmail.com",
            json!("https://attacker.example/photo.png"),
        ),
        ("photo-four", "none@gmail.com", Value::Null),
    ] {
        sign_in(subject, email, picture);
        let (state, code, cookie) = f.start(&f.app).await;
        let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
        let (_, _, me) = call(&f.app, "/api/admin/users/me/", Some(&session(&h))).await;
        assert_eq!(me["user"]["email"], email);
        assert!(me["user"]["photo"].is_null(), "{email}");
    }
    // The schema lists the photo as a read-only image the admin can show.
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/api/admin/users/")
        .header("cookie", session(&h))
        .body(Body::empty())
        .unwrap();
    let response = f.app.clone().oneshot(request).await.unwrap();
    let schema: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    assert_eq!(schema["fields"]["photo"]["type"], "image upload");
    assert_eq!(schema["fields"]["photo"]["read_only"], true);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn google_rejects_unverified_profiles_and_untrusted_redirects() {
    let f = Fixture::new().await;
    f.broker.lock().unwrap().reject_requests = true;
    let (_, headers, _) = call(&f.app, "/api/auth/google", None).await;
    failed(&headers, "unavailable");
    f.broker.lock().unwrap().reject_requests = false;
    for redirect in [
        "https://accounts.google.com.evil.example/",
        "http://accounts.google.com/",
        "https://user:secret@accounts.google.com/",
    ] {
        f.broker.lock().unwrap().redirect = Some(redirect.into());
        let (_, h, _) = call(&f.app, "/api/auth/google", None).await;
        failed(&h, "unavailable");
    }
    f.broker.lock().unwrap().redirect = None;
    let states: i64 = sqlx::query_scalar("SELECT count(*) FROM app_google_states")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        states, 0,
        "Failed authorization requests must discard local state"
    );
    for (field, value) in [
        ("email_verified", json!(false)),
        ("provider", json!("other")),
        ("sub", json!("")),
        ("email", json!("invalid")),
    ] {
        f.profile("valid-sub", "new@gmail.com", None);
        f.broker.lock().unwrap().profile[field] = value;
        let (state, code, cookie) = f.start(&f.app).await;
        let (_, h, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
        failed(&h, "unavailable");
    }
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM app_records WHERE kind='users'")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn concurrent_google_logins_create_one_identity_and_user() {
    let f = Fixture::new().await;
    let (s1, c1, k1) = f.start(&f.app).await;
    let (s2, c2, k2) = f.start(&f.app).await;
    let p1 = callback(&s1, &c1);
    let p2 = callback(&s2, &c2);
    let (r1, r2) = tokio::join!(call(&f.app, &p1, Some(&k1)), call(&f.app, &p2, Some(&k2)));
    assert_eq!(r1.1["location"], "https://app.example.org");
    assert_eq!(r2.1["location"], "https://app.example.org");
    for kind in ["users", "identities", "identity_verifications"] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_records WHERE kind=$1")
            .bind(kind)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and private loopback broker"]
async fn schema_upgrade_preserves_magic_identity_and_namespaces_google_subjects() {
    let f = Fixture::new().await;
    let id = f.user("viewer@gmail.com").await;
    sqlx::raw_sql("DROP INDEX app_identity_provider_subject; CREATE UNIQUE INDEX app_identity_subject ON app_records((data->>'subject')) WHERE kind='identities';")
        .execute(&f.pool).await.unwrap();
    // Upgrade an existing magic-link app, then rerun bootstrap idempotently.
    for _ in 0..2 {
        sqlx::raw_sql(include_str!("../src/application/templates/app-schema.sql"))
            .execute(&f.pool)
            .await
            .unwrap();
    }
    f.profile("email:viewer@gmail.com", "viewer@gmail.com", None);
    let (state, code, cookie) = f.start(&f.app).await;
    let (_, headers, _) = call(&f.app, &callback(&state, &code), Some(&cookie)).await;
    let (_, _, me) = call(&f.app, "/api/admin/users/me/", Some(&session(&headers))).await;
    assert_eq!(me["user"]["id"], id.to_string());
    let identities: i64 =
        sqlx::query_scalar("SELECT count(*) FROM app_records WHERE kind='identities'")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(identities, 2);
    f.close().await;
}
