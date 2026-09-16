#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::similar_names
)]
#![cfg(feature = "application")]
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request},
};
use dynamic_rust::application::{App, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

const CORE: [&str; 7] = [
    "users",
    "identities",
    "identity_verifications",
    "roles",
    "dashboards",
    "views",
    "providers",
];
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    app: Router,
    cookie: String,
    user: Uuid,
    mail: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    mail_server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        Self::configure(false, None).await
    }
    async fn with_preview(preview: bool) -> Self {
        Self::configure(preview, None).await
    }
    async fn configure(preview: bool, operator_secret: Option<&str>) -> Self {
        let url = std::env::var("DREAM_TEST_DATABASE_URL").expect("set DREAM_TEST_DATABASE_URL");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("runtime_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let search = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |conn, _| {
                let query = format!("SET search_path TO {search}");
                Box::pin(async move {
                    sqlx::query(&query).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../src/application/templates/app-schema.sql"))
            .execute(&pool)
            .await
            .unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(user)
            .bind(json!({"name":"Viewer","email":"viewer@example.org","data":{}}))
            .execute(&pool)
            .await
            .unwrap();
        let token = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '1 hour')").bind(digest(&token)).bind(user).execute(&pool).await.unwrap();
        let mail = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let received = mail.clone();
        let mail_router = Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                let received = received.clone();
                async move {
                    if body["to"] == "delivery-failure@example.org" {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                    }
                    received.lock().unwrap().push(body);
                    axum::http::StatusCode::ACCEPTED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mail_endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let mail_server = tokio::spawn(async move {
            axum::serve(listener, mail_router).await.unwrap();
        });
        let app = router(App {
            registry: std::sync::Arc::default(),
            pool: pool.clone(),
            name: "Dummy test".into(),
            preview_origins: if preview {
                vec!["https://dreamy.example.com".into()]
            } else {
                vec![]
            },
            origin: "https://dummy.example.org".into(),
            mail_from: "no-reply@example.org".into(),
            mail_region: "eu-west-1".into(),
            mail_api_key: None,
            google_auth: None,
            branding: json!({"company_name":"Example Company","primary_color":"#123456","accent_color":"#abcdef"}),
            mail_endpoint: Some(mail_endpoint),
            revision: "immutable-revision".into(),
            superusers: ["owner@example.org".to_string()].into_iter().collect(),
            operator_secret: operator_secret.map(str::to_owned),
        });
        Self {
            admin,
            pool,
            schema,
            app,
            cookie: format!("dream_app={token}"),
            user,
            mail,
            mail_server,
        }
    }
    async fn insert(&self, kind: &str, data: Value) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,$2,$3)")
            .bind(id)
            .bind(kind)
            .bind(data)
            .execute(&self.pool)
            .await
            .unwrap();
        id
    }
    async fn close(self) {
        self.mail_server.abort();
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
) -> (u16, HeaderMap, Value) {
    let mut request = Request::builder().method(method).uri(path);
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
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let value =
        serde_json::from_slice(&body).unwrap_or_else(|_| json!(String::from_utf8_lossy(&body)));
    (status, headers, value)
}

async fn post(
    app: &Router,
    path: &str,
    body: Value,
    origin: Option<&str>,
) -> (u16, HeaderMap, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}
fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
fn mail_token(f: &Fixture) -> String {
    let mail = f.mail.lock().unwrap();
    let link = mail.last().unwrap()["text"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .find(|word| word.starts_with("https://dummy.example.org/api/login/#token="))
        .unwrap();
    link.split_once("#token=").unwrap().1.to_owned()
}

#[tokio::test]
async fn custom_login_branding_is_text_and_cannot_inject_markup() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused@localhost/unused")
        .unwrap();
    let app = router(App {
        registry: std::sync::Arc::default(),
        pool: pool.clone(),
        name: "Dummy @@LOGO@@".into(),
        preview_origins: vec![],
        origin: "https://dummy.example.org".into(),
        mail_from: "no-reply@example.org".into(),
        mail_region: "eu-west-1".into(),
        mail_api_key: None,
        google_auth: None,
        mail_endpoint: None,
        revision: "test".into(),
        superusers: std::collections::BTreeSet::default(),
        operator_secret: None,
        branding: json!({"company_name":"<script>alert(1)</script>","logo_url":"javascript:alert(2)","primary_color":"red;}</style><script>alert(3)</script>","accent_color":"#abcdef"}),
    });
    let (status, headers, html) = call(&app, "GET", "/api/login/", None).await;
    assert_eq!(status, 200);
    let html = html.as_str().unwrap();
    assert!(html.contains("Dummy @@LOGO@@"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("javascript:alert"));
    assert!(!html.contains("alert(3)"));
    assert_eq!(html.matches("<script ").count(), 3);
    assert_eq!(html.matches("<script nonce=").count(), 3);
    assert!(html.contains("--primary:#000f14"));
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback mail transport"]
async fn magic_link_delivery_confirmation_replay_and_logout() {
    let f = Fixture::new().await;
    let (status, headers, html) = call(&f.app, "GET", "/api/login/", None).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    let html = html.as_str().unwrap();
    assert!(html.contains("Example Company"));
    assert!(html.contains("Confirm sign in"));
    assert!(html.contains("src=\"/branding.js\""));
    assert!(!html.contains("amazoncognito"));
    let email = "new-person@example.org";
    let (status, headers, reply) = post(
        &f.app,
        "/api/auth/magic-link",
        json!({"email":email}),
        Some("https://dummy.example.org"),
    )
    .await;
    assert_eq!(status, 202, "{reply}");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(!headers.contains_key("set-cookie"));
    assert!(reply.get("token").is_none());
    assert!(reply.get("url").is_none());
    let token = mail_token(&f);
    assert!(!reply.to_string().contains(&token));
    let (stored, stored_email, lifetime): (String, String, i64) = sqlx::query_as(
        "SELECT digest,email,extract(epoch FROM(expires-created))::bigint FROM app_magic_links",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(stored, digest(&token));
    assert_ne!(stored, token);
    assert_eq!(stored_email, email);
    assert_eq!(lifetime, 900);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_records WHERE kind='users'")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1,
        "requesting a link must not create a user"
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            &format!("/api/login/?token={token}&next=https://evil.example"),
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_magic_links")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1,
        "GET must never consume magic links"
    );
    assert_eq!(
        post(
            &f.app,
            "/api/auth/verify",
            json!({"token":token}),
            Some("https://evil.example")
        )
        .await
        .0,
        403
    );
    let (first, second) = tokio::join!(
        post(&f.app, "/api/auth/verify", json!({"token":token}), None),
        post(&f.app, "/api/auth/verify", json!({"token":token}), None)
    );
    assert!(matches!((first.0, second.0), (200, 401) | (401, 200)));
    let (_, headers, reply) = if first.0 == 200 { first } else { second };
    assert_eq!(reply, json!({"redirect":"https://dummy.example.org"}));
    let set_cookie = headers["set-cookie"].to_str().unwrap();
    for flag in [
        "Path=/api",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=43200",
    ] {
        assert!(set_cookie.contains(flag));
    }
    let cookie = set_cookie.split(';').next().unwrap();
    let (status, _, me) = call(&f.app, "GET", "/api/admin/users/me/", Some(cookie)).await;
    assert_eq!(status, 200);
    assert_eq!(me["user"]["email"], email);
    let id = me["user"]["id"].as_str().unwrap();
    for kind in ["identities", "identity_verifications"] {
        let (_, _, records) =
            call(&f.app, "GET", &format!("/api/admin/{kind}/"), Some(cookie)).await;
        assert_eq!(records[kind].as_array().unwrap().len(), 1);
        assert_eq!(records[kind][0]["user"], id);
    }
    let session = cookie.split_once('=').unwrap().1;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM(expires-now()))::bigint FROM app_sessions WHERE digest=$1",
    )
    .bind(digest(session))
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!((43190..=43200).contains(&remaining));
    assert_eq!(
        post(&f.app, "/api/auth/verify", json!({"token":token}), None)
            .await
            .0,
        401
    );
    let (status, headers, _) = call(&f.app, "GET", "/api/logout/", Some(cookie)).await;
    assert_eq!(status, 303);
    assert_eq!(headers["location"], "https://dummy.example.org/api/login/");
    // Signing out remembers a page on this app to return to, given as a path, an
    // absolute URL, or the login URL an admin wraps it in; never elsewhere or an API page.
    for (next, expected) in [
        (
            "/users/?page=2",
            "https://dummy.example.org/api/login/?next=%2Fusers%2F%3Fpage%3D2",
        ),
        (
            "https://dummy.example.org/orders/",
            "https://dummy.example.org/api/login/?next=%2Forders%2F",
        ),
        (
            "/api/login/?next=https%3A%2F%2Fdummy.example.org%2Froles%2F",
            "https://dummy.example.org/api/login/?next=%2Froles%2F",
        ),
        (
            "https://evil.example.org/users/",
            "https://dummy.example.org/api/login/",
        ),
        (
            "//evil.example.org/",
            "https://dummy.example.org/api/login/",
        ),
        ("/api/admin/users/", "https://dummy.example.org/api/login/"),
    ] {
        let (_, headers, _) = call(
            &f.app,
            "GET",
            &format!("/api/logout/?next={}", urlencoding(next)),
            None,
        )
        .await;
        assert_eq!(headers["location"].to_str().unwrap(), expected, "{next}");
    }
    assert!(
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        call(&f.app, "GET", "/api/admin/users/me/", Some(cookie))
            .await
            .0,
        401
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback mail transport"]
async fn magic_link_expiry_failure_and_existing_user() {
    let f = Fixture::new().await;
    for email in [
        "bad-address",
        "a@example.org\r\nBcc:leak@example.org",
        "a@@example.org",
    ] {
        assert_eq!(
            post(&f.app, "/api/auth/magic-link", json!({"email":email}), None)
                .await
                .0,
            400
        );
    }
    assert_eq!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"a@example.org"}),
            Some("https://evil.example")
        )
        .await
        .0,
        403
    );
    assert_eq!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"delivery-failure@example.org"}),
            None
        )
        .await
        .0,
        503
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_magic_links")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0,
        "failed delivery must revoke its token"
    );
    assert_eq!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"expired@example.org"}),
            None
        )
        .await
        .0,
        202
    );
    let token = mail_token(&f);
    // A requested return page rides in the emailed link, before the token.
    assert_eq!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"expired@example.org","next":"/orders/?state=draft"}),
            None
        )
        .await
        .0,
        202
    );
    let link = f.mail.lock().unwrap().last().unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        link.contains(
            "https://dummy.example.org/api/login/?next=%2Forders%2F%3Fstate%3Ddraft#token="
        ),
        "{link}"
    );
    assert_eq!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"expired@example.org","next":"https://evil.example.org/"}),
            None
        )
        .await
        .0,
        202
    );
    assert!(
        f.mail.lock().unwrap().last().unwrap()["text"]
            .as_str()
            .unwrap()
            .contains("https://dummy.example.org/api/login/#token=")
    );
    sqlx::query("UPDATE app_magic_links SET expires=now()-interval '1 second'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        post(&f.app, "/api/auth/verify", json!({"token":token}), None)
            .await
            .0,
        401
    );
    assert_eq!(
        post(&f.app, "/api/auth/verify", json!({"token":"invalid"}), None)
            .await
            .0,
        401
    );
    assert_eq!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":" VIEWER@EXAMPLE.ORG "}),
            None
        )
        .await
        .0,
        202
    );
    let token = mail_token(&f);
    let (status, headers, _) = post(&f.app, "/api/auth/verify", json!({"token":token}), None).await;
    assert_eq!(status, 200);
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(
        call(&f.app, "GET", "/api/admin/users/me/", Some(cookie))
            .await
            .2["user"]["id"],
        f.user.to_string()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_records WHERE kind='users'")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            "/api/auth/callback?code=unused&state=unused",
            None
        )
        .await
        .0,
        404
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback mail transport"]
async fn magic_link_rate_limits_hold_across_concurrent_requests() {
    let f = Fixture::new().await;
    let (a, b) = tokio::join!(
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"rate@example.org"}),
            None
        ),
        post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"RATE@example.org"}),
            None
        )
    );
    assert!(matches!((a.0, b.0), (202, 429) | (429, 202)));
    assert_eq!(f.mail.lock().unwrap().len(), 1);
    for (count, age, email_digest) in [
        (5, "2 minutes", digest("rate@example.org")),
        (30, "0 minutes", digest("other@example.org")),
        (200, "2 minutes", digest("other@example.org")),
    ] {
        sqlx::query("DELETE FROM app_magic_requests")
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO app_magic_requests(email_digest,created) SELECT $1,now()-$2::interval FROM generate_series(1,$3)").bind(email_digest).bind(age).bind(count).execute(&f.pool).await.unwrap();
        let (status, headers, _) = post(
            &f.app,
            "/api/auth/magic-link",
            json!({"email":"rate@example.org"}),
            None,
        )
        .await;
        assert_eq!(status, 429);
        assert_eq!(headers["retry-after"], "60");
    }
    assert_eq!(
        f.mail.lock().unwrap().len(),
        1,
        "throttled requests must not send mail"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn core_runtime_auth_metadata_and_read_only_routes() {
    let f = Fixture::new().await;
    for method in ["GET", "OPTIONS"] {
        for path in ["/api/admin/", "/api/admin/users/"] {
            assert_eq!(
                call(&f.app, method, path, None).await.0,
                401,
                "{method} {path}"
            );
            assert_eq!(
                call(&f.app, method, path, Some("dream_app=unknown"))
                    .await
                    .0,
                401
            );
        }
    }
    for path in ["/api/admin/users/me/", "/api/v0/s3/", "/api/admin/guides/"] {
        assert_eq!(call(&f.app, "GET", path, None).await.0, 401);
    }
    let (status, _, metadata) = call(&f.app, "OPTIONS", "/api/admin/", Some(&f.cookie)).await;
    assert_eq!(status, 200);
    assert_eq!(metadata["resources"].as_object().unwrap().len(), CORE.len());
    for kind in CORE {
        let schema = &metadata["resources"][kind];
        assert_eq!(schema["permissions"]["read"], true);
        for operation in ["create", "update", "delete"] {
            assert_eq!(schema["permissions"][operation], false);
        }
        for field in schema["fields"].as_object().unwrap().values() {
            assert_eq!(field["read_only"], true);
            assert_eq!(
                field["ui"], true,
                "The shared viewer requires explicit visible fields"
            );
            assert_eq!(field["hidden"], false);
            assert_eq!(
                field["deferred"], false,
                "The shared viewer filters deferred fields by boolean equality"
            );
        }
        assert!(!schema["sections"].as_array().unwrap().is_empty());
        // Only the resources people administer are listed in the navigation
        // drawer; the rest stay reachable but unlisted behind an empty section.
        assert_eq!(
            schema["section"],
            if matches!(
                kind,
                "identities" | "identity_verifications" | "dashboards" | "views"
            ) {
                ""
            } else {
                "Core"
            },
            "unexpected navigation section for {kind}"
        );
        assert_eq!(schema["permissions"]["fields"]["name"]["write"], false);
        assert_eq!(
            call(
                &f.app,
                "OPTIONS",
                &format!("/api/admin/{kind}/"),
                Some(&f.cookie)
            )
            .await
            .0,
            200
        );
        // Roles, dashboards and views can be created by people whose roles allow
        // it; this viewer's cannot. Every other built-in resource is read-only.
        assert_eq!(
            call(
                &f.app,
                "POST",
                &format!("/api/admin/{kind}/"),
                Some(&f.cookie)
            )
            .await
            .0,
            if matches!(kind, "roles" | "dashboards" | "views") {
                403
            } else {
                405
            }
        );
    }
    for (method, status) in [("PUT", 403), ("PATCH", 403), ("DELETE", 405)] {
        assert_eq!(
            call(
                &f.app,
                method,
                &format!("/api/admin/users/{}/", f.user),
                Some(&f.cookie)
            )
            .await
            .0,
            status
        );
    }
    for path in [
        "/admin/projects/",
        "/worker/claim",
        "/api/worker/claim",
        "/api/admin/projects/",
        "/api/admin/api_keys/",
        "/api/admin/app_sessions/",
        "/api/admin/app_logins/",
    ] {
        assert_eq!(
            call(&f.app, "GET", path, Some(&f.cookie)).await.0,
            404,
            "{path}"
        );
    }
    assert_eq!(
        call(&f.app, "GET", "/api/admin/users/me/", Some(&f.cookie))
            .await
            .2["user"]["id"],
        f.user.to_string()
    );
    sqlx::query("UPDATE app_sessions SET expires=now()-interval '1 second'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        call(&f.app, "GET", "/api/admin/users/me/", Some(&f.cookie))
            .await
            .0,
        401
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn core_runtime_lists_filter_projection_counts_and_resource_boundaries() {
    let f = Fixture::new().await;
    let a = f
        .insert("roles", json!({"name":"Alpha","permissions":{"read":true}}))
        .await;
    let b = f
        .insert("roles", json!({"name":"Beta","permissions":{"read":true}}))
        .await;
    // The generic admin includes the ID on every request. Includes add fields;
    // they only form an exclusive projection alongside exclude[]=*.
    let (status, _, default_rows) = call(
        &f.app,
        "GET",
        "/api/admin/users/?include[]=id&exclude_links=1",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(default_rows["users"][0]["name"], "Viewer");
    assert_eq!(default_rows["users"][0]["email"], "viewer@example.org");
    let (_, _, excluded) = call(
        &f.app,
        "GET",
        "/api/admin/users/?include[]=id&exclude[]=email",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(excluded["users"][0]["name"], "Viewer");
    assert!(excluded["users"][0].get("email").is_none());
    let (_, _, detail) = call(
        &f.app,
        "GET",
        &format!("/api/admin/users/{}/?include[]=id", f.user),
        Some(&f.cookie),
    )
    .await;
    assert_eq!(detail["user"]["email"], "viewer@example.org");
    let (_, _, detail_projection) = call(
        &f.app,
        "GET",
        &format!("/api/admin/users/{}/?include[]=name&exclude[]=*", f.user),
        Some(&f.cookie),
    )
    .await;
    assert_eq!(
        detail_projection["user"],
        json!({"id":f.user,"name":"Viewer"})
    );
    f.insert("roles", json!({"name":"Percent%_Literal"})).await;
    f.insert(
        "providers",
        json!({"name":"Not a role","kind":"cognito","enabled":true}),
    )
    .await;
    let (status, _, page) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?sort[]=name&per_page=1&page=2",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["roles"][0]["id"], b.to_string());
    assert_eq!(page["meta"]["total_results"], 3);
    assert_eq!(page["meta"]["total_pages"], 3);
    let (_, _, filtered) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?filter{name.in}[]=Alpha&filter{name.in}[]=Beta&sort[]=-name",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(filtered["meta"]["total_results"], 2);
    assert_eq!(filtered["roles"][0]["id"], b.to_string());
    let (_, _, literal) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?filter{name.icontains}=%25_",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(
        literal["meta"]["total_results"], 1,
        "wildcards must be literal: {literal}"
    );
    // The admin UI's default list query asks for rows whose id is present.
    let (status, _, present) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?filter{id.isnull}=0",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(status, 200, "{present}");
    assert_eq!(
        present["meta"]["total_results"],
        page["meta"]["total_results"]
    );
    let (_, _, absent) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?filter{id.isnull}=true",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(absent["meta"]["total_results"], 0);
    assert_eq!(
        call(
            &f.app,
            "GET",
            "/api/admin/roles/?filter{id.isnull}=maybe",
            Some(&f.cookie)
        )
        .await
        .0,
        400
    );
    let (_, _, projection) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?include[]=name&exclude[]=*&sort[]=name",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(projection["roles"][0], json!({"id":a,"name":"Alpha"}));
    let (_, _, empty) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?per_page=1&page=999",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(empty["roles"], json!([]));
    assert_eq!(empty["meta"]["total_results"], 3);
    let (status, _, one) = call(
        &f.app,
        "GET",
        &format!("/api/admin/roles/{a}/"),
        Some(&f.cookie),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(one["role"]["name"], "Alpha");
    assert_eq!(
        call(
            &f.app,
            "GET",
            &format!("/api/admin/providers/{a}/"),
            Some(&f.cookie)
        )
        .await
        .0,
        404
    );
    for query in [
        "filter{unknown}=x",
        "sort[]=unknown",
        "filter{name.gt}=a",
        "filter{name*}=email",
    ] {
        assert_eq!(
            call(
                &f.app,
                "GET",
                &format!("/api/admin/roles/?{query}"),
                Some(&f.cookie)
            )
            .await
            .0,
            400,
            "{query}"
        );
    }
    let (status, _, injection) = call(
        &f.app,
        "GET",
        "/api/admin/roles/?filter{name}=%27%20OR%201%3D1--",
        Some(&f.cookie),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(injection["meta"]["total_results"], 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn core_runtime_only_exposes_public_core_fields() {
    let f = Fixture::new().await;
    let id=f.insert("providers",json!({"name":"Sign in","kind":"cognito","enabled":true,"secret":"must-not-leak","credentials":{"access_key":"must-not-leak"},"ciphertext":"must-not-leak"})).await;
    sqlx::query("UPDATE app_records SET data=data || '{\"password_digest\":\"must-not-leak\"}'::jsonb WHERE id=$1").bind(f.user).execute(&f.pool).await.unwrap();
    for path in [
        "/api/admin/providers/".into(),
        format!("/api/admin/providers/{id}/"),
        "/api/admin/users/".into(),
        format!("/api/admin/users/{}/", f.user),
        "/api/admin/users/me/".into(),
    ] {
        let (status, _, body) = call(&f.app, "GET", &path, Some(&f.cookie)).await;
        assert_eq!(status, 200);
        assert!(
            !body.to_string().contains("must-not-leak"),
            "non-public fields exposed at {path}: {body}"
        );
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn preview_handoffs_are_origin_checked_expiring_one_use_and_partitioned() {
    let fixture = Fixture::with_preview(true).await;
    // The bridge script names the preview origins it may report navigation to, and nothing else.
    let (status, _, script) = call(&fixture.app, "GET", "/api/preview/script.js", None).await;
    assert_eq!(status, 200);
    let script = script.as_str().unwrap_or_default().to_owned();
    assert!(
        script.contains("const previewOrigins = [\"https://dreamy.example.com\"];"),
        "{script}"
    );
    assert!(script.contains("dream-preview-location"));
    let plain = Fixture::new().await;
    let (_, _, unembedded) = call(&plain.app, "GET", "/api/preview/script.js", None).await;
    assert!(
        unembedded
            .as_str()
            .unwrap_or_default()
            .contains("const previewOrigins = [];")
    );
    plain.close().await;
    // The sign-in page and the return shell inline the same script, substituted the same way.
    let (_, _, login) = call(&fixture.app, "GET", "/api/login/", None).await;
    let login = login.as_str().unwrap_or_default().to_owned();
    assert!(login.contains("const previewOrigins = [\"https://dreamy.example.com\"];"));
    assert!(!login.contains("__DREAM_PREVIEW_ORIGINS__"));
    let (_, _, shell) = call(&fixture.app, "GET", "/api/preview/finish", None).await;
    assert!(
        shell
            .as_str()
            .unwrap_or_default()
            .contains("const previewOrigins = [];")
    );
    let origin = "https://dummy.example.org";
    let nonce = "a".repeat(64);
    let (status, headers, _) = call(&fixture.app, "GET", "/api/login/", None).await;
    assert_eq!(status, 200);
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors https://dreamy.example.com")
    );
    let (_, headers, _) = call(&fixture.app, "GET", "/api/preview/auth", None).await;
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(
        post(
            &fixture.app,
            "/api/preview/issue",
            json!({"nonce":nonce}),
            Some(origin)
        )
        .await
        .0,
        401
    );
    let issue = || {
        let app = fixture.app.clone();
        let cookie = fixture.cookie.clone();
        let nonce = nonce.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/preview/issue")
                        .header("origin", origin)
                        .header("cookie", cookie)
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"nonce":nonce}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 10000).await.unwrap())
                    .unwrap();
            value["code"].as_str().unwrap().to_owned()
        }
    };
    let code = issue().await;
    let body = json!({"nonce":nonce,"code":code});
    assert_eq!(
        post(
            &fixture.app,
            "/api/preview/redeem",
            body.clone(),
            Some("https://attacker.example")
        )
        .await
        .0,
        403
    );
    assert_eq!(
        post(
            &fixture.app,
            "/api/preview/redeem",
            json!({"nonce":"b".repeat(64),"code":code}),
            Some(origin)
        )
        .await
        .0,
        401
    );
    let (status, headers, _) = post(
        &fixture.app,
        "/api/preview/redeem",
        body.clone(),
        Some(origin),
    )
    .await;
    assert_eq!(status, 200);
    let session = headers["set-cookie"].to_str().unwrap();
    assert!(session.contains("HttpOnly; Secure; SameSite=None; Partitioned"));
    let cookie = session.split(';').next().unwrap();
    assert_eq!(
        call(&fixture.app, "GET", "/api/admin/users/me/", Some(cookie))
            .await
            .0,
        200
    );
    assert_eq!(
        post(&fixture.app, "/api/preview/redeem", body, Some(origin))
            .await
            .0,
        401
    );
    let code = issue().await;
    sqlx::query("UPDATE app_preview_codes SET expires=now()-interval '1 second'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        post(
            &fixture.app,
            "/api/preview/redeem",
            json!({"nonce":nonce,"code":code}),
            Some(origin)
        )
        .await
        .0,
        401
    );
    let (_, headers, _) = call(&fixture.app, "GET", "/api/logout/", Some(cookie)).await;
    assert!(
        headers
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("dream_preview=;"))
    );
    assert_eq!(
        call(&fixture.app, "GET", "/api/admin/users/me/", Some(cookie))
            .await
            .0,
        401
    );
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn operator_grants_open_sessions_for_named_users_only_when_valid() {
    use dynamic_rust::application::operator::{GRANT_SECONDS, sign};
    let secret = "operator-secret-for-tests-0123456789abcdef";
    let f = Fixture::configure(false, Some(secret)).await;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let expires = now + 60;
    // Wrong signature, wrong email for the signature, expired, and too far ahead are all rejected.
    for grant in [
        json!({"email":"owner@example.org","expires":expires,"signature":"0".repeat(64)}),
        json!({"email":"other@example.org","expires":expires,"signature":sign(secret,"owner@example.org",expires)}),
        json!({"email":"owner@example.org","expires":now-1,"signature":sign(secret,"owner@example.org",now-1)}),
        json!({"email":"owner@example.org","expires":now+GRANT_SECONDS+60,"signature":sign(secret,"owner@example.org",now+GRANT_SECONDS+60)}),
    ] {
        assert_eq!(
            post(&f.app, "/api/operator/session", grant, None).await.0,
            401
        );
    }
    let (status, _, session) = post(
        &f.app,
        "/api/operator/session",
        json!({"email":"Owner@Example.org","expires":expires,"signature":sign(secret,"owner@example.org",expires)}),
        None,
    )
    .await;
    assert_eq!(status, 200, "{session}");
    assert_eq!(session["superuser"], true);
    let cookie = format!("dream_app={}", session["token"].as_str().unwrap());
    let (status, _, me) = call(&f.app, "GET", "/api/admin/users/me/", Some(&cookie)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["user"]["email"], "owner@example.org");
    // A superuser signing in holds the managed Admin role, so their own record
    // shows the access the platform guarantees them; anyone else holds nothing.
    let (_, _, roles) = call(&f.app, "GET", "/api/admin/roles/", Some(&cookie)).await;
    let admin = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Admin")
        .expect("managed Admin role")["id"]
        .clone();
    assert_eq!(me["user"]["roles"], json!([admin]));
    let (_, _, metadata) = call(&f.app, "OPTIONS", "/api/admin/", Some(&cookie)).await;
    assert_eq!(
        metadata["resources"]["dashboards"]["permissions"]["create"],
        true
    );
    assert_eq!(
        metadata["resources"]["views"]["permissions"]["update"],
        true
    );
    assert_eq!(
        metadata["resources"]["roles"]["fields"]["permissions"]["resources"]["views"]["conditional"],
        false
    );
    // A second grant reuses the same user record rather than creating another.
    let (_, _, again) = post(
        &f.app,
        "/api/operator/session",
        json!({"email":"owner@example.org","expires":expires,"signature":sign(secret,"owner@example.org",expires)}),
        None,
    )
    .await;
    assert_eq!(again["user"], session["user"]);
    // Without a configured secret the endpoint is unauthenticated for everyone.
    let plain = Fixture::new().await;
    assert_eq!(
        post(&plain.app, "/api/operator/session", json!({"email":"owner@example.org","expires":expires,"signature":sign(secret,"owner@example.org",expires)}), None).await.0,
        401
    );
    plain.close().await;
    f.close().await;
}
