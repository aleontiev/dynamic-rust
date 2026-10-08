#![allow(clippy::too_many_lines)]
#![cfg(feature = "application")]
//! File fields: uploads people make become files records keep, readable by
//! whoever may read the record and see the field. Without a bucket they are
//! `PostgreSQL` large objects in the app's own database; with one, objects in
//! it, which people upload to and read from through signed links.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request},
};
use dynamic_rust::{
    FieldKind,
    application::{
        App,
        extensions::{Actor, Context, Model, Registry, lock},
        files::{Bucket, Store, use_store},
        router, task_runner,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Body,
    json_body: bool,
) -> (u16, Vec<u8>, HeaderMap) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie);
    if json_body {
        builder = builder.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    (
        status,
        to_bytes(response.into_body(), 50_000_000)
            .await
            .unwrap()
            .to_vec(),
        headers,
    )
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (u16, Value) {
    let (status, bytes, _) = call(
        app,
        method,
        path,
        cookie,
        Body::from(body.to_string()),
        true,
    )
    .await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn registry() -> Registry {
    let mut registry = Registry::default();
    registry
        .model(
            Model::new("receipts", "receipt")
                .field("name", FieldKind::String)
                .file("scan")
                .label("scan", "Scan")
                .describe("scan", "The receipt as photographed or scanned.")
                .field("archive", FieldKind::File)
                .readonly("archive")
                .grant("clerk", &["list", "read", "create", "update", "delete"]),
        )
        .unwrap();
    registry
        .model(
            Model::new("notes", "note")
                .field("name", FieldKind::String)
                .grant("clerk", &["list", "read"]),
        )
        .unwrap();
    registry
}

async fn isolated(prefix: &str) -> (PgPool, Router, App) {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
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
        .unwrap();
    let registry = registry();
    registry.migrate(&pool).await.unwrap();
    let mut roles = std::collections::BTreeMap::new();
    for name in ["Clerk", "Viewer"] {
        let id = Uuid::new_v4();
        let permissions = if name == "Clerk" {
            json!({"receipts":{"list":true,"read":true,"create":true,"update":true,"delete":true}})
        } else {
            json!({"receipts":{"list":true,"read":true,"fields":{"scan":{"write_only":true}}}})
        };
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'roles',$2)")
            .bind(id)
            .bind(json!({"name":name,"permissions":permissions}))
            .execute(&pool)
            .await
            .unwrap();
        roles.insert(name, id);
    }
    for (name, held) in [
        ("owner", json!([])),
        ("clerk", json!([roles["Clerk"]])),
        ("other", json!([roles["Clerk"]])),
        ("viewer", json!([roles["Viewer"]])),
        ("stranger", json!([])),
    ] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":name,"email":format!("{name}@example.com"),"data":{"roles":held}}))
            .execute(&pool)
            .await
            .unwrap();
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
        name: "Receipts".into(),
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
    (pool, router(state.clone()), state)
}

// Which store files go to is the process's; the tests here take turns.
static STORE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn objects(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_largeobject_metadata")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn without_a_bucket_files_are_large_objects_people_upload_read_and_replace() {
    let _turn = STORE.lock().await;
    use_store(Store::Postgres);
    let (pool, app, state) = isolated("files_pg").await;
    let (clerk, other, viewer, stranger) = (
        "dream_app=clerk-token",
        "dream_app=other-token",
        "dream_app=viewer-token",
        "dream_app=stranger-token",
    );
    let begin = |cookie: &'static str, body: Value| {
        let app = app.clone();
        async move { request(&app, "POST", "/api/admin/files/", cookie, body).await }
    };
    let pdf = b"%PDF-1.4 receipt".to_vec();
    let slot = json!({"model":"receipts","field":"scan","name":"../receipt one.pdf","size":pdf.len(),"content_type":"application/pdf"});

    // Only someone who may write the model and the field may start an upload.
    assert_eq!(begin(stranger, slot.clone()).await.0, 403);
    assert_eq!(begin(viewer, slot.clone()).await.0, 403);
    for (body, field) in [
        (
            json!({"model":"notes","field":"name","name":"a","size":1}),
            "field",
        ),
        (
            json!({"model":"receipts","field":"name","name":"a","size":1}),
            "field",
        ),
        (
            json!({"model":"receipts","field":"scan","name":"a","size":0}),
            "size",
        ),
        (
            json!({"model":"receipts","field":"scan","name":"a","size":20_000_000}),
            "size",
        ),
        (
            json!({"model":"receipts","field":"scan","name":" ","size":3}),
            "name",
        ),
        (
            json!({"model":"nothing","field":"scan","name":"a","size":3}),
            "model",
        ),
    ] {
        let (status, answer) = begin(clerk, body.clone()).await;
        assert_eq!(status, 400, "{body} {answer}");
        assert!(answer["detail"].get(field).is_some(), "{answer}");
    }
    assert_eq!(
        begin(
            clerk,
            json!({"model":"receipts","field":"archive","name":"a","size":3})
        )
        .await
        .0,
        403,
        "a read-only field takes no upload"
    );

    let (status, started) = begin(clerk, slot.clone()).await;
    assert_eq!(status, 201, "{started}");
    let upload = started["upload"].clone();
    assert_eq!(upload["method"], "PUT");
    let id = upload["id"].as_str().unwrap().to_owned();
    assert_eq!(
        upload["url"],
        format!("https://example.com/api/admin/files/{id}/")
    );
    let put_path = format!("/api/admin/files/{id}/");
    // The bytes go to the upload that is theirs, at the size given.
    assert_eq!(
        call(
            &app,
            "PUT",
            &put_path,
            other,
            Body::from(pdf.clone()),
            false
        )
        .await
        .0,
        404
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &put_path,
            clerk,
            Body::from(b"short".to_vec()),
            false
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &put_path,
            clerk,
            Body::from(pdf.clone()),
            false
        )
        .await
        .0,
        204
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &put_path,
            clerk,
            Body::from(pdf.clone()),
            false
        )
        .await
        .0,
        409,
        "once only"
    );

    // Someone else cannot attach it; its maker can.
    let (status, body) = request(
        &app,
        "POST",
        "/api/admin/receipts/",
        other,
        json!({"name":"Fuel","scan":{"upload":id}}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (status, created) = request(
        &app,
        "POST",
        "/api/admin/receipts/",
        clerk,
        json!({"name":"Fuel","scan":{"upload":id}}),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let receipt = created["receipt"].clone();
    let rid = receipt["id"].as_str().unwrap().to_owned();
    let url = format!("/api/admin/receipts/{rid}/files/scan/");
    assert_eq!(
        receipt["scan"]["name"], "receipt one.pdf",
        "the name is kept without its path"
    );
    assert_eq!(receipt["scan"]["size"], pdf.len());
    assert_eq!(receipt["scan"]["content_type"], "application/pdf");
    assert_eq!(receipt["scan"]["url"], url);
    assert!(
        receipt["scan"].get("oid").is_none() && receipt["scan"].get("store").is_none(),
        "where it is stays private"
    );
    let stored: Value =
        sqlx::query_scalar("SELECT data->'scan' FROM app_records WHERE id=$1::uuid")
            .bind(&rid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored["store"], "postgres");
    // An attached upload is used up.
    let (status, _) = request(
        &app,
        "POST",
        "/api/admin/receipts/",
        clerk,
        json!({"name":"Again","scan":{"upload":id}}),
    )
    .await;
    assert_eq!(status, 400);

    // Whoever may read the record and see the field gets the bytes.
    let (status, bytes, headers) = call(&app, "GET", &url, clerk, Body::empty(), false).await;
    assert_eq!(status, 200);
    assert_eq!(bytes, pdf);
    assert_eq!(headers["content-type"], "application/pdf");
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename*=UTF-8''receipt%20one.pdf"
    );
    let (_, listed) = request(
        &app,
        "GET",
        &format!("/api/admin/receipts/{rid}/"),
        viewer,
        Value::Null,
    )
    .await;
    assert!(
        listed["receipt"].get("scan").is_none(),
        "the viewer's role hides the scan: {listed}"
    );
    assert_eq!(
        call(&app, "GET", &url, viewer, Body::empty(), false)
            .await
            .0,
        404
    );
    assert_eq!(
        call(&app, "GET", &url, stranger, Body::empty(), false)
            .await
            .0,
        403
    );

    // Sending back what was read keeps the file; replacing it lets the old one go.
    let (status, kept) = request(
        &app,
        "PATCH",
        &format!("/api/admin/receipts/{rid}/"),
        clerk,
        json!({"name":"Fuel, May","scan":receipt["scan"]}),
    )
    .await;
    assert_eq!(status, 200, "{kept}");
    assert_eq!(kept["receipt"]["scan"], receipt["scan"]);
    let before = objects(&pool).await;
    let second = b"%PDF-1.4 second".to_vec();
    let (_, started) = begin(clerk, json!({"model":"receipts","field":"scan","name":"second.pdf","size":second.len(),"content_type":"application/pdf"})).await;
    let id2 = started["upload"]["id"].as_str().unwrap().to_owned();
    call(
        &app,
        "PUT",
        &format!("/api/admin/files/{id2}/"),
        clerk,
        Body::from(second.clone()),
        false,
    )
    .await;
    let (status, replaced) = request(
        &app,
        "PATCH",
        &format!("/api/admin/receipts/{rid}/"),
        clerk,
        json!({"scan":{"upload":id2}}),
    )
    .await;
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(replaced["receipt"]["scan"]["name"], "second.pdf");
    assert_eq!(
        objects(&pool).await,
        before,
        "the new file in, the old one out"
    );
    assert_eq!(
        call(&app, "GET", &url, clerk, Body::empty(), false).await.1,
        second
    );

    // Code stores files it makes, and deleting the record lets them go.
    let mut tx = pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    let mut context = Context::new(&mut tx, &state.registry, Actor::system());
    let made = context
        .put_file("export.csv", "text/csv", b"a,b\n1,2\n".to_vec())
        .await
        .unwrap();
    context
        .elevated()
        .update(
            "receipts",
            Uuid::parse_str(&rid).unwrap(),
            json!({"archive": made}),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (_, bytes, headers) = call(
        &app,
        "GET",
        &format!("/api/admin/receipts/{rid}/files/archive/"),
        clerk,
        Body::empty(),
        false,
    )
    .await;
    assert_eq!(bytes, b"a,b\n1,2\n");
    assert_eq!(headers["content-type"], "text/csv");
    // People cannot point a field at a stored file themselves.
    let (_, forged) = request(
        &app,
        "PATCH",
        &format!("/api/admin/receipts/{rid}/"),
        clerk,
        json!({"scan":{"store":"postgres","oid":1,"name":"x","size":1}}),
    )
    .await;
    assert_eq!(
        forged["receipt"]["scan"]["name"], "second.pdf",
        "a forged value keeps the file: {forged}"
    );
    let before = objects(&pool).await;
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/receipts/{rid}/"),
            clerk,
            Value::Null
        )
        .await
        .0,
        204
    );
    assert_eq!(
        objects(&pool).await,
        before - 2,
        "both files went with the record"
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and an S3-compatible bucket"]
async fn with_a_bucket_files_go_straight_to_it_and_are_read_through_signed_links() {
    let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let Some(endpoint) = var("DREAM_TEST_S3_ENDPOINT") else {
        eprintln!(
            "skipped: set DREAM_TEST_S3_ENDPOINT, DREAM_TEST_S3_BUCKET, DREAM_TEST_S3_ACCESS_KEY and DREAM_TEST_S3_SECRET_KEY"
        );
        return;
    };
    let _turn = STORE.lock().await;
    let bucket = Bucket {
        endpoint: endpoint.trim_end_matches('/').into(),
        region: "us-east-1".into(),
        bucket: var("DREAM_TEST_S3_BUCKET").unwrap(),
        prefix: format!("apps/{}/dev/", Uuid::new_v4()),
        access_key: var("DREAM_TEST_S3_ACCESS_KEY").unwrap(),
        secret_key: var("DREAM_TEST_S3_SECRET_KEY").unwrap(),
        session_token: None,
        path_style: true,
    };
    assert!(
        !format!("{bucket:?}").contains(&bucket.secret_key),
        "the key stays out of logs"
    );
    use_store(Store::Bucket(bucket.clone()));
    let (pool, app, state) = isolated("files_s3").await;
    let (clerk, viewer, stranger) = (
        "dream_app=clerk-token",
        "dream_app=viewer-token",
        "dream_app=stranger-token",
    );
    let http = reqwest::Client::new();
    let tasks = || {
        let state = state.clone();
        async move {
            task_runner::drain(&state, std::time::Duration::from_secs(30))
                .await
                .unwrap()
        }
    };
    let upload = |name: &'static str, bytes: Vec<u8>, size: usize| {
        let (app, http) = (app.clone(), http.clone());
        async move {
            let (status, started) = request(&app, "POST", "/api/admin/files/", clerk, json!({"model":"receipts","field":"scan","name":name,"size":size,"content_type":"application/pdf"})).await;
            assert_eq!(status, 201, "{started}");
            let upload = started["upload"].clone();
            let mut put = http.put(upload["url"].as_str().unwrap()).body(bytes);
            for (header, value) in upload["headers"].as_object().unwrap() {
                put = put.header(header, value.as_str().unwrap());
            }
            let response = put.send().await.unwrap();
            assert!(
                response.status().is_success(),
                "the bucket takes the bytes: {}",
                response.text().await.unwrap()
            );
            upload
        }
    };
    let pdf = b"%PDF-1.4 bucket receipt".to_vec();

    // The bytes go straight to the bucket, to a pending place under the app's prefix.
    let first = upload("receipt.pdf", pdf.clone(), pdf.len()).await;
    let id = first["id"].as_str().unwrap().to_owned();
    let pending = format!("{}pending/{id}", bucket.prefix);
    assert!(
        first["url"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}/{}/{pending}?", bucket.endpoint, bucket.bucket))
    );
    assert_eq!(bucket.head(&pending).await.unwrap(), Some(pdf.len() as u64));
    // Only with the signature: the bucket refuses the address without it.
    let bare = http
        .get(format!("{}/{}/{pending}", bucket.endpoint, bucket.bucket))
        .send()
        .await
        .unwrap();
    assert_eq!(bare.status().as_u16(), 403);

    // A file that is not the size it was announced as is not attached.
    let short = upload("short.pdf", b"short".to_vec(), 50).await;
    let (status, body) = request(
        &app,
        "POST",
        "/api/admin/receipts/",
        clerk,
        json!({"name":"Short","scan":{"upload":short["id"]}}),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // Attaching moves it to where the record keeps it.
    let (status, created) = request(
        &app,
        "POST",
        "/api/admin/receipts/",
        clerk,
        json!({"name":"Fuel","scan":{"upload":id}}),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let rid = created["receipt"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created["receipt"]["scan"]["name"], "receipt.pdf");
    let stored: Value =
        sqlx::query_scalar("SELECT data->'scan' FROM app_records WHERE id=$1::uuid")
            .bind(&rid)
            .fetch_one(&pool)
            .await
            .unwrap();
    let key = stored["key"].as_str().unwrap().to_owned();
    assert_eq!(stored["store"], "bucket");
    assert_eq!(
        key,
        format!("{}files/receipts/{rid}/scan/{id}", bucket.prefix)
    );
    assert_eq!(bucket.head(&key).await.unwrap(), Some(pdf.len() as u64));
    assert_eq!(
        bucket.head(&pending).await.unwrap(),
        None,
        "nothing is left pending"
    );

    // Reading it sends people to a short-lived signed link with the file's name.
    let url = format!("/api/admin/receipts/{rid}/files/scan/");
    let (status, _, headers) = call(&app, "GET", &url, clerk, Body::empty(), false).await;
    assert_eq!(status, 302);
    assert_eq!(headers["cache-control"], "no-store");
    let signed = headers["location"].to_str().unwrap().to_owned();
    assert!(signed.contains("X-Amz-Expires="), "{signed}");
    let fetched = http.get(&signed).send().await.unwrap();
    assert_eq!(fetched.status().as_u16(), 200);
    assert_eq!(fetched.headers()["content-type"], "application/pdf");
    assert_eq!(
        fetched.headers()["content-disposition"],
        "attachment; filename*=UTF-8''receipt.pdf"
    );
    assert_eq!(fetched.bytes().await.unwrap().to_vec(), pdf);
    assert_eq!(
        call(&app, "GET", &url, viewer, Body::empty(), false)
            .await
            .0,
        404
    );
    assert_eq!(
        call(&app, "GET", &url, stranger, Body::empty(), false)
            .await
            .0,
        403
    );

    // Replacing the file lets the old object go once the change commits.
    let second = upload("second.pdf", b"%PDF second".to_vec(), 11).await;
    let (status, replaced) = request(
        &app,
        "PATCH",
        &format!("/api/admin/receipts/{rid}/"),
        clerk,
        json!({"scan":{"upload":second["id"]}}),
    )
    .await;
    assert_eq!(status, 200, "{replaced}");
    assert!(tasks().await >= 1);
    assert_eq!(bucket.head(&key).await.unwrap(), None);

    // Code stores the files it makes in the bucket too.
    let mut tx = pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    let mut context = Context::new(&mut tx, &state.registry, Actor::system());
    let made = context
        .put_file("export.csv", "text/csv", b"a,b\n".to_vec())
        .await
        .unwrap();
    context
        .elevated()
        .update(
            "receipts",
            Uuid::parse_str(&rid).unwrap(),
            json!({"archive": made}),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let stored: Value = sqlx::query_scalar("SELECT data FROM app_records WHERE id=$1::uuid")
        .bind(&rid)
        .fetch_one(&pool)
        .await
        .unwrap();
    let (scan, archive) = (
        stored["scan"]["key"].as_str().unwrap().to_owned(),
        stored["archive"]["key"].as_str().unwrap().to_owned(),
    );
    assert_eq!(bucket.head(&archive).await.unwrap(), Some(4));

    // Deleting the record lets both go.
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/receipts/{rid}/"),
            clerk,
            Value::Null
        )
        .await
        .0,
        204
    );
    tasks().await;
    assert_eq!(bucket.head(&scan).await.unwrap(), None);
    assert_eq!(bucket.head(&archive).await.unwrap(), None);

    // What was put in the bucket for an upload nobody attached goes when it expires.
    let forgotten = upload("forgotten.pdf", pdf.clone(), pdf.len()).await;
    let forgotten = format!(
        "{}pending/{}",
        bucket.prefix,
        forgotten["id"].as_str().unwrap()
    );
    sqlx::query("UPDATE app_uploads SET expires=now()-interval '1 minute' WHERE state<>'attached'")
        .execute(&pool)
        .await
        .unwrap();
    upload("next.pdf", pdf.clone(), pdf.len()).await;
    tasks().await;
    assert_eq!(bucket.head(&forgotten).await.unwrap(), None);
}
