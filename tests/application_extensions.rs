#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::similar_names
)]
#![cfg(feature = "application")]
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use dynamic_rust::{
    ApiError, FieldKind, PermissionFilter,
    application::{
        App,
        extensions::{Actor, Context, Handler, Hook, Model, Registry, handler},
        router, task_runner,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct OrderHook;
#[handler]
impl Hook for OrderHook {
    async fn before(
        &self,
        _: &mut Context<'_>,
        operation: &str,
        previous: Option<&Value>,
        record: &mut Value,
    ) -> Result<(), ApiError> {
        if operation == "create" {
            record["state"] = json!("draft");
            record["received"] = json!(0);
        }
        if record["quantity"].as_i64().unwrap_or(0) <= 0 {
            return Err(ApiError::Parse("Quantity must be positive".into()));
        }
        if operation == "delete" && previous.is_some_and(|p| p["state"] != "draft") {
            return Err(ApiError::Conflict(
                "Only draft orders can be deleted".into(),
            ));
        }
        Ok(())
    }
}
struct Approve;
#[handler]
impl Handler for Approve {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        let id = Uuid::parse_str(input["id"].as_str().unwrap()).unwrap();
        let order = ctx.get("orders", id).await?;
        if order["state"] != "draft" {
            return Err(ApiError::Conflict("Order already submitted".into()));
        }
        ctx.update("orders", id, json!({"state":"approved"})).await
    }
}
struct Receive;
#[handler]
impl Handler for Receive {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        let id = Uuid::parse_str(input["id"].as_str().unwrap()).unwrap();
        let order = ctx.get("orders", id).await?;
        if order["state"] != "approved" {
            return Err(ApiError::Conflict("Order must be approved".into()));
        }
        let qty = input["data"]["quantity"].as_i64().unwrap_or(0);
        let received = order["received"].as_i64().unwrap() + qty;
        if qty <= 0 || received > order["quantity"].as_i64().unwrap() {
            return Err(ApiError::Parse("Over receipt".into()));
        }
        ctx.create(
            "receipts",
            json!({"name":input["data"]["reference"],"order":id,"quantity":qty}),
        )
        .await?;
        ctx.update("orders", id, json!({"received":received}))
            .await?;
        ctx.enqueue(
            "receipt_recorded",
            input["data"]["reference"].as_str().unwrap(),
            json!({"order":id}),
        )
        .await?;
        if input["data"]["fail"] == true {
            return Err(ApiError::Conflict("Rollback requested".into()));
        }
        ctx.get("orders", id).await
    }
}
struct ReceiptTask;
#[handler]
impl Handler for ReceiptTask {
    async fn run(&self, ctx: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        ctx.create("events", json!({"name":input["idempotency_key"]}))
            .await
    }
}
fn registry() -> Registry {
    let mut registry = Registry::default();
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
                .required("name")
                .relation("supplier", "suppliers")
                .required("supplier")
                .field("quantity", FieldKind::Integer)
                .required("quantity")
                .field("received", FieldKind::Integer)
                .field("state", FieldKind::String)
                .grant("buyer", &all)
                .grant("viewer", &["list", "read"])
                .hook(OrderHook),
        )
        .unwrap();
    registry
        .model(
            Model::new("receipts", "receipt")
                .field("name", FieldKind::String)
                .required("name")
                .relation("order", "orders")
                .required("order")
                .field("quantity", FieldKind::Integer)
                .required("quantity")
                .unique(&["name"])
                .grant("buyer", &all),
        )
        .unwrap();
    registry
        .model(
            Model::new("events", "event")
                .field("name", FieldKind::String)
                .unique(&["name"])
                .grant("buyer", &all),
        )
        .unwrap();
    let mut notes = Model::new("notes", "note")
        .field("name", FieldKind::String)
        .field("owner", FieldKind::Uuid)
        .required("owner")
        .grant("buyer", &all);
    notes.resource.role_filters.insert(
        "buyer".into(),
        all.iter()
            .map(|op| {
                (
                    (*op).into(),
                    PermissionFilter::Condition {
                        lookup: "owner".into(),
                        value: json!("$user.id"),
                    },
                )
            })
            .collect(),
    );
    registry.model(notes).unwrap();
    registry
        .action("orders", "approve", &["buyer"], Approve)
        .unwrap();
    registry
        .action("orders", "receive", &["buyer"], Receive)
        .unwrap();
    registry.task("receipt_recorded", ReceiptTask).unwrap();
    registry
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (u16, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
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
#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn custom_models_actions_hooks_permissions_tasks_and_persistence() {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("extensions_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
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
    let registry = registry();
    registry.migrate(&pool).await.unwrap();
    registry.migrate(&pool).await.unwrap();
    let buyer = Uuid::new_v4();
    let viewer = Uuid::new_v4();
    for (id, role, token) in [
        (buyer, "buyer", "buyer-token"),
        (viewer, "viewer", "viewer-token"),
    ] {
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(
                json!({"name":role,"email":format!("{role}@example.com"),"data":{"roles":[role]}}),
            )
            .execute(&pool)
            .await
            .unwrap();
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
        sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '1 hour')").bind(digest).bind(id).execute(&pool).await.unwrap();
    }
    let appstate = App {
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
    };
    let app = router(appstate.clone());
    let buyer_cookie = "dream_app=buyer-token";
    let viewer_cookie = "dream_app=viewer-token";
    let (status, meta) = request(&app, "OPTIONS", "/api/admin/", buyer_cookie, Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(meta["resources"]["orders"]["permissions"]["create"], true);
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", viewer_cookie, Value::Null).await;
    assert_eq!(meta["resources"]["orders"]["permissions"]["create"], false);
    assert!(meta["resources"]["suppliers"].is_null());
    assert_eq!(
        request(&app, "GET", "/api/admin/orders/", "", Value::Null)
            .await
            .0,
        401
    );
    let (status, supplier) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        buyer_cookie,
        json!({"supplier":{"name":"Example"}}),
    )
    .await;
    assert_eq!(status, 201, "{supplier}");
    let supplier = &supplier["supplier"]["id"];
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/orders/",
            viewer_cookie,
            json!({"name":"Denied","supplier":supplier,"quantity":10})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/orders/",
            buyer_cookie,
            json!({"name":"Bad","supplier":supplier,"quantity":0})
        )
        .await
        .0,
        400
    );
    let (status, order) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        buyer_cookie,
        json!({"name":"PO-1","supplier":supplier,"quantity":10}),
    )
    .await;
    assert_eq!(status, 201, "{order}");
    let id = order["order"]["id"].as_str().unwrap();
    let path = format!("/api/admin/orders/{id}/");
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/approve/"),
            viewer_cookie,
            json!({})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/approve/"),
            buyer_cookie,
            json!({})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/receive/"),
            buyer_cookie,
            json!({"reference":"R1","quantity":3})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/receive/"),
            buyer_cookie,
            json!({"reference":"R1","quantity":3})
        )
        .await
        .0,
        409
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/receive/"),
            buyer_cookie,
            json!({"reference":"R2","quantity":8})
        )
        .await
        .0,
        400
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/receive/"),
            buyer_cookie,
            json!({"reference":"R2","quantity":7,"fail":true})
        )
        .await
        .0,
        409
    );
    let (_, after) = request(
        &router(appstate.clone()),
        "GET",
        &path,
        buyer_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(
        after["order"]["received"], 3,
        "Failed hook/action writes must rollback"
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{path}actions/receive/"),
            buyer_cookie,
            json!({"reference":"R2","quantity":7})
        )
        .await
        .0,
        200
    );
    let (_, after) = request(
        &router(appstate.clone()),
        "GET",
        &path,
        buyer_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(after["order"]["received"], 10);
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/suppliers/{}/", supplier.as_str().unwrap()),
            buyer_cookie,
            Value::Null
        )
        .await
        .0,
        409
    );
    assert!(task_runner::tick(&appstate).await.unwrap());
    assert!(task_runner::tick(&appstate).await.unwrap());
    assert!(!task_runner::tick(&appstate).await.unwrap());
    let (_, events) = request(&app, "GET", "/api/admin/events/", buyer_cookie, Value::Null).await;
    assert_eq!(events["meta"]["total_results"], 2);
    let (status, note) = request(
        &app,
        "POST",
        "/api/admin/notes/",
        buyer_cookie,
        json!({"name":"Private","owner":buyer}),
    )
    .await;
    assert_eq!(status, 201, "{note}");
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/notes/",
            buyer_cookie,
            json!({"name":"Other","owner":viewer})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/notes/{}/", note["note"]["id"].as_str().unwrap()),
            buyer_cookie,
            json!({"owner":viewer})
        )
        .await
        .0,
        403
    );
    let actor = Actor {
        id: buyer.to_string(),
        roles: ["buyer".into()].into(),
    };
    let mut tx = pool.begin().await.unwrap();
    dynamic_rust::application::extensions::lock(&mut tx)
        .await
        .unwrap();
    Context::new(&mut tx, &appstate.registry, actor)
        .enqueue("receipt_recorded", "retry", json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE app_tasks SET state='running',lease_until=now()-interval '1 second' WHERE idempotency_key='retry'").execute(&pool).await.unwrap();
    assert!(task_runner::tick(&appstate).await.unwrap());
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
