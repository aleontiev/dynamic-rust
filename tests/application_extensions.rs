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
                .icon("truck")
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
                .relations("backup_suppliers", "suppliers")
                .field("quantity", FieldKind::Integer)
                .required("quantity")
                .field("received", FieldKind::Integer)
                .field("state", FieldKind::String)
                .label("received", "Units received")
                .describe("received", "How many units of the order have arrived.")
                .describe("state", "Where the order is in the fulfilment process.")
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
    let owner = Uuid::new_v4();
    let newcomer = Uuid::new_v4();
    // The owner and the newcomer hold no app role at all; only the owner's email is configured as a superuser.
    for (id, role, token, roles) in [
        (buyer, "buyer", "buyer-token", json!(["buyer"])),
        (viewer, "viewer", "viewer-token", json!(["viewer"])),
        (owner, "owner", "owner-token", json!([])),
        (newcomer, "newcomer", "newcomer-token", json!([])),
    ] {
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":role,"email":format!("{role}@example.com"),"data":{"roles":roles}}))
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
        superusers: dynamic_rust::application::parse_superusers(" Owner@Example.com ,ignored"),
        operator_secret: None,
    };
    let app = router(appstate.clone());
    let buyer_cookie = "dream_app=buyer-token";
    let viewer_cookie = "dream_app=viewer-token";
    let owner_cookie = "dream_app=owner-token";
    let newcomer_cookie = "dream_app=newcomer-token";
    // Without a role, custom models are invisible; the configured superuser sees and may do everything.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", newcomer_cookie, Value::Null).await;
    assert!(meta["resources"]["orders"].is_null());
    assert!(meta["resources"]["suppliers"].is_null());
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/admin/orders/",
            newcomer_cookie,
            Value::Null
        )
        .await
        .0,
        403
    );
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", owner_cookie, Value::Null).await;
    assert_eq!(
        meta["resources"]["orders"]["permissions"]["create"], true,
        "{meta}"
    );
    assert_eq!(meta["resources"]["orders"]["permissions"]["delete"], true);
    // Declared labels and descriptions reach the admin; undeclared labels still
    // fall back to the title-cased field name, and an undeclared description is
    // null rather than absent so the client can rely on the key.
    let fields = &meta["resources"]["orders"]["fields"];
    assert_eq!(fields["received"]["label"], "Units received");
    assert_eq!(
        fields["received"]["description"],
        "How many units of the order have arrived."
    );
    assert_eq!(fields["state"]["label"], "State");
    assert_eq!(
        fields["state"]["description"],
        "Where the order is in the fulfilment process."
    );
    assert_eq!(fields["quantity"]["label"], "Quantity");
    assert!(fields["quantity"]["description"].is_null());
    assert!(
        meta["resources"]["orders"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["name"] == "approve")
    );
    let (status, owner_supplier) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        owner_cookie,
        json!({"supplier":{"name":"Owner supplier"}}),
    )
    .await;
    assert_eq!(status, 201, "{owner_supplier}");
    let (status, owner_order) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        owner_cookie,
        json!({"name":"PO-owner","supplier":owner_supplier["supplier"]["id"],"quantity":2}),
    )
    .await;
    assert_eq!(status, 201, "{owner_order}");
    let owner_order = owner_order["order"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("/api/admin/orders/{owner_order}/actions/approve/"),
            owner_cookie,
            json!({})
        )
        .await
        .0,
        200
    );
    // isnull filters work on custom models: every order has an id; none has a note yet.
    let (status, listed) = request(
        &app,
        "GET",
        "/api/admin/orders/?filter{id.isnull}=0&filter{received.isnull}=false",
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["meta"]["total_results"], 1, "{listed}");
    let (_, none) = request(
        &app,
        "GET",
        "/api/admin/orders/?filter{state.isnull}=1",
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(none["meta"]["total_results"], 0, "{none}");
    // Business rules still apply to a superuser: approved orders cannot be deleted.
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/orders/{owner_order}/"),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        409
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!(
                "/api/admin/suppliers/{}/",
                owner_supplier["supplier"]["id"].as_str().unwrap()
            ),
            newcomer_cookie,
            Value::Null
        )
        .await
        .0,
        403
    );
    let (status, meta) = request(&app, "OPTIONS", "/api/admin/", buyer_cookie, Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(
        meta["resources"]["orders"]["permissions"]["create"], true,
        "{meta}"
    );
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
        is_superuser: false,
        access: std::collections::BTreeMap::default(),
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

/// Roles stored as records: their access maps merge with the grants the code
/// declares, follow the user around as they navigate, and are managed through
/// the API by superusers and by anyone a role lets manage them.
#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn stored_roles_grant_access_at_runtime_and_are_managed_through_the_api() {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("roles_{}", Uuid::new_v4().simple());
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
    let owner = Uuid::new_v4();
    let clerk = Uuid::new_v4();
    let auditor = Uuid::new_v4();
    for (id, name, token) in [
        (owner, "owner", "owner-token"),
        (clerk, "clerk", "clerk-token"),
        (auditor, "auditor", "auditor-token"),
    ] {
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":name,"email":format!("{name}@example.com"),"data":{"roles":[],"team":"ops"}}))
            .execute(&pool)
            .await
            .unwrap();
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
        sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '1 hour')").bind(digest).bind(id).execute(&pool).await.unwrap();
    }
    let app = router(App {
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
    });
    let (owner_cookie, clerk_cookie, auditor_cookie) = (
        "dream_app=owner-token",
        "dream_app=clerk-token",
        "dream_app=auditor-token",
    );

    // Migrating provisioned the managed Admin role with every operation on every
    // resource, and it follows the registered models.
    let (_, roles) = request(&app, "GET", "/api/admin/roles/", owner_cookie, Value::Null).await;
    let admin_role = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Admin")
        .cloned()
        .expect("managed Admin role");
    assert_eq!(admin_role["permissions"]["orders"]["delete"], true);
    assert_eq!(admin_role["permissions"]["roles"]["create"], true);
    assert_eq!(admin_role["permissions"]["dashboards"]["create"], true);
    assert_eq!(
        admin_role["permissions"]["users"],
        json!({"list":true,"read":true,"update":true})
    );
    // Relations are described the way the admin renders them: as one/many with the related resource.
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/orders/",
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(meta["fields"]["supplier"]["type"], "one");
    assert_eq!(meta["fields"]["supplier"]["related"], "suppliers");

    // The permissions field tells an editor which resources rules may name and
    // which of them accept conditions; built-ins take only true or false.
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/roles/",
        owner_cookie,
        Value::Null,
    )
    .await;
    let resources = &meta["fields"]["permissions"]["resources"];
    assert_eq!(meta["fields"]["permissions"]["type"], "permissions");
    assert_eq!(resources["orders"]["conditional"], true);
    assert_eq!(resources["users"]["conditional"], false);
    assert!(
        resources["identities"].is_null(),
        "plumbing resources are not offered"
    );
    assert_eq!(meta["permissions"]["create"], true);
    assert_eq!(meta["fields"]["name"]["read_only"], false);
    let (_, meta) = request(
        &app,
        "OPTIONS",
        "/api/admin/roles/",
        clerk_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(meta["permissions"]["create"], false);
    assert_eq!(meta["fields"]["name"]["read_only"], true);

    // Only people whose roles allow it manage roles; maps are validated on save.
    let permissions = json!({
        "orders": {"list": true, "read": true, "create": true, "update": {"$or": [{"state": "draft"}, {"quantity": 1}]}, "delete": false},
        "suppliers": {"list": true, "read": true},
        "users": {"list": true}
    });
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/roles/",
            clerk_cookie,
            json!({"name":"Clerk","permissions":permissions})
        )
        .await
        .0,
        403
    );
    for (body, field, message) in [
        (json!({"name":"authenticated"}), "name", "reserved"),
        (json!({"name":""}), "name", "1 to 100"),
        (
            json!({"name":"Clerk","permissions":{"orders":{"fly":true}}}),
            "permissions",
            "unknown operation fly",
        ),
        (
            json!({"name":"Clerk","permissions":{"orders":{"list":{"colour":"red"}}}}),
            "permissions",
            "unknown field colour",
        ),
        (
            json!({"name":"Clerk","permissions":{"users":{"list":{"name":"x"}}}}),
            "permissions",
            "only true or false",
        ),
        (
            json!({"name":"Clerk","permissions":{"rockets":{"list":true}}}),
            "permissions",
            "Unknown resource: rockets",
        ),
    ] {
        let (status, error) = request(&app, "POST", "/api/admin/roles/", owner_cookie, body).await;
        assert_eq!(status, 400, "{error}");
        assert!(
            error["detail"][field][0]
                .as_str()
                .unwrap()
                .contains(message),
            "{error}"
        );
    }
    let (status, created) = request(
        &app,
        "POST",
        "/api/admin/roles/",
        owner_cookie,
        json!({"role":{"name":"Clerk","permissions":permissions}}),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let role = created["role"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created["role"]["permissions"], permissions);
    let (status, error) = request(
        &app,
        "POST",
        "/api/admin/roles/",
        owner_cookie,
        json!({"name":"clerk"}),
    )
    .await;
    assert_eq!(status, 400);
    assert!(
        error["detail"]["name"][0]
            .as_str()
            .unwrap()
            .contains("already exists")
    );

    // Holding no role, the clerk sees nothing custom.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", clerk_cookie, Value::Null).await;
    assert!(meta["resources"]["orders"].is_null());
    assert_eq!(
        request(&app, "GET", "/api/admin/orders/", clerk_cookie, Value::Null)
            .await
            .0,
        403
    );

    // Roles are assigned by id on the user record, by someone allowed to.
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/users/{clerk}/"),
            clerk_cookie,
            json!({"roles":[role]})
        )
        .await
        .0,
        403
    );
    let (status, error) = request(
        &app,
        "PATCH",
        &format!("/api/admin/users/{clerk}/"),
        owner_cookie,
        json!({"roles":[Uuid::new_v4()]}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(error["detail"]["roles"][0], "Unknown role.");
    let (status, updated) = request(
        &app,
        "PATCH",
        &format!("/api/admin/users/{clerk}/"),
        owner_cookie,
        json!({"user":{"roles":[role]}}),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["user"]["roles"], json!([role]));
    assert_eq!(
        updated["user"]["data"],
        json!({"team":"ops"}),
        "the rest of the user's data is untouched"
    );
    let (_, me) = request(
        &app,
        "GET",
        "/api/admin/users/me/",
        clerk_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(me["user"]["roles"], json!([role]));

    // From the next request on, the clerk navigates with the role's access.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", clerk_cookie, Value::Null).await;
    let orders = &meta["resources"]["orders"]["permissions"];
    assert_eq!(
        (
            orders["list"].clone(),
            orders["create"].clone(),
            orders["update"].clone(),
            orders["delete"].clone()
        ),
        (json!(true), json!(true), json!(true), json!(false)),
        "{meta}"
    );
    assert_eq!(
        meta["resources"]["suppliers"]["permissions"]["create"],
        false
    );
    assert!(
        meta["resources"]["receipts"].is_null(),
        "resources no role grants stay invisible"
    );
    assert_eq!(meta["resources"]["users"]["permissions"]["update"], false);
    let (status, supplier) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        owner_cookie,
        json!({"name":"Acme"}),
    )
    .await;
    assert_eq!(status, 201, "{supplier}");
    let supplier = supplier["supplier"]["id"].clone();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/suppliers/",
            clerk_cookie,
            json!({"name":"Nope"})
        )
        .await
        .0,
        403
    );
    let (status, order) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        clerk_cookie,
        json!({"name":"Paper","supplier":supplier,"quantity":5}),
    )
    .await;
    assert_eq!(status, 201, "{order}");
    let order = order["order"]["id"].as_str().unwrap().to_owned();
    let (status, _) = request(
        &app,
        "PATCH",
        &format!("/api/admin/orders/{order}/"),
        clerk_cookie,
        json!({"name":"Paper (draft)"}),
    )
    .await;
    assert_eq!(status, 200, "a draft order matches the update condition");
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/orders/{order}/"),
            clerk_cookie,
            Value::Null
        )
        .await
        .0,
        403
    );
    sqlx::query("UPDATE app_records SET data=data||'{\"state\":\"approved\"}' WHERE id=$1")
        .bind(Uuid::parse_str(&order).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/admin/orders/{order}/"),
            clerk_cookie,
            Value::Null
        )
        .await
        .0,
        200,
        "reading is unconditional"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{order}/"),
            clerk_cookie,
            json!({"name":"Paper (approved)"})
        )
        .await
        .0,
        404,
        "an approved order with quantity 5 is outside the update condition"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{order}/"),
            clerk_cookie,
            json!({"quantity":1})
        )
        .await
        .0,
        404,
        "the condition applies to the row as it is, not as proposed"
    );

    // Conditions carry operators: numbers compare numerically, `in` lists,
    // `icontains` matches text, `isnull` tests presence.
    let (status, edited) = request(&app, "PATCH", &format!("/api/admin/roles/{role}/"), owner_cookie, json!({"permissions":{
        "orders":{"list":{"$or":[{"quantity__gte":5,"name__icontains":"PAPER"},{"state__in":["shipped","closed"]}]},"read":true,"update":{"received__lte":0,"quantity__lt":10,"state__isnull":false}},
        "suppliers":{"list":true,"read":true}
    }})).await;
    assert_eq!(status, 200, "{edited}");
    let (_, big) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        owner_cookie,
        json!({"name":"Paper reams","supplier":supplier,"quantity":12}),
    )
    .await;
    let big = big["order"]["id"].as_str().unwrap().to_owned();
    let (_, small) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        owner_cookie,
        json!({"name":"Paper clips","supplier":supplier,"quantity":2}),
    )
    .await;
    let small = small["order"]["id"].as_str().unwrap().to_owned();
    let (_, shipped) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        owner_cookie,
        json!({"name":"Toner","supplier":supplier,"quantity":1}),
    )
    .await;
    let shipped = shipped["order"]["id"].as_str().unwrap().to_owned();
    sqlx::query("UPDATE app_records SET data=data||'{\"state\":\"shipped\"}' WHERE id=$1")
        .bind(Uuid::parse_str(&shipped).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let (status, listed) = request(
        &app,
        "GET",
        "/api/admin/orders/?sort[]=name",
        clerk_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{listed}");
    let names: Vec<&str> = listed["orders"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["Paper (draft)", "Paper reams", "Toner"],
        "{listed}"
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/admin/orders/{small}/"),
            clerk_cookie,
            Value::Null
        )
        .await
        .0,
        200,
        "reading stays unconditional"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{small}/"),
            clerk_cookie,
            json!({"name":"Paper clips (boxed)"})
        )
        .await
        .0,
        200,
        "nothing received yet and quantity 2 < 10"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{big}/"),
            clerk_cookie,
            json!({"name":"Paper reams (boxed)"})
        )
        .await
        .0,
        404,
        "quantity 12 is not < 10"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{small}/"),
            clerk_cookie,
            json!({"received":1})
        )
        .await
        .0,
        403,
        "setting received leaves the update condition"
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{small}/"),
            clerk_cookie,
            json!({"quantity":30})
        )
        .await
        .0,
        403,
        "the proposed quantity must still satisfy the condition"
    );

    // Editing the role changes what its holders may do on their next request.
    let (status, edited) = request(
        &app,
        "PATCH",
        &format!("/api/admin/roles/{role}/"),
        owner_cookie,
        json!({"permissions":{"orders":{"list":true,"read":true,"update":true},"suppliers":{"list":true,"read":true}}}),
    )
    .await;
    assert_eq!(status, 200, "{edited}");
    assert_eq!(edited["role"]["name"], "Clerk");
    let (status, body) = request(
        &app,
        "PATCH",
        &format!("/api/admin/orders/{order}/"),
        clerk_cookie,
        json!({"name":"Paper (approved)"}),
    )
    .await;
    assert_eq!(status, 200, "{body} {edited}");
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/orders/",
            clerk_cookie,
            json!({"name":"Pens","supplier":supplier,"quantity":2})
        )
        .await
        .0,
        403
    );
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", clerk_cookie, Value::Null).await;
    assert_eq!(meta["resources"]["orders"]["permissions"]["create"], false);
    assert!(
        meta["resources"]["users"]["permissions"]["list"]
            .as_bool()
            .unwrap()
    );

    // A role that manages roles and users delegates administration.
    let (status, admins) = request(&app, "POST", "/api/admin/roles/", owner_cookie, json!({"name":"Manager","permissions":{"roles":{"list":true,"read":true,"create":true,"update":true,"delete":true},"users":{"list":true,"read":true,"update":true}}})).await;
    assert_eq!(status, 201, "{admins}");
    let admins = admins["role"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/users/{auditor}/"),
            owner_cookie,
            json!({"roles":[admins]})
        )
        .await
        .0,
        200
    );
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", auditor_cookie, Value::Null).await;
    assert_eq!(meta["resources"]["roles"]["permissions"]["delete"], true);
    assert_eq!(meta["resources"]["users"]["permissions"]["update"], true);
    assert_eq!(
        meta["resources"]["users"]["fields"]["roles"]["read_only"],
        false
    );
    assert_eq!(
        meta["resources"]["users"]["fields"]["roles"]["choices"],
        json!([{"id":admin_role["id"],"label":"Admin"},{"id":role,"label":"Clerk"},{"id":admins,"label":"Manager"}]),
        "existing roles are the choices for a user's roles"
    );
    assert_eq!(
        meta["resources"]["users"]["fields"]["email"]["read_only"],
        true
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/roles/",
            auditor_cookie,
            json!({"name":"Viewer","permissions":{}})
        )
        .await
        .0,
        201
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/users/{clerk}/"),
            auditor_cookie,
            json!({"name":"Clerk Two"})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/users/",
            auditor_cookie,
            json!({"name":"x"})
        )
        .await
        .0,
        405
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/users/{clerk}/"),
            auditor_cookie,
            Value::Null
        )
        .await
        .0,
        405
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/admin/orders/",
            auditor_cookie,
            Value::Null
        )
        .await
        .0,
        403,
        "managing roles grants nothing else"
    );

    // Deleting a role removes it from its holders, who lose its access at once.
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/roles/{role}/"),
            auditor_cookie,
            Value::Null
        )
        .await
        .0,
        204
    );
    let (_, user) = request(
        &app,
        "GET",
        &format!("/api/admin/users/{clerk}/"),
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(user["user"]["roles"], json!([]));
    assert_eq!(user["user"]["name"], "Clerk Two");
    assert_eq!(
        request(&app, "GET", "/api/admin/orders/", clerk_cookie, Value::Null)
            .await
            .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/admin/roles/{role}/"),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        404
    );

    // Dashboards and saved views are written by superusers and holders of roles that grant them.
    let (status, dashboard) = request(
        &app,
        "POST",
        "/api/admin/dashboards/",
        owner_cookie,
        json!({"name":"Operations","data":{"cards":[]}}),
    )
    .await;
    assert_eq!(status, 201, "{dashboard}");
    let dashboard = dashboard["dashboard"]["id"].as_str().unwrap().to_owned();
    let (status, view) = request(&app, "POST", "/api/admin/views/", owner_cookie, json!({"view":{"name":"Open orders","resource":"orders","data":{"filter":[{"state":"draft"}]}}})).await;
    assert_eq!(status, 201, "{view}");
    assert_eq!(view["view"]["resource"], "orders");
    let (status, error) = request(
        &app,
        "POST",
        "/api/admin/views/",
        owner_cookie,
        json!({"name":"Bad","resource":"rockets","data":{}}),
    )
    .await;
    assert_eq!(status, 400);
    assert!(
        error["detail"]["resource"][0]
            .as_str()
            .unwrap()
            .contains("Choose one of")
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/admin/dashboards/{dashboard}/"),
            owner_cookie,
            json!({"name":"Ops"})
        )
        .await
        .1["dashboard"]["name"],
        "Ops"
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/admin/dashboards/",
            clerk_cookie,
            json!({"name":"Mine","data":{}})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/dashboards/{dashboard}/"),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        204
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/admin/dashboards/{dashboard}/"),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        404
    );

    // Related records are sideloaded on request, as the admin asks for every relation it shows.
    let (_, listed) = request(
        &app,
        "GET",
        "/api/admin/orders/?include[]=supplier.*",
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(
        listed["suppliers"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    assert_eq!(listed["suppliers"][0]["name"], "Acme");
    assert_eq!(
        listed["orders"][0]["supplier"], supplier,
        "the relation stays an id on the record"
    );
    let (_, plain) = request(&app, "GET", "/api/admin/orders/", owner_cookie, Value::Null).await;
    assert!(
        plain["suppliers"].is_null(),
        "nothing is sideloaded unless asked"
    );
    let (_, one) = request(
        &app,
        "GET",
        &format!("/api/admin/orders/{order}/?include[]=supplier.*"),
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(one["suppliers"][0]["name"], "Acme");

    // A model's icon reaches the admin, and a many-relation is a list of ids
    // that must all exist, sideloads like a single one, and keeps its targets.
    let (_, meta) = request(&app, "OPTIONS", "/api/admin/", owner_cookie, Value::Null).await;
    assert_eq!(meta["resources"]["suppliers"]["icon"], "truck");
    assert_eq!(meta["resources"]["orders"]["icon"], "table");
    let backups = &meta["resources"]["orders"]["fields"]["backup_suppliers"];
    assert_eq!(backups["type"], "many", "{backups}");
    assert_eq!(backups["related"], "suppliers");
    assert_eq!(backups["many"], true);
    let (status, spare) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        owner_cookie,
        json!({"name":"Spare"}),
    )
    .await;
    assert_eq!(status, 201, "{spare}");
    let spare = spare["supplier"]["id"].clone();
    for (body, expected) in [
        (
            json!({"name":"Backed","supplier":supplier,"quantity":1,"backup_suppliers":[spare, supplier]}),
            201,
        ),
        (
            json!({"name":"Unknown","supplier":supplier,"quantity":1,"backup_suppliers":[Uuid::new_v4()]}),
            400,
        ),
        (
            json!({"name":"Scalar","supplier":supplier,"quantity":1,"backup_suppliers":spare}),
            400,
        ),
        (
            json!({"name":"Junk","supplier":supplier,"quantity":1,"backup_suppliers":["not-an-id"]}),
            400,
        ),
    ] {
        let name = body["name"].clone();
        let (status, created) =
            request(&app, "POST", "/api/admin/orders/", owner_cookie, body).await;
        assert_eq!(status, expected, "{name}: {created}");
    }
    let (_, backed) = request(
        &app,
        "GET",
        "/api/admin/orders/?filter{name}=Backed&include[]=backup_suppliers.*",
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(
        backed["orders"][0]["backup_suppliers"],
        json!([spare, supplier])
    );
    let mut sideloaded: Vec<&str> = backed["suppliers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    sideloaded.sort_unstable();
    assert_eq!(sideloaded, ["Acme", "Spare"]);
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/admin/suppliers/{}/", spare.as_str().unwrap()),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        409,
        "a supplier listed as a backup is still referenced"
    );
    // The records behind a relation are served as a page in the record's order,
    // which is how the admin lists a many-relation on a detail page.
    let backed_id = backed["orders"][0]["id"].as_str().unwrap().to_owned();
    let (status, page) = request(
        &app,
        "GET",
        &format!("/api/admin/orders/{backed_id}/backup_suppliers/?include[]=name&include[]=id&exclude[]=*&page=1&per_page=10"),
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(
        page["suppliers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Spare", "Acme"]
    );
    assert_eq!(page["meta"]["total_results"], 2);
    let (status, one) = request(
        &app,
        "GET",
        &format!("/api/admin/orders/{backed_id}/supplier/"),
        owner_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{one}");
    assert_eq!(one["suppliers"].as_array().map(Vec::len), Some(1));
    assert_eq!(one["suppliers"][0]["name"], "Acme");
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/admin/orders/{backed_id}/quantity/"),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        404,
        "only relation fields have related records"
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/admin/orders/{}/backup_suppliers/", Uuid::new_v4()),
            owner_cookie,
            Value::Null
        )
        .await
        .0,
        404
    );

    // Legacy role names on a user still match the grants declared in code.
    sqlx::query(
        "UPDATE app_records SET data=jsonb_set(data,'{data,roles}','[\"viewer\"]') WHERE id=$1",
    )
    .bind(clerk)
    .execute(&pool)
    .await
    .unwrap();
    let (status, viewer_orders) = request(
        &app,
        "GET",
        "/api/admin/orders/?include[]=supplier.*",
        clerk_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{viewer_orders}");
    assert!(
        viewer_orders["suppliers"].is_null(),
        "a viewer cannot read suppliers, so none are sideloaded"
    );
    sqlx::query(
        "UPDATE app_records SET data=jsonb_set(data,'{data,roles}','[\"buyer\"]') WHERE id=$1",
    )
    .bind(clerk)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/admin/receipts/",
            clerk_cookie,
            Value::Null
        )
        .await
        .0,
        200
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}
