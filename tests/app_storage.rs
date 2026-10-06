#![allow(clippy::too_many_lines, clippy::items_after_statements)]
#![cfg(feature = "application")]
//! Table storage: a typed schema the database enforces, and how it evolves.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use dynamic_rust::{
    FieldKind,
    application::{
        App,
        extensions::{Model, Registry, Storage},
        router,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

async fn isolated_pool(prefix: &str) -> PgPool {
    let url = std::env::var("DREAM_TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    PgPoolOptions::new()
        .max_connections(4)
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
async fn request(app: &Router, method: &str, path: &str, body: Value) -> (u16, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", "dream_app=owner-token")
                .header("content-type", "application/json")
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
/// A signed-in owner (a superuser) and the router over `registry`.
async fn serve(pool: &PgPool, registry: Registry) -> Router {
    let owner = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(json!({"name":"owner","email":"owner@example.com","data":{"roles":[]}}))
    .execute(pool)
    .await
    .unwrap();
    use sha2::{Digest, Sha256};
    sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '1 hour') ON CONFLICT DO NOTHING")
        .bind(format!("{:x}", Sha256::digest(b"owner-token")))
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    router(App {
        pool: pool.clone(),
        registry: Arc::new(registry),
        name: "Storage".into(),
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
    })
}
fn suppliers() -> Model {
    Model::new("suppliers", "supplier")
        .field("name", FieldKind::String)
        .required("name")
        .field("code", FieldKind::String)
        .unique(&["code"])
        .grant("buyer", &["list", "read"])
}
fn orders(quantity: FieldKind) -> Model {
    Model::new("orders", "order")
        .field("name", FieldKind::String)
        .required("name")
        .field("quantity", quantity)
        .field("price", FieldKind::Decimal)
        .field("rate", FieldKind::Float)
        .field("rush", FieldKind::Boolean)
        .field("due", FieldKind::Date)
        .field("sent_at", FieldKind::DateTime)
        .field("cutoff", FieldKind::Time)
        .field("contact", FieldKind::Email)
        .field("details", FieldKind::Json)
        .field("reference", FieldKind::Uuid)
        .field("lead_time", FieldKind::Duration)
        .relation("supplier", "suppliers")
        .required("supplier")
        .relations("backups", "suppliers")
        .relation("owner", "users")
        .grant("buyer", &["list", "read"])
}
fn registry(models: Vec<Model>) -> Registry {
    let mut registry = Registry::default();
    registry.storage(Storage::Tables);
    for model in models {
        registry.model(model).unwrap();
    }
    registry
}
async fn columns(pool: &PgPool, table: &str) -> BTreeMap<String, (String, bool)> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT a.attname::text,format_type(a.atttypid,a.atttypmod),a.attnotnull FROM pg_attribute a WHERE a.attrelid=to_regclass($1) AND a.attnum>0 AND NOT a.attisdropped",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.into_iter().map(|(n, t, nn)| (n, (t, nn))).collect()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn tables_hold_a_typed_schema_the_database_enforces() {
    let pool = isolated_pool("tables_schema").await;
    let registry = registry(vec![suppliers(), orders(FieldKind::Integer)]);
    registry.migrate(&pool).await.unwrap();
    registry.migrate(&pool).await.unwrap();

    // One typed column per field; required fields are NOT NULL.
    let order = columns(&pool, "orders").await;
    for (name, typ, not_null) in [
        ("id", "uuid", true),
        ("created", "timestamp with time zone", true),
        ("updated", "timestamp with time zone", true),
        ("name", "text", true),
        ("quantity", "bigint", false),
        ("price", "numeric", false),
        ("rate", "double precision", false),
        ("rush", "boolean", false),
        ("due", "date", false),
        ("sent_at", "timestamp with time zone", false),
        ("cutoff", "time without time zone", false),
        ("contact", "text", false),
        ("details", "jsonb", false),
        ("reference", "uuid", false),
        ("lead_time", "text", false),
        ("supplier", "uuid", true),
        ("owner", "uuid", false),
    ] {
        assert_eq!(order[name], (typ.to_owned(), not_null), "{name}");
    }
    assert!(
        !order.contains_key("backups"),
        "a many-relation has a join table"
    );
    let join = columns(&pool, "orders__backups").await;
    assert_eq!(join["target"].0, "uuid");
    assert_eq!(join["position"].0, "integer");
    // Records in app_records stay where they were: users are built in.
    let keys: Vec<(String, String)> = sqlx::query_as(
        "SELECT conrelid::regclass::text,confrelid::regclass::text FROM pg_constraint WHERE contype='f' AND connamespace=current_schema()::regnamespace AND conrelid::regclass::text NOT LIKE 'app\\_%' ORDER BY 1,2",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        keys,
        vec![
            ("orders".to_owned(), "suppliers".to_owned()),
            ("orders__backups".to_owned(), "orders".to_owned()),
            ("orders__backups".to_owned(), "suppliers".to_owned()),
        ],
        "relations to models get foreign keys; one to a built-in does not"
    );

    let app = serve(&pool, registry).await;
    let (status, acme) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        json!({"name":"Acme","code":"A1"}),
    )
    .await;
    assert_eq!(status, 201, "{acme}");
    let acme = acme["supplier"]["id"].as_str().unwrap().to_owned();
    let (_, globex) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        json!({"name":"Globex","code":"G1"}),
    )
    .await;
    let globex = globex["supplier"]["id"].as_str().unwrap().to_owned();
    // Unique combinations: the runtime refuses, and so would the database.
    let (status, _) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        json!({"name":"Copy","code":"A1"}),
    )
    .await;
    assert_eq!(status, 409);
    let raw = sqlx::query("INSERT INTO suppliers(id,name,code) VALUES($1,'Raw','A1')")
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await;
    assert!(raw.is_err(), "the unique index holds outside the API too");

    let reference = Uuid::new_v4();
    let (status, created) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        json!({"name":"Paper","quantity":3,"price":12.5,"rate":0.25,"rush":true,"due":"2026-11-02",
               "sent_at":"2026-10-06T15:30:00Z","cutoff":"17:00:00","contact":"buyer@example.com",
               "details":{"bin":"A-4"},"reference":reference,"lead_time":"2 days",
               "supplier":acme,"backups":[globex,acme]}),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let created = &created["order"];
    assert_eq!(created["quantity"], 3);
    assert_eq!(created["price"], 12.5);
    assert_eq!(created["rush"], true);
    assert_eq!(created["due"], "2026-11-02");
    assert_eq!(created["cutoff"], "17:00:00");
    assert_eq!(created["details"], json!({"bin":"A-4"}));
    assert_eq!(
        created["backups"],
        json!([globex, acme]),
        "in the order given"
    );
    assert!(created["owner"].is_null() && created.as_object().unwrap().contains_key("owner"));
    let paper = created["id"].as_str().unwrap().to_owned();
    // The row is in the table, typed.
    let (due, price): (String, String) =
        sqlx::query_as("SELECT due::text,price::text FROM orders WHERE id=$1")
            .bind(Uuid::parse_str(&paper).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((due.as_str(), price.as_str()), ("2026-11-02", "12.5"));
    let records: i64 =
        sqlx::query_scalar("SELECT count(*) FROM app_records WHERE kind IN ('orders','suppliers')")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(records, 0);

    // A value of the wrong form is a 400, not a server error.
    for bad in [
        json!({"due":"next tuesday"}),
        json!({"cutoff":"25:99"}),
        json!({"sent_at":"soon"}),
    ] {
        let (status, body) = request(
            &app,
            "PATCH",
            &format!("/api/admin/orders/{paper}/"),
            bad.clone(),
        )
        .await;
        assert_eq!(status, 400, "{bad} {body}");
    }
    let (_, second) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        json!({"name":"Toner","quantity":10,"price":99.99,"due":"2026-10-20","sent_at":"2026-10-07T09:00:00+02:00","supplier":globex}),
    )
    .await;
    let toner = second["order"]["id"].as_str().unwrap().to_owned();

    // Filters and sorts compare typed values.
    let ids = |body: &Value| -> Vec<String> {
        body["orders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap().to_owned())
            .collect()
    };
    for (query, expected) in [
        ("filter{quantity.gt}=5".to_owned(), vec![toner.clone()]),
        ("filter{price.lte}=20".to_owned(), vec![paper.clone()]),
        ("filter{due.lt}=2026-11-01".to_owned(), vec![toner.clone()]),
        (
            "filter{sent_at.gte}=2026-10-06T16:00:00Z".to_owned(),
            vec![toner.clone()],
        ),
        ("filter{name.icontains}=ONE".to_owned(), vec![toner.clone()]),
        ("filter{rush}=true".to_owned(), vec![paper.clone()]),
        (format!("filter{{supplier}}={acme}"), vec![paper.clone()]),
        (
            "filter{owner.isnull}=true&sort[]=-due".to_owned(),
            vec![paper.clone(), toner.clone()],
        ),
        (
            "sort[]=quantity".to_owned(),
            vec![paper.clone(), toner.clone()],
        ),
    ] {
        let (status, body) = request(
            &app,
            "GET",
            &format!("/api/admin/orders/?{query}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200, "{query} {body}");
        assert_eq!(ids(&body), expected, "{query}");
    }
    let (status, _) = request(
        &app,
        "GET",
        "/api/admin/orders/?filter{due.lt}=whenever",
        Value::Null,
    )
    .await;
    assert_eq!(status, 400);

    // Foreign keys: referenced records stay, dangling ids are refused.
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/admin/suppliers/{acme}/"),
        Value::Null,
    )
    .await;
    assert_eq!(status, 409);
    assert!(
        sqlx::query("DELETE FROM suppliers WHERE id=$1")
            .bind(Uuid::parse_str(&acme).unwrap())
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("INSERT INTO orders(id,name,supplier) VALUES($1,'Ghost',$2)")
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("INSERT INTO orders(id,name) VALUES($1,'No supplier')")
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .is_err(),
        "NOT NULL holds"
    );
    // Deleting an order removes its many-relation rows with it.
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/admin/orders/{paper}/"),
        Value::Null,
    )
    .await;
    assert_eq!(status, 204);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM orders__backups")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/admin/suppliers/{acme}/"),
        Value::Null,
    )
    .await;
    assert_eq!(status, 204, "no longer referenced");
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn schemas_evolve_by_adding_and_refuse_to_lose_data() {
    let pool = isolated_pool("tables_evolve").await;
    registry(vec![suppliers(), orders(FieldKind::Integer)])
        .migrate(&pool)
        .await
        .unwrap();
    let supplier = Uuid::new_v4();
    sqlx::query("INSERT INTO suppliers(id,name) VALUES($1,'Acme')")
        .bind(supplier)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO orders(id,name,quantity,supplier) VALUES($1,'Paper',3,$2)")
        .bind(Uuid::new_v4())
        .bind(supplier)
        .execute(&pool)
        .await
        .unwrap();

    // A new field is a new column; a new required field becomes NOT NULL only
    // once no row lacks it.
    let grown = || {
        orders(FieldKind::Integer)
            .field("region", FieldKind::String)
            .field("cost_center", FieldKind::String)
            .required("cost_center")
    };
    registry(vec![suppliers(), grown()])
        .migrate(&pool)
        .await
        .unwrap();
    let order = columns(&pool, "orders").await;
    assert_eq!(order["region"], ("text".to_owned(), false));
    assert_eq!(
        order["cost_center"],
        ("text".to_owned(), false),
        "existing rows have none yet"
    );
    sqlx::query("UPDATE orders SET cost_center='OPS'")
        .execute(&pool)
        .await
        .unwrap();
    registry(vec![suppliers(), grown()])
        .migrate(&pool)
        .await
        .unwrap();
    assert!(
        columns(&pool, "orders").await["cost_center"].1,
        "now enforced"
    );

    // A changed type stops the migration until a migration converts it.
    let mut retyped = registry(vec![
        suppliers(),
        Model::new("orders", "order")
            .field("name", FieldKind::String)
            .required("name")
            .field("quantity", FieldKind::Decimal)
            .field("price", FieldKind::Decimal)
            .field("rate", FieldKind::Float)
            .field("rush", FieldKind::Boolean)
            .field("due", FieldKind::Date)
            .field("sent_at", FieldKind::DateTime)
            .field("cutoff", FieldKind::Time)
            .field("contact", FieldKind::Email)
            .field("details", FieldKind::Json)
            .field("reference", FieldKind::Uuid)
            .field("lead_time", FieldKind::Duration)
            .relation("supplier", "suppliers")
            .required("supplier")
            .relations("backups", "suppliers")
            .relation("owner", "users")
            .field("region", FieldKind::String)
            .field("cost_center", FieldKind::String)
            .required("cost_center"),
    ]);
    let error = retyped.migrate(&pool).await.unwrap_err().to_string();
    assert!(
        error.contains("quantity") && error.contains("registry.migration"),
        "{error}"
    );
    assert_eq!(
        columns(&pool, "orders").await["quantity"].0,
        "bigint",
        "nothing changed"
    );
    retyped
        .migration(
            "m001_quantity_numeric",
            "ALTER TABLE orders ALTER COLUMN quantity TYPE numeric",
        )
        .unwrap();
    retyped.migrate(&pool).await.unwrap();
    assert_eq!(columns(&pool, "orders").await["quantity"].0, "numeric");
    let quantity: String = sqlx::query_scalar("SELECT quantity::text FROM orders")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(quantity, "3", "the data came along");

    // A removed field keeps its data until a migration drops it on purpose.
    let mut shrunk = registry(vec![suppliers(), grown()]);
    shrunk
        .models
        .get_mut("orders")
        .unwrap()
        .resource
        .fields
        .retain(|f| f.name != "region");
    shrunk
        .migration(
            "m001_quantity_numeric",
            "ALTER TABLE orders ALTER COLUMN quantity TYPE numeric",
        )
        .unwrap();
    // (quantity is decimal again in the code of this release)
    let orders_model = shrunk.models.get_mut("orders").unwrap();
    for field in &mut orders_model.resource.fields {
        if field.name == "quantity" {
            field.kind = FieldKind::Decimal;
        }
    }
    let error = shrunk.migrate(&pool).await.unwrap_err().to_string();
    assert!(
        error.contains("region") && error.contains("DROP COLUMN"),
        "{error}"
    );
    shrunk
        .migration("m002_drop_region", "ALTER TABLE orders DROP COLUMN region")
        .unwrap();
    shrunk.migrate(&pool).await.unwrap();
    assert!(!columns(&pool, "orders").await.contains_key("region"));

    // Dropping a whole model is refused while its table holds records.
    let error = Registry::default()
        .migrate(&pool)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("no longer registered") && error.contains("DROP TABLE"),
        "{error}"
    );
    // Reserved names are refused.
    let pool = isolated_pool("tables_reserved").await;
    let mut reserved = Registry::default();
    reserved
        .model(
            Model::new("app_things", "app_thing")
                .storage(Storage::Tables)
                .field("name", FieldKind::String),
        )
        .unwrap();
    let error = reserved.migrate(&pool).await.unwrap_err().to_string();
    assert!(error.contains("reserved"), "{error}");
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn records_move_into_a_table_and_not_silently_back() {
    let pool = isolated_pool("tables_move").await;
    // An app that started in records storage...
    let records = || {
        let mut registry = Registry::default();
        registry.model(suppliers()).unwrap();
        registry.model(orders(FieldKind::Integer)).unwrap();
        registry
    };
    records().migrate(&pool).await.unwrap();
    let app = serve(&pool, records()).await;
    let (_, acme) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        json!({"name":"Acme","code":"A1"}),
    )
    .await;
    let acme = acme["supplier"]["id"].as_str().unwrap().to_owned();
    let (_, globex) = request(
        &app,
        "POST",
        "/api/admin/suppliers/",
        json!({"name":"Globex"}),
    )
    .await;
    let globex = globex["supplier"]["id"].as_str().unwrap().to_owned();
    let (status, paper) = request(
        &app,
        "POST",
        "/api/admin/orders/",
        json!({"name":"Paper","quantity":3,"price":1.5,"due":"2026-11-02","supplier":acme,"backups":[globex]}),
    )
    .await;
    assert_eq!(status, 201, "{paper}");
    let paper = paper["order"].clone();

    // ...moves its orders into a table: the records come along, typed.
    let moved = || {
        let mut registry = Registry::default();
        registry.model(suppliers()).unwrap();
        registry
            .model(orders(FieldKind::Integer).storage(Storage::Tables))
            .unwrap();
        registry
    };
    moved().migrate(&pool).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM app_records WHERE kind='orders'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    let app = serve(&pool, moved()).await;
    let (status, read) = request(
        &app,
        "GET",
        &format!("/api/admin/orders/{}/", paper["id"].as_str().unwrap()),
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{read}");
    for field in [
        "name", "quantity", "price", "due", "supplier", "backups", "created",
    ] {
        assert_eq!(read["order"][field], paper[field], "{field}");
    }
    // Suppliers stayed in records storage; the order's foreign key points there.
    let target: String = sqlx::query_scalar("SELECT confrelid::regclass::text FROM pg_constraint WHERE contype='f' AND conrelid='orders'::regclass")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(target, "app_records");
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/admin/suppliers/{acme}/"),
        Value::Null,
    )
    .await;
    assert_eq!(status, 409, "still referenced from the table");

    // Going back would hide the table's rows: refused with what to do.
    let error = records().migrate(&pool).await.unwrap_err().to_string();
    assert!(error.contains("still holds 1 records"), "{error}");
}
