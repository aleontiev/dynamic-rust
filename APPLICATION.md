# Application runtime

The optional `application` feature adds a PostgreSQL-backed Axum application to
Dynamic Rust's protocol primitives. It includes app-local Google/magic-link auth,
core identity resources, registered CRUD models, transactional hooks/actions,
admin metadata, append-only migrations and durable tasks. Each app connects using
its own database role. Cloud orchestration belongs to the host, not this library.

## Register business models

```rust
use dynamic_rust::{ApiError, FieldKind};
use dynamic_rust::application::extensions::{Model, Registry};

pub fn register(registry: &mut Registry) -> Result<(), ApiError> {
    registry.model(Model::new("suppliers", "supplier")
        .field("name", FieldKind::String).required("name")
        .field("email", FieldKind::Email)
        .unique(&["email"])
        .grant("authenticated", &["list", "read", "create", "update"]))?;
    Ok(())
}
```

Default access is denied. `authenticated` is assigned to signed-in users; other
roles come from the user's server-owned `data.roles` array, never request headers.
Core identity resources remain read-only. `Model.resource` exposes Dynamic Rust's
metadata, role grants, per-role field overrides, list columns and row filters.
Row filters support boolean groups and exact comparisons, including `$user.id`.
Declare filters for every permitted operation. Writes check both the existing and
proposed row scope. Hidden/write-only fields are excluded from record responses.

Relationships use `.relation("supplier", "suppliers")`; `.required("supplier")`
makes the reference mandatory. A referenced record must exist and be readable.
Deleting referenced records fails. Unique field combinations reject duplicates.
Models store validated JSON records; additive model fields do not require ALTER
TABLE. Use `registry.migration("001_backfill", SQL)` for data migrations and custom
indexes. Applied migration SQL cannot change. Migrations run with the app role,
never a shared-database administrator. Business writes serialize per app database;
this deliberately favors transaction correctness over high write concurrency.

CRUD routes are `/api/admin/suppliers/` and `/api/admin/suppliers/UUID/`. POST and
PATCH accept plain JSON or a singular envelope (`{"supplier":{...}}`). OPTIONS
returns the official admin's resource/field/action metadata. GET supports paging,
field selection, direct-field sorting, equality/inclusion, numeric comparisons,
and text contains filters. Nested relation query operators are rejected explicitly.

## Hooks and custom actions

Implement `Hook` with `#[handler]` (the re-exported async-trait macro) and attach it
using `model.hook(MyHook)`. `before(context, operation, previous, record)` validates
or changes the proposed record; `after` performs associated writes. Operations are
create/update/delete. Use `context.get/create/update/delete/list` for related
business data. All changes share the request transaction; nested mutations have
savepoints and hooks cannot change record identity. Keep external effects out of
hooks: queue a task in that transaction instead.

Implement `Handler::run(&self, &mut Context<'_>, Value) -> Result<Value, ApiError>`
for a custom API action. Register with
`registry.action("orders", "approve", &["buyer"], Approve)?`. It is POSTed to
`/api/admin/orders/UUID/actions/approve/` and receives
`{"id":"UUID","data":{...request JSON...}}`. The runtime checks action roles and
record visibility before invoking it. Context mutations continue to enforce model
permissions. `context.connection` is the current app-scoped SQL connection for
advanced transactional operations; code using raw SQL must enforce its own rules.

## Tasks

Register a `Handler` with `registry.task("send_receipt", SendReceipt)?`.
`context.enqueue("send_receipt", "receipt:UUID", payload).await?` persists work in
the same transaction as the triggering write. Repeating a key with different
input/actor is rejected. The task receives `task_id`, `idempotency_key` and `data`.
The actor's roles are loaded again at execution time.

Call `application::task_runner::tick(&app).await?` from an IAM-only scheduled Lambda
or a native loop. One tick processes at most one job. Claims expire after 120s;
handlers time out after 60s, retry with exponential backoff, and stop after five
attempts. Database effects and completion commit together. External effects are
at-least-once: pass the same idempotency key to the external provider. This queue
is for app business tasks, not a platform's project/agent messages.

## Host

Build a registry, call `application::configured(registry)`, then
`app.registry.migrate(&app.pool).await?`, and serve `application::router(app)`.
The same Router works with Axum locally or lambda-http in a Lambda executable.
The host supplies DATABASE_URL, APP_ORIGIN (HTTPS), APP_NAME, APP_REVISION,
APP_MAIL_FROM and optional broker/branding configuration. Local tests can construct
`App` with an isolated pool. `from_env()` retains the core-only bootstrap entry;
never put a shared database administrator URL into an executable containing custom
project code. Provision the database separately with a trusted bootstrap artifact.

See `tests/application_extensions.rs` for a complete executable purchase-order,
receipt, permission and task example. Run the suite against isolated PostgreSQL:

```sh
DREAM_TEST_DATABASE_URL=postgres://localhost/test_db cargo test --features application -- --include-ignored
```
