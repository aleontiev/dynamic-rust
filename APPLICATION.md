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
        .label("email", "Contact email")
        .describe("email", "Where purchase orders for this supplier are sent.")
        .unique(&["email"])
        .grant("authenticated", &["list", "read", "create", "update"]))?;
    Ok(())
}
```

Default access is denied. `authenticated` is assigned to signed-in users; other
roles come from the user's server-owned `roles` list, never request headers.

Signing in is for the people the app knows: its superusers (the owners), and
anyone an administrator added on the Users page — `POST /api/admin/users/`
with an `email`, an optional `name` (defaulting to the address) and optional
`roles`, which takes the `users` `create` grant the managed Admin role holds.
An email link is only sent to such an address (a stranger's request answers
403 with a message saying to ask an administrator), and Google sign-in for an
unknown address ends on the sign-in page with the same advice; no account is
ever created by signing in. The email is set once, when the person is added,
and is read-only afterwards. So `authenticated` means every member of the app,
never the public.

Holding a role is what makes someone a member: the superusers and anyone with
at least one role. A signed-in person with no role carries no `authenticated`
role either, so they reach nothing — `OPTIONS /api/admin/` answers
`"access": "none"` with no resources, every list and schema request is
refused, and only their own user record and `/api/admin/users/me/` answer —
and the admin shows them a page saying to ask an administrator for a role.
Built-in resources follow the same rule: a member reads dashboards and views
(the admin's own pages) and whatever their roles grant (`users`, `roles`,
`providers`, `identities`, `identity_verifications`), and nothing else.
`Model.resource` exposes Dynamic Rust's metadata, role grants, per-role field
overrides, list columns and row filters. Row filters support boolean groups and
exact comparisons, including `$user.id`. A role granted an operation without a
filter is unrestricted for it. Writes check both the existing and proposed row
scope. Hidden/write-only fields are excluded from record responses.

## Stored roles

Roles are also records: `/api/admin/roles/` holds a `name` and a `permissions`
access map, grouped by resource and operation. A rule is `true`, `false`, or a
condition the rows must meet — an object of field lookups whose values are
scalars or `$user.id`, or `$or`, `$and` and `$not` groups of conditions. A
lookup is a field name with an optional operator: `exact` (the default), `in`
(a list of values), `icontains`, `gt`, `gte`, `lt`, `lte`, and `isnull` (a
boolean). Numeric fields compare as numbers, other fields as text:

```json
{"orders": {"list": true, "read": true, "create": true,
            "update": {"$or": [{"state__in": ["draft", "review"]},
                               {"owner": "$user.id", "quantity__lte": 10}]}},
 "suppliers": {"list": {"name__icontains": "acme"}, "read": true},
 "users": {"list": true, "read": true, "update": true}}
```

Users hold roles by id in their `roles` field. On every request the runtime
loads the held roles, adds each role's name to the actor (so grants declared in
code for that name apply too) and merges its access map into the resources it
names, with union semantics: any role that grants an operation grants it, and
conditions are OR-ed with each other and with the code's row filters. A model
that declares no grants is open to every signed-in user, so rules for it change
nothing. Built-in resources take only `true` or `false`. Maps are validated when
saved; `OPTIONS /api/admin/roles/` lists the resources rules may name under the
`permissions` field, marking which accept conditions.

Superusers, and holders of a role whose map grants those operations on `roles`
and `users`, create, edit and delete roles, add and remove users (removing
one ends their sessions and sign-in identities; nobody removes themselves), and
set the `roles` (and `name`) of users; deleting a role removes it from every user. `dashboards` and `views`
(the admin's saved pages) are written the same way. Everything else built in
remains read-only. Role names must be unique; `*` and `authenticated` are
reserved. Role entries on a user that are not record ids are still treated as
role names, so applications that assigned roles by name keep working.

`registry.migrate` provisions a managed **Admin** role granting every
operation on every resource, users included and keeps its map in
step with the registered models; its name is fixed. A superuser who signs in
holds it, so the owner's own record shows and carries full access from the
first sign-in. Make other roles for narrower access.

Signing in with Google also fills a person's `photo` — Google's profile picture
URL — when they have none yet; a photo already set is kept. Users carry it as a
read-only `image upload` field, and `/api/admin/users/me/` returns it so the
admin shows it as the account avatar.

Signing out with `/api/logout/?next=<page>` sends the browser to `/api/login/`
remembering that page — a path on this app, an absolute URL on its origin, or
the login URL an admin wraps it in — and the sign-in that follows, by email
link or Google, returns there. Pages elsewhere and API pages are ignored.

Relations appear in metadata as `one`/`many` fields with `related` naming the
resource when the actor may list it, and as plain `uuid` fields otherwise.
`include[]=<relation>.*` on a list or detail request sideloads the related
records under the related resource's name (only those the actor may read), so
an admin can show names instead of ids.

`.label(field, text)` and `.describe(field, text)` set the heading and help text
the admin shows for a field; without a label it title-cases the field name, and
without a description it shows none. `.metadata(json!({"section": ""}))` keeps a
model out of the navigation drawer while leaving it routable and linkable — the
built-in identities, identity verifications, dashboards and views ship that way,
so only users, roles and providers are listed by default.

Relationships use `.relation("supplier", "suppliers")`; `.required("supplier")`
makes the reference mandatory. `.relations("backup_suppliers", "suppliers")`
holds a list of ids instead (a `many` field in metadata): every id must name an
existing, readable record, the admin lists them as links on the detail page and
edits them with a search box, and `include[]=backup_suppliers.*` sideloads them
like a single relation. `GET /api/admin/orders/UUID/backup_suppliers/` (or
`/supplier/`) pages through the records a relation points at, in the record's
order, under the related resource's name. A referenced record must exist and be
readable. Deleting referenced records fails, including records listed in a
many-relation.

`.icon("truck")` names the Material Design icon (without the `mdi-` prefix) the
admin shows for a model in the navigation drawer, on its pages, and on every
field of another model that references it, so a `borrower` relation carries the
borrower model's icon rather than a generic one. Without it the admin uses
`table`. Unique field combinations reject duplicates.
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
