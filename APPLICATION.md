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
(the admin's saved pages) are written the same way. So are `providers`: a
role granting their operations adds one by hand with a `name`, a `kind` and
`enabled`, edits and removes it; anything else stored on the record stays
private and unchanged. Providers the app's code registers (see
[Calling outside services](#calling-outside-services)) can be renamed but keep
their kind and cannot be removed. Everything else built in remains read-only. Role names must be unique; `*` and `authenticated` are
reserved. Role entries on a user that are not record ids are still treated as
role names, so applications that assigned roles by name keep working.

`registry.migrate` provisions a managed **Admin** role granting every
operation on every resource, users and providers included, and every action;
its name is fixed. A superuser who signs in holds it, so the owner's own record
shows and carries full access from the first sign-in. The owner may narrow it
like any other role and that choice lasts: later releases grant it only what
the app gained since — a new model, action or built-in resource — once. A role
still holding the earlier defaults (providers read-only, no actions) is brought
up to date once; one an owner had customised is left alone. Make other roles
for narrower access.

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
`{"id":"UUID","data":{...request JSON...}}` (an empty body is `{}`). The
runtime checks action roles and record visibility before invoking it. Context
mutations continue to enforce model permissions. `context.connection` is the
current app-scoped SQL connection for advanced transactional operations; code
using raw SQL must enforce its own rules.

The admin shows each action a person may run as a button on the record page.
`registry.describe_action` says how, after the action is registered:

```rust
registry.action("orders", "reject", &["approver"], Reject)?;
registry.describe_action("orders", "reject", json!({
    "label": "Reject", "icon": "close-circle-outline",
    "description": "Send the order back to its requester.",
    "confirm": "Reject this order?",
    "when": {"state__in": ["submitted"]},
    "parameters": {"reason": {"type": "string", "required": true, "label": "Reason"}}
}))?;
```

`when` holds lookups on the record's own fields — `field` (equals),
`field__in` (a list) and `field__isnull` (a boolean). The admin shows the button
only on matching records, and the runtime answers 409 for any other record, so a
handler need not re-check them. `parameters` makes the admin ask for input in a
dialog before running the action; the values arrive in `data`. A parameter's
`type` is a field kind (`string`, `integer`, `decimal`, `money`, `boolean`,
`date`, `datetime`, `email`, ...), with optional `label`, `description`,
`required` (enforced: missing or blank answers 400) and `choices` (values, or
`{"id", "label"}` objects). `confirm` asks before running an action without
parameters. A handler's JSON result is returned to the caller; return the
updated record (`ctx.get(...)`) so the admin shows its new state.

Who may run an action comes from two places, with union semantics:

- **Code**: `&["approver"]` lets anyone holding a role named exactly `approver`
  — a stored role of that name included — run it on any record they can read.
  Superusers run every action.
- **Stored roles**: a role's access map may name the actions registered on a
  resource next to its operations, as `true` (every record) or a condition the
  record must meet: `{"purchase_orders": {"list": true, "read": true,
  "approve": {"approver": "$user.id"}}}` lets its holders approve the orders
  assigned to them and no others. Unknown action names are refused when the
  role is saved. The managed Admin role holds every action. The role editor
  lists each resource's actions under it (`OPTIONS /api/admin/roles/` reports
  them as `actions` on each resource under the `permissions` field), and a
  person sees an action's button only when one of these grants it.

Prefer stored-role grants for anything an administrator should be able to
change without a release.

Running an action is the permission it checks; the handler's writes are then
checked against the person's own grants. Workflow code that must change what
the person may not edit directly — an approver approving an order they may
only read, or a `state` field that is read-only for everyone — writes through
`ctx.elevated()`, the same transaction with the application's own authority:
it skips the actor's grants, row filters and read-only fields, but still runs
hooks, validation, references and uniqueness, and keeps `ctx.actor.id`:

```rust
ctx.elevated()
    .update("purchase_orders", id, json!({"state": "approved", "approved_by": ctx.actor.id}))
    .await?;
```

Use it only after the code has decided the change is allowed. Making workflow
fields such as `state`, totals and numbers `.readonly(...)` keeps people from
setting them through the record form or a PATCH, so the actions are the only
way to move a record through its states.

## Tasks

Register a `Handler` with `registry.task("send_receipt", SendReceipt)?`.
`context.enqueue("send_receipt", "receipt:UUID", payload).await?` persists work in
the same transaction as the triggering write. Repeating a key with different
input/actor is rejected. The task receives `task_id`, `idempotency_key` and `data`.
The actor's roles are loaded again at execution time.

Call `application::task_runner::drain(&app, budget).await?` from an IAM-only
scheduled Lambda (it runs due tasks one after another until none is due or the
budget has passed), or `tick(&app)` — one task — from a native loop. Claims
expire after 120s; handlers time out after 60s, retry with exponential backoff,
and stop after five attempts. Database effects and completion commit together.
External effects are at-least-once: pass the same idempotency key to the
external provider. This queue is for app business tasks, not a platform's
project/agent messages.

A task does not hold the application write lock until its first write through
the context, so calls to outside services made before it do not hold up the
app's users. Call `context.lock().await?` first when a later write depends on
what the task read, or before writing with raw SQL. Keep outside calls out of
hooks and actions — they run inside a user's request, which must finish within
the host's timeout — and queue a task for them instead.

## Calling outside services

`dynamic_rust::application::reqwest` is the HTTP client library, and
`context.http()` a shared client with 10 s connect and 25 s request timeouts —
no dependency to add. Use it from tasks.

Services that sign in with OAuth 2 (QuickBooks Online, Xero, Google, Slack, ...)
are registered as **integrations**:

```rust
use dynamic_rust::application::extensions::Integration;

registry.integration(
    Integration::oauth2("quickbooks", "QuickBooks Online")
        .describe("Two-way sync of vendors, accounts, purchase orders and bills.")
        .authorize_url("https://appcenter.intuit.com/connect/oauth2")
        .token_url("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer")
        .scopes(&["com.intuit.quickbooks.accounting"])
        .account_params(&["realmId"]),
)?;
```

Each registered integration is a record in the built-in `providers` resource
(`registry.migrate` adds it). An administrator — a superuser, or anyone whose
role grants `providers` `update` — opens it, enters the **client ID** and
**client secret** from the service's developer console, registers the record's
**redirect URI** (`https://<app>/api/integrations/<name>/callback`) there, and
presses **Connect**. After the service's consent page the record shows
`status` `connected`, when, and the `account` the service identified (the
callback parameters named in `account_params`, e.g. QuickBooks' `realmId`).
**Disconnect** drops the tokens. Changing the client ID or secret clears the
connection. Roles that grant only `providers` `list`/`read` see the status but
neither the buttons nor the credentials; nobody sees the secret or the tokens,
which live in a table no API returns. `.authorize_param(k, v)` adds query
parameters to the consent page (Google's `access_type=offline`), and
`.client_secret_in_body()` sends the credentials as form fields for services
that refuse HTTP Basic.

Code uses the connection from a task:

```rust
let books = context.integration("quickbooks").await?;
let realm = books.account["realmId"].as_str().unwrap_or_default();
let vendor: Value = books
    .get(&format!("https://quickbooks.api.intuit.com/v3/company/{realm}/vendor/58"))
    .header("accept", "application/json")
    .send().await.map_err(ApiError::internal)?
    .json().await.map_err(ApiError::internal)?;
```

`integration` refreshes the access token first when it expires within a minute
and keeps a rotated refresh token, committing that on its own so it survives
the task failing afterwards. When the service is not connected, is turned off
(`enabled` false), or refuses to refresh, it answers 409 with a message for
people, and the provider record's `status` becomes `error` with the reason, so
an administrator knows to connect it again. The connection belongs to the app,
not to the person whose action queued the task: decide in code who may start
work that uses it.

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
