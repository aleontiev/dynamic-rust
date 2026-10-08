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
`permissions` field, marking which accept conditions, with each model's fields
and what the app declares about them.

Next to its operations, a role's rules for a model may say who sees and changes
which fields, as Dynamic REST serializers do: `read_only: false` lets the role
change a field the app declares read-only, `write_only: false` lets it see one
the app hides (`.write_only("salary")`), and `true` takes either away:

```json
{"staff": {"list": true, "read": true, "update": true,
           "fields": {"salary": {"write_only": false},
                      "grade": {"read_only": false},
                      "name": {"read_only": true}}}}
```

Across the roles a person holds that reach the model, a field is visible when
any of them may see it and changeable when any may change it — union
semantics, as with operations. Hidden fields are left out of what the API
returns and marked `hidden` in metadata; a read-only one is refused in writes.

An app ships its own roles with `registry.role(name, map)`:

```rust
registry.role("Approver", json!({
    "purchase_orders": {"list": {"approver": "$user.id"}, "read": {"approver": "$user.id"},
                        "approve": {"approver": "$user.id", "state": "submitted"}},
    "suppliers": {"list": true, "read": true}
}))?;
```

`registry.migrate` checks each map against the registered models, fields and
actions — a mistake fails the app's tests and its start instead of quietly
granting nothing — and creates the role when no role of that name exists.
Later releases update a shipped role's map only while it still holds the
defaults the app gave it; once an administrator changes the role, theirs
stays. Grants in code for the same name still apply; keep the rules people
should be able to adjust in the map.

Superusers, and holders of a role whose map grants those operations on `roles`
and `users`, create, edit and delete roles, add and remove users (removing
one ends their sessions and sign-in identities; nobody removes themselves), and
set the `roles` (and `name`) of users; deleting a role removes it from every user. `dashboards` and `views`
(the admin's saved pages) are written the same way. `providers` is a built-in
*model* rather than one of these (see
[Calling outside services](#calling-outside-services)): roles grant its
operations, actions and fields like any model's. Everything else built in
remains read-only. Role names must be unique; `*` and `authenticated` are
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

`registry.schedule("pull_vendors", Duration::from_secs(900))` runs a
registered task on its own every period (one minute to one week): `drain`
queues it once per period, keyed `schedule:<period number>`, with empty
`data`, and it runs as the app itself (`ctx.actor.is_superuser`, an empty
`ctx.actor.id`). A failed task keeps its handler's error message in
`app_tasks.error` while it is retried.

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

Every outside service the app talks to is registered as an **integration**,
whichever way it lets the app in. Services that sign in with OAuth 2 (most
accounting, payments, mail and workspace services) use `Integration::oauth2`:

```rust
use dynamic_rust::application::extensions::Integration;

registry.integration(
    Integration::oauth2("books", "Books Online")
        .describe("Two-way sync of vendors, accounts and bills.")
        .authorize_url("https://accounts.books.example/oauth2/authorize")
        .token_url("https://accounts.books.example/oauth2/token")
        .scopes(&["accounting"])
        .account_params(&["companyId"]),
)?;
```

Each registered integration is a record of the built-in `providers` model
(`registry.migrate` adds it, flagged `primary`). Providers are an ordinary
model: the API, filters, metadata and role rules work as for any other, roles
grant its `connect` and `disconnect` actions, and its field rules can hide or
open its fields to a role. Someone whose roles grant `providers` `update`
opens the record, enters the **client ID** and **client secret** from the
service's developer console, registers the record's **redirect URI**
(`https://<app>/api/integrations/<name>/callback`) there, and — holding
`connect` — presses **Connect**. After the service's consent page the record
shows `status` `connected`, when, and the `account` the service identified (the
callback parameters named in `account_params`). **Disconnect** drops the
tokens. Changing the client ID or secret clears the connection. The fields the
service owns (status, account, redirect URI, ...) are read-only; nobody sees
the secret or the tokens, which live in a table no API returns — the record
shows `Saved` in their place. Administrators may also add providers by hand (a
`name`, a `kind` and `enabled`) for the app's code to read; the ones the code
registers can be renamed but keep their kind and cannot be removed. `.authorize_param(k, v)` adds query
parameters to the consent page (Google's `access_type=offline`), and
`.client_secret_in_body()` sends the credentials as form fields for services
that refuse HTTP Basic.

Services that issue an API token (key) instead use `Integration::token`; an
administrator pastes the token into the provider record and presses
**Connect**, which requests the `check` path with it and marks the provider
`connected` only when the service answers 2xx (otherwise `error`, with the
service's answer). **Disconnect** forgets the token. The token is sent as
`Authorization: Bearer <token>` unless `.token_header` says otherwise:

```rust
registry.integration(
    Integration::token("ledger", "Ledger API")
        .describe("Pulls collections and pushes receipts.")
        .token_header("Authorization", "JWT {token}")
        .base_url("https://api.ledger.example")
        .stage_base_url("dev", "https://api.ledger.dev")
        .check("/v0/users/?per_page=1"),
)?;
```

Either kind may name where the service's API is: `.base_url` by default, and
`.stage_base_url(stage, url)` while the app runs as that stage (`APP_STAGE`:
`dev` or `production`; unset means `dev`). The provider record shows that
**Default Base URL**, and an administrator may enter a **Base URL** to use
another tenant, sandbox or server instead; changing a token provider's base URL
asks for Connect again.

Code uses the connection from a task:

```rust
let books = context.integration("books").await?;
let company = books.account["companyId"].as_str().unwrap_or_default();
let vendor: Value = books
    .get(&format!("/v1/companies/{company}/vendors/58"))
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

A connection's `base_url` is the record's Base URL or the integration's
default, and a path starting with `/` is requested under it, with the
credentials: `ledger.get("/v0/collections/?page=1")`, `ledger.post(...)`,
`.put`, `.patch` and `.delete`.

### One connection per record

An integration serves the whole app unless it says otherwise. To connect each
record of something on its own — each company or entity to its own books, each
person to their own account — add a relation to the providers model with
`registry.extend` and name it with `.per`:

```rust
registry.extend("providers", |providers| {
    providers
        .relation("entity", "entities")
        .label("entity", "Entity")
        .describe("entity", "The entity whose books this connection reaches.")
})?;
registry.integration(Integration::oauth2("books", "Books Online") /* ... */.per("entity"))?;

// In a task: the books of this entity, and no other's.
let books = context.integration_for("books", entity_id).await?;
```

Each record's connection is a `providers` record naming it in that field, added
under Providers (choose the service and the record) or by code with
`context.add_connection("books", entity_id)` — say from a hook when an entity is
created — which returns the existing one if there is one. A record has at most
one connection per service. OAuth connections sign in with the client ID and
secret saved on the service's `primary` provider, so each only needs
**Connect**; a token connection takes its own token, and its Base URL falls
back to the primary provider's. The primary provider may itself name a record.
`integration_for` answers 409 when the record has no connection or it is not
connected, never falling back to another record's. A record with a connection
cannot be deleted until the connection is, and deleting a connection deletes
its tokens.

For a person's own account, relate providers to `users` and let roles reach
only their own, with ordinary conditions:

```json
{"providers": {"list": {"user": "$user.id"}, "read": {"user": "$user.id"},
               "create": {"user": "$user.id"}, "update": {"user": "$user.id"},
               "connect": {"user": "$user.id"}, "disconnect": {"user": "$user.id"},
               "fields": {"base_url": {"write_only": true}}}}
```

Someone adding a connection to such a service who names nobody serves
themselves; code reaches it with `context.integration_for("ledger", user_id)`.
Removing a person removes their connections and tokens.

### Keeping records in step

A model whose records are kept in step with an outside service declares
`.external_id()`: a read-only, unique `external_id` field holding each record's
id in the service. People see it but cannot set it. To bring a record in, a task
calls `context.upsert_external("vendors", &remote_id, fields)`, which updates the
record with that `external_id` or creates it (as the app, read-only fields
included), so pulling the same record twice never duplicates it. To send a
record out, create it in the service, then save the id the service returns
with `context.elevated().update(kind, id, json!({"external_id": remote_id}))`;
a record with an `external_id` is updated in the service rather than created
again.

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
