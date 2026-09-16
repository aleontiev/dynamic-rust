#![allow(clippy::items_after_statements, clippy::map_unwrap_or)]
//! Registered, transaction-backed application extensions. All writes, hooks,
//! actions and task effects share a transaction. No cloud credentials are needed.
use super::DOCUMENT;
use crate::{
    AccessMap, AccessTargets, ApiError, Field, FieldKind, PermissionFilter, Principal,
    QueryFeatures, RelationLink, Resource,
};
use async_trait::async_trait;
pub use async_trait::async_trait as handler;
use serde_json::{Map, Value, json};
pub use sqlx;
use sqlx::{PgConnection, PgPool, Postgres, QueryBuilder};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Actor {
    pub id: String,
    pub roles: BTreeSet<String>,
    /// Bypasses model grants, row filters and action roles. Granted only to the
    /// application's configured superusers (`APP_SUPERUSER_EMAILS`), never from
    /// user data.
    pub is_superuser: bool,
    /// The access maps of the roles this user holds, keyed by role name. They
    /// are merged with the grants the code declares when a resource is resolved.
    pub access: BTreeMap<String, AccessMap>,
}
impl Actor {
    /// The actor for a user record before its stored roles are resolved: the
    /// role entries that are not record ids are taken as role names, which is
    /// how applications assigned roles before roles became records.
    pub fn from_user(user: &Value) -> Self {
        let mut roles: BTreeSet<String> = stored_roles(user)
            .filter(|role| Uuid::parse_str(role).is_err())
            .map(str::to_owned)
            .collect();
        roles.insert("authenticated".into());
        Self {
            id: user["id"].as_str().unwrap_or_default().into(),
            roles,
            is_superuser: false,
            access: BTreeMap::new(),
        }
    }
    /// The record ids among a user's stored roles.
    #[must_use]
    pub fn role_ids(user: &Value) -> Vec<Uuid> {
        stored_roles(user)
            .filter_map(|role| Uuid::parse_str(role).ok())
            .collect()
    }
    /// Hold a stored role: its name joins the actor's roles, so grants the code
    /// declares for that name apply, and its access map is merged at runtime.
    pub fn hold(&mut self, name: &str, access: AccessMap) {
        self.roles.insert(name.into());
        self.access.insert(name.into(), access);
    }
    /// Whether a held role grants an operation on a resource unconditionally.
    /// Built-in resources have no row filters, so this is their whole answer.
    #[must_use]
    pub fn granted(&self, resource: &str, operation: &str) -> bool {
        self.is_superuser
            || self.access.values().any(|map| {
                map.get(resource)
                    .and_then(|rules| rules.get(operation))
                    .is_some_and(|rule| matches!(rule, PermissionFilter::All))
            })
    }
    /// The actor for a user, marked as a superuser when that user's verified
    /// email is one of `superusers` (case-insensitive).
    #[must_use]
    pub fn for_user(user: &Value, superusers: &BTreeSet<String>) -> Self {
        let mut actor = Self::from_user(user);
        actor.is_superuser = user["email"]
            .as_str()
            .is_some_and(|email| superusers.contains(&email.trim().to_ascii_lowercase()));
        actor
    }
    #[must_use]
    pub fn principal(&self) -> Principal<'_> {
        Principal {
            id: &self.id,
            roles: &self.roles,
            is_superuser: self.is_superuser,
        }
    }
    #[must_use]
    pub fn may_run(&self, action: &Action) -> bool {
        self.is_superuser || action.roles.contains("*") || !action.roles.is_disjoint(&self.roles)
    }
}

/// A user's stored roles, from either the public record (`roles`) or the raw
/// document (`data.roles`).
fn stored_roles(user: &Value) -> impl Iterator<Item = &str> {
    let roles = &user["roles"];
    if roles.is_array() {
        roles
    } else {
        &user["data"]["roles"]
    }
    .as_array()
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
}

#[async_trait]
pub trait Hook: Send + Sync {
    async fn before(
        &self,
        _context: &mut Context<'_>,
        _operation: &str,
        _previous: Option<&Value>,
        _record: &mut Value,
    ) -> Result<(), ApiError> {
        Ok(())
    }
    async fn after(
        &self,
        _context: &mut Context<'_>,
        _operation: &str,
        _previous: Option<&Value>,
        _record: &Value,
    ) -> Result<(), ApiError> {
        Ok(())
    }
}
#[async_trait]
pub trait Handler: Send + Sync {
    async fn run(&self, context: &mut Context<'_>, input: Value) -> Result<Value, ApiError>;
}

#[derive(Clone)]
#[must_use]
pub struct Model {
    pub resource: Resource,
    pub hook: Option<Arc<dyn Hook>>,
    /// Unique field combinations; enforced inside the application write lock.
    pub unique: Vec<Vec<String>>,
}
impl Model {
    pub fn new(plural: &str, singular: &str) -> Self {
        let resource = Resource {
            namespace: "admin".into(),
            name: singular.into(),
            plural_name: plural.into(),
            table: "app_records".into(),
            id_field: "id".into(),
            fields: vec![],
            actions: vec![],
            metadata_actions: vec![],
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "PATCH".into(),
                "DELETE".into(),
            ],
            permission_classes: vec!["IsAuthenticated".into()],
            role_grants: BTreeMap::from([("*".into(), vec![])]),
            role_filters: BTreeMap::new(),
            effective_row_filter: None,
            row_actor_id: None,
            role_order: vec!["*".into()],
            role_field_overrides: BTreeMap::new(),
            list_fields: Some(vec!["name".into(), "created".into()]),
            default_sort: vec![],
            metadata: None,
        };
        Self {
            resource,
            hook: None,
            unique: vec![],
        }
        .field("id", FieldKind::Uuid)
        .readonly("id")
        .field("created", FieldKind::DateTime)
        .readonly("created")
        .field("updated", FieldKind::DateTime)
        .readonly("updated")
    }
    pub fn field(mut self, name: &str, kind: FieldKind) -> Self {
        self.resource.fields.push(Field {
            name: name.into(),
            label: None,
            description: None,
            source: name.into(),
            column: Some(name.into()),
            kind,
            required: false,
            read_only: false,
            write_only: false,
            deferred: false,
            nullable: true,
            many: false,
            immutable: false,
            only_update: false,
            create: None,
            creator: false,
            decimal_places: None,
            related_table: None,
            related_pk_column: None,
            reverse_column: None,
            through_table: None,
            through_source_column: None,
            through_target_column: None,
            related_resource: None,
            relation_order: vec![],
            link: RelationLink::Default,
        });
        self
    }
    pub fn required(mut self, name: &str) -> Self {
        if let Some(f) = self.resource.fields.iter_mut().find(|f| f.name == name) {
            f.required = true;
            f.nullable = false;
        }
        self
    }
    /// Human-readable name for a field, shown as the column heading and form
    /// label. Without one the admin title-cases the field name.
    pub fn label(mut self, name: &str, label: &str) -> Self {
        if let Some(f) = self.resource.fields.iter_mut().find(|f| f.name == name) {
            f.label = Some(label.into());
        }
        self
    }
    /// One-sentence explanation of what a field holds, shown as help text in
    /// the admin and returned in the resource's OPTIONS document.
    pub fn describe(mut self, name: &str, description: &str) -> Self {
        if let Some(f) = self.resource.fields.iter_mut().find(|f| f.name == name) {
            f.description = Some(description.into());
        }
        self
    }
    pub fn readonly(mut self, name: &str) -> Self {
        if let Some(f) = self.resource.fields.iter_mut().find(|f| f.name == name) {
            f.read_only = true;
        }
        self
    }
    pub fn relation(mut self, name: &str, target: &str) -> Self {
        self = self.field(name, FieldKind::Relation);
        if let Some(field) = self.resource.fields.last_mut() {
            field.related_resource = Some(target.into());
        }
        self
    }
    pub fn grant(mut self, role: &str, operations: &[&str]) -> Self {
        self.resource.role_grants.insert(
            role.into(),
            operations.iter().map(|s| (*s).into()).collect(),
        );
        if !self.resource.role_order.iter().any(|r| r == role) {
            self.resource.role_order.push(role.into());
        }
        self
    }
    pub fn unique(mut self, fields: &[&str]) -> Self {
        self.unique
            .push(fields.iter().map(|s| (*s).into()).collect());
        self
    }
    pub fn hook(mut self, hook: impl Hook + 'static) -> Self {
        self.hook = Some(Arc::new(hook));
        self
    }
    pub fn metadata(mut self, metadata: Value) -> Self {
        self.resource.metadata = Some(metadata);
        self
    }
}

#[derive(Clone)]
pub struct Action {
    pub roles: BTreeSet<String>,
    pub handler: Arc<dyn Handler>,
}
#[derive(Clone, Default)]
pub struct Registry {
    pub models: BTreeMap<String, Model>,
    pub actions: BTreeMap<(String, String), Action>,
    pub tasks: BTreeMap<String, Arc<dyn Handler>>,
    pub migrations: BTreeMap<String, String>,
}
impl Registry {
    /// A model's resource with the actor's stored roles merged into its grants.
    #[must_use]
    pub fn resource_for(&self, kind: &str, actor: &Actor) -> Option<Resource> {
        let model = self.models.get(kind)?;
        let mut resource = model.resource.clone();
        for (role, access) in &actor.access {
            if let Some(rules) = access.get(kind) {
                crate::grant_access(&mut resource, role, rules);
            }
        }
        Some(resource)
    }
    /// What an access map may name: every registered model with its fields.
    /// The application adds its built-in resources, which take only booleans.
    #[must_use]
    pub fn access_targets(&self) -> AccessTargets {
        self.models
            .iter()
            .map(|(name, model)| {
                (
                    name.clone(),
                    Some(
                        model
                            .resource
                            .fields
                            .iter()
                            .map(|f| f.name.clone())
                            .collect(),
                    ),
                )
            })
            .collect()
    }
    /// Register a model. Rejects reserved/duplicate names, invalid fields and invalid unique constraints.
    ///
    /// # Errors
    /// Rejects reserved/duplicate names, invalid fields and invalid unique constraints.
    pub fn model(&mut self, model: Model) -> Result<(), ApiError> {
        let name = &model.resource.plural_name;
        if !identifier(name)
            || super::KINDS.contains(&name.as_str())
            || self.models.contains_key(name)
        {
            return Err(ApiError::Parse(format!(
                "Invalid, reserved or duplicate model: {name}"
            )));
        }
        let mut seen = BTreeSet::new();
        for field in &model.resource.fields {
            if !identifier(&field.name) || !seen.insert(&field.name) {
                return Err(ApiError::Parse("Invalid or duplicate field".into()));
            }
        }
        for group in &model.unique {
            if group.is_empty()
                || group
                    .iter()
                    .any(|field| model.resource.field(field).is_none())
            {
                return Err(ApiError::Parse(
                    "Unique constraints must name registered fields".into(),
                ));
            }
        }
        self.models.insert(name.clone(), model);
        Ok(())
    }
    /// Register a record action. Rejects missing models and invalid/duplicate action names.
    ///
    /// # Errors
    /// Rejects missing models and invalid/duplicate action names.
    pub fn action(
        &mut self,
        model: &str,
        name: &str,
        roles: &[&str],
        handler: impl Handler + 'static,
    ) -> Result<(), ApiError> {
        let key = (model.into(), name.into());
        if !self.models.contains_key(model) || !identifier(name) || self.actions.contains_key(&key)
        {
            return Err(ApiError::Parse("Invalid or duplicate action".into()));
        }
        self.actions.insert(
            key,
            Action {
                roles: roles.iter().map(|s| (*s).into()).collect(),
                handler: Arc::new(handler),
            },
        );
        Ok(())
    }
    /// Register a durable handler. Rejects invalid or duplicate task names.
    ///
    /// # Errors
    /// Rejects invalid or duplicate task names.
    pub fn task(&mut self, name: &str, handler: impl Handler + 'static) -> Result<(), ApiError> {
        if !identifier(name) || self.tasks.contains_key(name) {
            return Err(ApiError::Parse("Invalid or duplicate task".into()));
        }
        self.tasks.insert(name.into(), Arc::new(handler));
        Ok(())
    }
    /// Register an ordered, append-only SQL migration. Rejects invalid or duplicate migration names.
    ///
    /// # Errors
    /// Rejects invalid or duplicate migration names.
    pub fn migration(&mut self, name: &str, sql: &str) -> Result<(), ApiError> {
        if !identifier(name) || self.migrations.contains_key(name) {
            return Err(ApiError::Parse("Invalid or duplicate migration".into()));
        }
        self.migrations.insert(name.into(), sql.into());
        Ok(())
    }
    /// Apply migrations atomically using the app database role. Fails on SQL errors or changed previously applied migrations.
    ///
    /// # Errors
    /// Fails on SQL errors or changed previously applied migrations.
    pub async fn migrate(&self, pool: &PgPool) -> Result<(), ApiError> {
        let mut tx = pool.begin().await.map_err(ApiError::internal)?;
        lock(&mut tx).await?;
        sqlx::raw_sql(include_str!("templates/app-schema.sql"))
            .execute(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
        sqlx::raw_sql(include_str!("templates/extensions.sql"))
            .execute(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
        super::core::ensure_admin_role(&mut tx, self.models.keys().cloned()).await?;
        for (name, sql) in &self.migrations {
            let digest = super::hash(sql);
            let prior: Option<String> =
                sqlx::query_scalar("SELECT digest FROM app_migrations WHERE name=$1")
                    .bind(name)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(ApiError::internal)?;
            if let Some(prior) = prior {
                if prior != digest {
                    return Err(ApiError::Conflict(format!(
                        "Applied migration changed: {name}"
                    )));
                }
                continue;
            }
            sqlx::raw_sql(sql)
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
            sqlx::query("INSERT INTO app_migrations(name,digest) VALUES($1,$2)")
                .bind(name)
                .bind(digest)
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
        }
        tx.commit().await.map_err(ApiError::internal)
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && value.as_bytes()[0].is_ascii_lowercase()
}
/// Serialize a transaction against other application writes. Returns database errors.
///
/// # Errors
/// Returns database errors.
pub async fn lock(conn: &mut PgConnection) -> Result<(), ApiError> {
    // Transactions involving several models (e.g. a receipt and inventory) are
    // serialized per app database. This also fences uniqueness and references.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(current_database() || ':dynamic-app-writes',0))").execute(conn).await.map_err(ApiError::internal)?;
    Ok(())
}

pub struct Context<'a> {
    pub connection: &'a mut PgConnection,
    pub registry: &'a Registry,
    pub actor: Actor,
    depth: usize,
}
impl<'a> Context<'a> {
    pub fn new(connection: &'a mut PgConnection, registry: &'a Registry, actor: Actor) -> Self {
        Self {
            connection,
            registry,
            actor,
            depth: 0,
        }
    }
    fn effective(&self, kind: &str, operation: &str) -> Result<Resource, ApiError> {
        let resource = self
            .registry
            .resource_for(kind, &self.actor)
            .ok_or(ApiError::NotFound)?;
        if !crate::operation_granted(&resource, Some(self.actor.principal()), operation, true) {
            return Err(ApiError::Forbidden);
        }
        let method = match operation {
            "create" => "POST",
            "update" => "PATCH",
            "delete" => "DELETE",
            _ => "GET",
        };
        Ok(crate::resource_for_principal_operation(
            &resource,
            Some(self.actor.principal()),
            method,
            operation,
        ))
    }
    /// Read a visible record. Rejects missing records, missing permissions and database failures.
    ///
    /// # Errors
    /// Rejects missing records, missing permissions and database failures.
    pub async fn get(&mut self, kind: &str, id: Uuid) -> Result<Value, ApiError> {
        let resource = self.effective(kind, "read")?;
        let mut query = QueryBuilder::<Postgres>::new(format!(
            "SELECT {DOCUMENT} FROM app_records WHERE kind="
        ));
        query
            .push_bind(kind.to_owned())
            .push(" AND id=")
            .push_bind(id);
        row_filter(&mut query, &resource)?;
        let row: Value = query
            .build_query_scalar()
            .fetch_optional(&mut *self.connection)
            .await
            .map_err(ApiError::internal)?
            .ok_or(ApiError::NotFound)?;
        Ok(output(&resource, row))
    }
    /// Read a permission-filtered page. Rejects unsupported queries, missing permissions and database failures.
    ///
    /// # Errors
    /// Rejects unsupported queries, missing permissions and database failures.
    pub async fn list(
        &mut self,
        kind: &str,
        features: &QueryFeatures,
    ) -> Result<(Vec<Value>, u64), ApiError> {
        let resource = self.effective(kind, "list")?;
        let mut count =
            QueryBuilder::<Postgres>::new("SELECT count(*) FROM app_records WHERE kind=");
        count.push_bind(kind.to_owned());
        query_filters(&mut count, &resource, features)?;
        let total: i64 = count
            .build_query_scalar()
            .fetch_one(&mut *self.connection)
            .await
            .map_err(ApiError::internal)?;
        let mut query = QueryBuilder::<Postgres>::new(format!(
            "SELECT {DOCUMENT} FROM app_records WHERE kind="
        ));
        query.push_bind(kind.to_owned());
        query_filters(&mut query, &resource, features)?;
        query.push(" ORDER BY ");
        for sort in &features.sort {
            expression(&mut query, &resource, &sort.field)?;
            query.push(if sort.descending { " DESC," } else { " ASC," });
        }
        query
            .push("created,id LIMIT ")
            .push_bind(i64::from(features.per_page))
            .push(" OFFSET ")
            .push_bind(i64::from(features.page.saturating_sub(1)) * i64::from(features.per_page));
        let rows: Vec<Value> = query
            .build_query_scalar()
            .fetch_all(&mut *self.connection)
            .await
            .map_err(ApiError::internal)?;
        Ok((
            rows.into_iter().map(|row| output(&resource, row)).collect(),
            u64::try_from(total).map_err(ApiError::internal)?,
        ))
    }
    /// Create a validated record and run hooks. Returns validation, permission, conflict or database errors; the caller must roll back on error.
    ///
    /// # Errors
    /// Returns validation, permission, conflict or database errors; the caller must roll back on error.
    pub async fn create(&mut self, kind: &str, input: Value) -> Result<Value, ApiError> {
        self.write(kind, None, input, "create").await
    }
    /// Patch a visible record and run hooks. Returns validation, permission, conflict or database errors; the caller must roll back on error.
    ///
    /// # Errors
    /// Returns validation, permission, conflict or database errors; the caller must roll back on error.
    pub async fn update(&mut self, kind: &str, id: Uuid, input: Value) -> Result<Value, ApiError> {
        self.write(kind, Some(id), input, "update").await
    }
    /// Delete a visible, unreferenced record and run hooks. Returns validation, permission, conflict or database errors; the caller must roll back on error.
    ///
    /// # Errors
    /// Returns validation, permission, conflict or database errors; the caller must roll back on error.
    pub async fn delete(&mut self, kind: &str, id: Uuid) -> Result<Value, ApiError> {
        self.write(kind, Some(id), json!({}), "delete").await
    }
    fn write<'b>(
        &'b mut self,
        kind: &'b str,
        id: Option<Uuid>,
        input: Value,
        operation: &'b str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, ApiError>> + Send + 'b>>
    {
        Box::pin(async move {
            if self.depth >= 16 {
                return Err(ApiError::Parse("Recursive hook limit exceeded".into()));
            }
            let resource = self.effective(kind, operation)?;
            let model = self.registry.models.get(kind).unwrap().clone();
            let id = id.unwrap_or_else(Uuid::new_v4);
            let previous = if operation == "create" {
                None
            } else {
                let mut query = QueryBuilder::<Postgres>::new(format!(
                    "SELECT {DOCUMENT} FROM app_records WHERE kind="
                ));
                query
                    .push_bind(kind.to_owned())
                    .push(" AND id=")
                    .push_bind(id);
                row_filter(&mut query, &resource)?;
                Some(
                    query
                        .build_query_scalar::<Value>()
                        .fetch_optional(&mut *self.connection)
                        .await
                        .map_err(ApiError::internal)?
                        .ok_or(ApiError::NotFound)?,
                )
            };
            let mut record = previous.clone().unwrap_or_else(|| json!({"id":id}));
            if operation != "delete" {
                let method = if operation == "create" {
                    "POST"
                } else {
                    "PATCH"
                };
                let patch = resource.validate_input_for(input, method)?;
                record.as_object_mut().unwrap().extend(patch);
            }
            let savepoint = format!("dynamic_write_{}", self.depth);
            sqlx::query(&format!("SAVEPOINT {savepoint}"))
                .execute(&mut *self.connection)
                .await
                .map_err(ApiError::internal)?;
            self.depth += 1;
            let result=async {
                if let Some(hook)=&model.hook { hook.before(self,operation,previous.as_ref(),&mut record).await?; }
                if record["id"]!=json!(id) { return Err(ApiError::Parse("Hooks cannot change record identity".into())); }
                if operation=="delete" {
                    for related in self.registry.models.values() {
                        for field in &related.resource.fields {
                            if field.related_resource.as_deref()==Some(kind) {
                                let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_records WHERE kind=$1 AND data->>$2=$3)").bind(&related.resource.plural_name).bind(&field.name).bind(id.to_string()).fetch_one(&mut *self.connection).await.map_err(ApiError::internal)?;
                                if used { return Err(ApiError::Conflict("This record is still referenced".into())); }
                            }
                        }
                    }
                    sqlx::query("DELETE FROM app_records WHERE kind=$1 AND id=$2").bind(kind).bind(id).execute(&mut *self.connection).await.map_err(ApiError::internal)?;
                } else {
                    validate_record(self,&model,&record).await?;
                    // Check proposed ownership as well as existing ownership.
                    // Role filters cannot be bypassed by reassigning a row.
                    check_proposed_scope(&resource,&record)?;
                    let mut data=record.clone();
                    for reserved in ["id","created","updated"] { data.as_object_mut().unwrap().remove(reserved); }
                    record=sqlx::query_scalar(&format!("INSERT INTO app_records(id,kind,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,updated=now() RETURNING {DOCUMENT}")).bind(id).bind(kind).bind(data).fetch_one(&mut *self.connection).await.map_err(ApiError::internal)?;
                }
                if let Some(hook)=&model.hook { hook.after(self,operation,previous.as_ref(),&record).await?; }
                Ok(output(&resource,record))
            }.await;
            self.depth -= 1;
            if result.is_err() {
                sqlx::query(&format!("ROLLBACK TO SAVEPOINT {savepoint}"))
                    .execute(&mut *self.connection)
                    .await
                    .map_err(ApiError::internal)?;
            }
            sqlx::query(&format!("RELEASE SAVEPOINT {savepoint}"))
                .execute(&mut *self.connection)
                .await
                .map_err(ApiError::internal)?;
            result
        })
    }
    /// Queue work atomically with the current write. Rejects unknown handlers, invalid keys, reused keys with different input, or database failures.
    ///
    /// # Errors
    /// Rejects unknown handlers, invalid keys, reused keys with different input, or database failures.
    pub async fn enqueue(&mut self, task: &str, key: &str, input: Value) -> Result<Uuid, ApiError> {
        if !self.registry.tasks.contains_key(task) || key.is_empty() || key.len() > 200 {
            return Err(ApiError::Parse(
                "Use a registered task and an idempotency key up to 200 characters".into(),
            ));
        }
        sqlx::query_scalar("INSERT INTO app_tasks(id,name,idempotency_key,input,actor) VALUES($1,$2,$3,$4,$5) ON CONFLICT(name,idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key WHERE app_tasks.input=EXCLUDED.input AND app_tasks.actor=EXCLUDED.actor RETURNING id")
            .bind(Uuid::new_v4()).bind(task).bind(key).bind(input).bind(json!({"id":self.actor.id})).fetch_optional(&mut *self.connection).await.map_err(ApiError::internal)?.ok_or_else(|| ApiError::Conflict("Idempotency key already belongs to different task input or actor".into()))
    }
}
fn output(resource: &Resource, mut value: Value) -> Value {
    value
        .as_object_mut()
        .unwrap()
        .retain(|name, _| resource.field(name).is_some_and(|f| !f.write_only));
    value
}
async fn validate_record(
    context: &mut Context<'_>,
    model: &Model,
    record: &Value,
) -> Result<(), ApiError> {
    let object = record
        .as_object()
        .ok_or_else(|| ApiError::Parse("Expected record object".into()))?;
    for name in object.keys() {
        if model.resource.field(name).is_none() {
            return Err(ApiError::Parse(format!("Unregistered field: {name}")));
        }
    }
    for field in &model.resource.fields {
        if ["id", "created", "updated"].contains(&field.name.as_str()) {
            continue;
        }
        let value = &record[&field.name];
        if value.is_null() {
            if field.required || (!field.nullable && object.contains_key(&field.name)) {
                return Err(ApiError::Parse(format!("Field required: {}", field.name)));
            }
            continue;
        }
        let valid = match field.kind {
            FieldKind::Boolean => value.is_boolean(),
            FieldKind::Integer => value.as_i64().is_some(),
            FieldKind::Float | FieldKind::Decimal | FieldKind::Money => {
                value.as_f64().is_some_and(f64::is_finite)
            }
            FieldKind::Uuid | FieldKind::Relation => {
                value.as_str().is_some_and(|s| Uuid::parse_str(s).is_ok())
            }
            FieldKind::Json => true,
            _ => value.is_string(),
        };
        if !valid {
            return Err(ApiError::Parse(format!("Invalid value for {}", field.name)));
        }
        if let Some(target) = &field.related_resource {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind=$1 AND id=$2)",
            )
            .bind(target)
            .bind(Uuid::parse_str(value.as_str().unwrap()).map_err(ApiError::internal)?)
            .fetch_one(&mut *context.connection)
            .await
            .map_err(ApiError::internal)?;
            if !exists {
                return Err(ApiError::Parse(format!(
                    "Unknown related record: {}",
                    field.name
                )));
            }
            // Referencing a record does not grant access to a hidden row.
            if context.registry.models.contains_key(target) {
                context
                    .get(target, Uuid::parse_str(value.as_str().unwrap()).unwrap())
                    .await?;
            }
        }
    }
    for unique in &model.unique {
        if unique.iter().any(|field| record[field].is_null()) {
            continue;
        }
        let mut query =
            QueryBuilder::<Postgres>::new("SELECT EXISTS(SELECT 1 FROM app_records WHERE kind=");
        query
            .push_bind(model.resource.plural_name.clone())
            .push(" AND id<>")
            .push_bind(Uuid::parse_str(record["id"].as_str().unwrap()).unwrap());
        for field in unique {
            query
                .push(" AND data->")
                .push_bind(field.clone())
                .push(" = ")
                .push_bind(record[field].clone());
        }
        query.push(")");
        if query
            .build_query_scalar::<bool>()
            .fetch_one(&mut *context.connection)
            .await
            .map_err(ApiError::internal)?
        {
            return Err(ApiError::Conflict(format!(
                "Duplicate {}",
                unique.join(", ")
            )));
        }
    }
    Ok(())
}
fn expression(
    query: &mut QueryBuilder<'_, Postgres>,
    resource: &Resource,
    name: &str,
) -> Result<(), ApiError> {
    let field = resource
        .field(name)
        .ok_or_else(|| ApiError::Parse("Unknown filter/sort field".into()))?;
    if ["id", "created", "updated"].contains(&name) {
        query.push(format!("{name}::text"));
    } else {
        query.push("(data->>").push_bind(name.to_owned()).push(")");
        if matches!(
            field.kind,
            FieldKind::Integer | FieldKind::Decimal | FieldKind::Float | FieldKind::Money
        ) {
            query.push("::numeric");
        }
    }
    Ok(())
}
fn query_filters(
    query: &mut QueryBuilder<'_, Postgres>,
    resource: &Resource,
    features: &QueryFeatures,
) -> Result<(), ApiError> {
    row_filter(query, resource)?;
    for filter in &features.filters {
        if filter.field_reference || !filter.relation.is_empty() || filter.values.is_empty() {
            return Err(ApiError::Parse("Unsupported filter".into()));
        }
        let field = resource
            .field(&filter.field)
            .ok_or_else(|| ApiError::Parse("Unknown filter field".into()))?;
        if field.write_only {
            return Err(ApiError::Forbidden);
        }
        query.push(if filter.exclude {
            " AND NOT ("
        } else {
            " AND ("
        });
        if filter.operator == crate::FilterOperator::IsNull {
            let expected = crate::FilterOperator::null_expected(&filter.values[0])
                .ok_or_else(|| ApiError::Parse("isnull expects true/false or 1/0".into()))?;
            expression(query, resource, &filter.field)?;
            query.push(if expected { " IS NULL" } else { " IS NOT NULL" });
            query.push(")");
            continue;
        }
        for (i, value) in filter.values.iter().enumerate() {
            if i > 0 {
                query.push(" OR ");
            }
            expression(query, resource, &filter.field)?;
            use crate::FilterOperator as F;
            query.push(match filter.operator {
                F::Eq | F::In => " = ",
                F::Gt => " > ",
                F::Gte => " >= ",
                F::Lt => " < ",
                F::Lte => " <= ",
                F::IContains => " ILIKE ",
                _ => return Err(ApiError::Parse("Unsupported filter operator".into())),
            });
            if matches!(
                field.kind,
                FieldKind::Integer | FieldKind::Decimal | FieldKind::Float | FieldKind::Money
            ) {
                let value = value
                    .parse::<f64>()
                    .ok()
                    .filter(|v| v.is_finite())
                    .ok_or_else(|| ApiError::Parse("Expected numeric filter".into()))?;
                query.push_bind(value);
            } else if filter.operator == F::IContains {
                query.push_bind(format!(
                    "%{}%",
                    value
                        .replace('\\', "\\\\")
                        .replace('%', "\\%")
                        .replace('_', "\\_")
                ));
            } else {
                query.push_bind(value.clone());
            }
        }
        query.push(")");
    }
    Ok(())
}
fn row_filter(query: &mut QueryBuilder<'_, Postgres>, resource: &Resource) -> Result<(), ApiError> {
    if let Some(filter) = &resource.effective_row_filter {
        query.push(" AND (");
        predicate(query, resource, filter)?;
        query.push(")");
    }
    Ok(())
}
fn predicate(
    query: &mut QueryBuilder<'_, Postgres>,
    resource: &Resource,
    filter: &PermissionFilter,
) -> Result<(), ApiError> {
    match filter {
        PermissionFilter::All => {
            query.push("true");
        }
        PermissionFilter::None => {
            query.push("false");
        }
        PermissionFilter::Group {
            connector,
            negated,
            children,
        } => {
            if *negated {
                query.push("NOT ");
            }
            query.push("(");
            if children.is_empty() {
                query.push("false");
            }
            for (i, child) in children.iter().enumerate() {
                if i > 0 {
                    query.push(if connector.eq_ignore_ascii_case("or") {
                        " OR "
                    } else {
                        " AND "
                    });
                }
                predicate(query, resource, child)?;
            }
            query.push(")");
        }
        PermissionFilter::Condition { lookup, value } => {
            condition(query, resource, lookup, value)?;
        }
    }
    Ok(())
}
/// One row-permission comparison. Numeric fields compare as numbers (a value
/// that is not a number matches nothing), everything else as text; `in` is a
/// disjunction of comparisons and `icontains` a case-insensitive substring.
fn condition(
    query: &mut QueryBuilder<'_, Postgres>,
    resource: &Resource,
    lookup: &str,
    value: &Value,
) -> Result<(), ApiError> {
    let (name, operator) = crate::split_lookup(lookup);
    let field = resource
        .field(name)
        .ok_or_else(|| ApiError::Parse("Unknown row permission field".into()))?;
    let numeric = matches!(
        field.kind,
        FieldKind::Integer | FieldKind::Decimal | FieldKind::Float | FieldKind::Money
    ) && operator != "icontains";
    let column = |query: &mut QueryBuilder<'_, Postgres>| {
        if ["id", "created", "updated"].contains(&name) {
            query.push(format!("{name}::text"));
        } else {
            query.push("(data->>").push_bind(name.to_owned()).push(")");
            if numeric {
                query.push("::numeric");
            }
        }
    };
    if operator == "isnull" {
        column(query);
        query.push(if value.as_bool().unwrap_or(true) {
            " IS NULL"
        } else {
            " IS NOT NULL"
        });
        return Ok(());
    }
    let values: Vec<&Value> = if operator == "in" {
        value
            .as_array()
            .map(|items| items.iter().collect())
            .unwrap_or_default()
    } else {
        vec![value]
    };
    if values.is_empty() {
        query.push("false");
        return Ok(());
    }
    query.push("(");
    for (index, item) in values.iter().enumerate() {
        if index > 0 {
            query.push(" OR ");
        }
        let text = scope_value(item, resource);
        let comparison = match operator {
            "gt" => " > ",
            "gte" => " >= ",
            "lt" => " < ",
            "lte" => " <= ",
            "icontains" => " ILIKE ",
            _ => " = ",
        };
        if numeric {
            match text.trim().parse::<f64>().ok().filter(|v| v.is_finite()) {
                Some(number) => {
                    column(query);
                    query.push(comparison).push_bind(number);
                }
                None => {
                    query.push("false");
                }
            }
        } else if operator == "icontains" {
            column(query);
            query.push(comparison).push_bind(format!(
                "%{}%",
                text.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            ));
        } else {
            column(query);
            query.push(comparison).push_bind(text);
        }
    }
    query.push(")");
    Ok(())
}
fn scope_value(value: &Value, resource: &Resource) -> String {
    if value == "$user.id" {
        resource.row_actor_id.clone().unwrap_or_default()
    } else {
        value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned)
    }
}
fn check_proposed_scope(resource: &Resource, record: &Value) -> Result<(), ApiError> {
    fn matches(resource: &Resource, record: &Value, filter: &PermissionFilter) -> bool {
        match filter {
            PermissionFilter::All => true,
            PermissionFilter::None => false,
            PermissionFilter::Group {
                connector,
                negated,
                children,
            } => {
                let result = if connector.eq_ignore_ascii_case("or") {
                    children.iter().any(|c| matches(resource, record, c))
                } else {
                    !children.is_empty() && children.iter().all(|c| matches(resource, record, c))
                };
                result != *negated
            }
            PermissionFilter::Condition { lookup, value } => crate::condition_matches(
                record,
                lookup,
                value,
                resource.row_actor_id.as_deref().unwrap_or_default(),
            ),
        }
    }
    if resource
        .effective_row_filter
        .as_ref()
        .is_some_and(|f| !matches(resource, record, f))
    {
        Err(ApiError::Forbidden)
    } else {
        Ok(())
    }
}

pub fn metadata(model: &Model, actor: &Actor, registry: &Registry) -> Value {
    let resource = &registry
        .resource_for(&model.resource.plural_name, actor)
        .unwrap_or_else(|| model.resource.clone());
    let fields: Map<String,Value>=resource.fields.iter().map(|f| {
        // A relation is one the admin can follow only when the actor may list the
        // related resource; otherwise the field is just the id it holds.
        let visible=f.related_resource.as_deref().and_then(|related| registry.resource_for(related, actor)).is_some_and(|related| crate::operation_granted(&related, Some(actor.principal()), "list", true));
        let typ=match f.kind {FieldKind::DateTime=>json!("datetime"), FieldKind::Relation if visible=>json!(if f.many {"many"} else {"one"}), FieldKind::Relation=>json!("uuid"), _=>serde_json::to_value(&f.kind).unwrap_or(Value::Null)};
        let related=f.related_resource.clone().filter(|_| visible);
        (f.name.clone(),json!({"name":f.name,"label":f.label.clone().unwrap_or_else(||crate::python_title(&f.name.replace('_'," "))),"description":f.description,"type":typ,"read_only":f.read_only,"required":f.required,"nullable":f.nullable,"null":f.nullable,"many":f.many,"ui":true,"hidden":f.write_only,"deferred":f.deferred,"sortable":!f.write_only,"filterable":!f.write_only,"related":related,"related_resource":f.related_resource}))
    }).collect();
    let names: Vec<_> = resource
        .fields
        .iter()
        .filter(|f| !f.read_only && !f.write_only)
        .map(|f| f.name.clone())
        .collect();
    let mut value = json!({"type":"resource","name":resource.plural_name,"singular":resource.name,"singular_name":resource.name,"label":crate::python_title(&resource.plural_name.replace('_'," ")),"icon":"table","url":format!("/api/admin/{}/",resource.plural_name),"id_field":"id","name_field":"name","section":"App","fields":fields,"features":{"detail":true},"sections":[{"name":"details","label":"Details","fields":names}],"list_fields":resource.list_fields});
    if let Some(extra) = resource.metadata.as_ref().and_then(Value::as_object) {
        if let Some(object) = value.as_object_mut() {
            object.extend(extra.clone());
        }
    }
    let effective = crate::resource_metadata(resource, Some(actor.principal()));
    value["permissions"] = effective["permissions"].clone();
    value["actions"]=json!(registry.actions.iter().filter(|((kind,_),action)|kind==&resource.plural_name && actor.may_run(action)).map(|((_,name),_)|json!({"name":name,"label":crate::python_title(name),"methods":["POST"],"detail":true,"url":format!("/api/admin/{}/{{id}}/actions/{}/",resource.plural_name,name)})).collect::<Vec<_>>());
    value
}
