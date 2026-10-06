//! Where registered models keep their records.
//!
//! [`Storage::Records`], the default, keeps every model's records as JSON
//! documents in the shared `app_records` table: a new field needs no
//! migration. [`Storage::Tables`] gives a model its own table named after it,
//! with a typed column per field, `NOT NULL` for required fields, foreign keys
//! for relations, a join table per many-relation and real unique indexes, so
//! the database itself holds the schema and plain SQL can report on it.
//!
//! A model's storage is recorded in its resource's `table`: `app_records`, or
//! the model's own table. Everything that reads or writes model records goes
//! through this module, so the rest of the runtime works with JSON documents of
//! either kind alike.
use super::{
    DOCUMENT,
    extensions::{Model, Registry},
};
use crate::{ApiError, Field, FieldKind, Resource};
use serde_json::{Value, json};
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// How a model keeps its records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Storage {
    /// JSON documents in the shared `app_records` table. Adding, removing or
    /// retyping a field needs no migration; the runtime checks types,
    /// relations and uniqueness itself.
    #[default]
    Records,
    /// A table per model (named after its plural) with a typed column per
    /// field: `NOT NULL` for required fields, foreign keys for relations, a
    /// join table per many-relation and unique indexes. `registry.migrate`
    /// creates the table and adds columns for new fields; a changed type or a
    /// removed field stops the migration until a `registry.migration` handles
    /// the data explicitly.
    Tables,
}

/// The shared table of [`Storage::Records`].
pub(super) const RECORDS: &str = "app_records";
/// What the runtime remembers of each table it manages.
const SCHEMA_TABLE: &str = "app_model_tables";

/// The `table` a resource names for a storage choice.
pub(super) fn table_for(storage: Storage, plural: &str) -> String {
    match storage {
        Storage::Records => RECORDS.into(),
        Storage::Tables => plural.into(),
    }
}
/// Whether a model's records live in a table of their own.
pub(super) fn in_table(resource: &Resource) -> bool {
    resource.table != RECORDS
}
fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}
fn reserved(name: &str) -> bool {
    ["id", "created", "updated"].contains(&name)
}
/// Postgres truncates names longer than 63 bytes; long ones end in a digest.
fn object_name(base: &str) -> String {
    if base.len() <= 63 {
        return base.to_owned();
    }
    let digest = super::hash(base);
    format!("{}_{}", &base[..50], &digest[..12])
}
/// The join table holding a many-relation's ids, in order.
pub(super) fn join_table(resource: &Resource, field: &str) -> String {
    format!("{}__{field}", resource.table)
}
/// The column type of a field in table storage.
fn column_type(field: &Field) -> &'static str {
    match field.kind {
        FieldKind::Boolean => "boolean",
        FieldKind::Date => "date",
        FieldKind::DateTime => "timestamp with time zone",
        FieldKind::Decimal | FieldKind::Money => "numeric",
        FieldKind::Float => "double precision",
        FieldKind::Integer => "bigint",
        FieldKind::Json => "jsonb",
        FieldKind::Time => "time without time zone",
        FieldKind::Relation | FieldKind::Uuid => "uuid",
        // Durations stay text: the API accepts any duration notation.
        FieldKind::Duration | FieldKind::Email | FieldKind::File | FieldKind::String => "text",
    }
}
fn numeric(field: &Field) -> bool {
    matches!(
        field.kind,
        FieldKind::Integer | FieldKind::Decimal | FieldKind::Float | FieldKind::Money
    )
}
/// The fields that are columns of a model's table.
fn columns(resource: &Resource) -> impl Iterator<Item = &Field> {
    resource
        .fields
        .iter()
        .filter(|field| !reserved(&field.name) && !field.many)
}
fn many(resource: &Resource) -> impl Iterator<Item = &Field> {
    resource.fields.iter().filter(|field| field.many)
}

/// A record as a JSON document, built from its table row: the declared fields
/// only, many-relations as id lists in their order.
fn document(resource: &Resource) -> String {
    let mut pairs: Vec<String> = ["id", "created", "updated"]
        .iter()
        .map(|name| format!("'{name}',t.{name}"))
        .collect();
    pairs.extend(
        columns(resource).map(|field| format!("'{}',t.{}", field.name, quote(&field.name))),
    );
    // jsonb_build_object takes at most 100 arguments.
    let mut parts: Vec<String> = pairs
        .chunks(40)
        .map(|chunk| format!("jsonb_build_object({})", chunk.join(",")))
        .collect();
    parts.extend(many(resource).map(|field| {
        format!(
            "jsonb_build_object('{}',coalesce((SELECT jsonb_agg(j.target ORDER BY j.position) FROM {} j WHERE j.record=t.id),'[]'::jsonb))",
            field.name,
            quote(&join_table(resource, &field.name))
        )
    }));
    format!("({})", parts.join("||"))
}

/// `SELECT <documents> FROM <this model's records> WHERE true`, ready for
/// further ` AND ...` conditions.
pub(super) fn select_documents<'a>(resource: &Resource) -> QueryBuilder<'a, Postgres> {
    if in_table(resource) {
        QueryBuilder::new(format!(
            "SELECT {} FROM {} AS t WHERE true",
            document(resource),
            quote(&resource.table)
        ))
    } else {
        let mut query = QueryBuilder::new(format!("SELECT {DOCUMENT} FROM {RECORDS} WHERE kind="));
        query.push_bind(resource.plural_name.clone());
        query
    }
}
/// `SELECT count(*) FROM <this model's records> WHERE true`.
pub(super) fn select_count<'a>(resource: &Resource) -> QueryBuilder<'a, Postgres> {
    if in_table(resource) {
        QueryBuilder::new(format!(
            "SELECT count(*) FROM {} AS t WHERE true",
            quote(&resource.table)
        ))
    } else {
        let mut query = QueryBuilder::new(format!("SELECT count(*) FROM {RECORDS} WHERE kind="));
        query.push_bind(resource.plural_name.clone());
        query
    }
}

/// A field's value in a query. `typed` compares numbers as numbers, and in
/// table storage dates and times as dates and times; otherwise the value is
/// text, as `icontains` and equality on text need.
pub(super) fn push_column(
    query: &mut QueryBuilder<'_, Postgres>,
    resource: &Resource,
    field: &Field,
    typed: bool,
) {
    let name = field.name.as_str();
    if reserved(name) {
        query.push(format!("{name}::text"));
    } else if in_table(resource) {
        if field.many {
            query.push(format!(
                "(SELECT jsonb_agg(j.target ORDER BY j.position) FROM {} j WHERE j.record=t.id)::text",
                quote(&join_table(resource, name))
            ));
        } else if typed && (numeric(field) || temporal(resource, field).is_some()) {
            query.push(quote(name));
        } else {
            query.push(format!("{}::text", quote(name)));
        }
    } else {
        query.push("(data->>").push_bind(name.to_owned()).push(")");
        if typed && numeric(field) {
            query.push("::numeric");
        }
    }
}
/// The SQL type a compared value is cast to, for a date or time in table storage.
fn temporal(resource: &Resource, field: &Field) -> Option<&'static str> {
    if !in_table(resource) || field.many {
        return None;
    }
    match field.kind {
        FieldKind::Date => Some("date"),
        FieldKind::DateTime => Some("timestamptz"),
        FieldKind::Time => Some("time"),
        _ => None,
    }
}
/// A text value compared with [`push_column`]'s typed form.
pub(super) fn push_value(
    query: &mut QueryBuilder<'_, Postgres>,
    resource: &Resource,
    field: &Field,
    value: String,
) {
    match temporal(resource, field) {
        Some(cast) => {
            query
                .push("CAST(")
                .push_bind(value)
                .push(format!(" AS {cast})"));
        }
        None => {
            query.push_bind(value);
        }
    }
}

/// Database refusals people can act on: a value of the wrong form, a duplicate,
/// a missing required value or a reference that does not hold.
pub(super) fn database_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database) = &error {
        let code = database.code().unwrap_or_default().to_string();
        let message = database.message().to_owned();
        if code.starts_with("22") {
            return ApiError::Parse(format!("Invalid value: {message}"));
        }
        match code.as_str() {
            "23505" => return ApiError::Conflict(format!("Duplicate value: {message}")),
            "23503" => {
                return ApiError::Conflict(format!(
                    "A related record is missing or still referenced: {message}"
                ));
            }
            "23502" => return ApiError::Parse(format!("Field required: {message}")),
            _ => {}
        }
    }
    ApiError::internal(error)
}

/// Write a complete record (its fields, without `id`, `created` and
/// `updated`) and return its stored document.
pub(super) async fn save(
    connection: &mut PgConnection,
    resource: &Resource,
    id: Uuid,
    data: &Value,
) -> Result<Value, ApiError> {
    if !in_table(resource) {
        return sqlx::query_scalar(&format!("INSERT INTO {RECORDS}(id,kind,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,updated=now() RETURNING {DOCUMENT}"))
            .bind(id)
            .bind(&resource.plural_name)
            .bind(data)
            .fetch_one(&mut *connection)
            .await
            .map_err(ApiError::internal);
    }
    let table = quote(&resource.table);
    let names: Vec<String> = columns(resource).map(|field| quote(&field.name)).collect();
    let mut sql = insert_columns(&table, "id", "$1", resource)
        + &format!(
            " FROM jsonb_populate_record(NULL::{table},$2) p ON CONFLICT(id) DO UPDATE SET "
        );
    if !names.is_empty() {
        let excluded: Vec<String> = names
            .iter()
            .map(|name| format!("EXCLUDED.{name}"))
            .collect();
        sql = sql + "(" + &names.join(",") + ")=ROW(" + &excluded.join(",") + "),";
    }
    sql.push_str("updated=now()");
    let mut row = data.clone();
    if let Some(object) = row.as_object_mut() {
        object.retain(|name, _| resource.field(name).is_some_and(|f| !f.many));
    }
    sqlx::query(&sql)
        .bind(id)
        .bind(&row)
        .execute(&mut *connection)
        .await
        .map_err(database_error)?;
    for field in many(resource) {
        let join = quote(&join_table(resource, &field.name));
        sqlx::query(&format!("DELETE FROM {join} WHERE record=$1"))
            .bind(id)
            .execute(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
        let ids = match &data[&field.name] {
            Value::Array(items) => Value::Array(items.clone()),
            _ => json!([]),
        };
        sqlx::query(&format!("INSERT INTO {join}(record,position,target) SELECT $1,a.position,a.value::uuid FROM jsonb_array_elements_text($2) WITH ORDINALITY AS a(value,position)"))
            .bind(id)
            .bind(ids)
            .execute(&mut *connection)
            .await
            .map_err(database_error)?;
    }
    let mut query = select_documents(resource);
    query.push(" AND id=").push_bind(id);
    query
        .build_query_scalar()
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)
}
/// Remove a record (and, in table storage, its many-relation rows).
pub(super) async fn remove(
    connection: &mut PgConnection,
    resource: &Resource,
    id: Uuid,
) -> Result<(), ApiError> {
    if in_table(resource) {
        sqlx::query(&format!(
            "DELETE FROM {} WHERE id=$1",
            quote(&resource.table)
        ))
        .bind(id)
        .execute(&mut *connection)
        .await
        .map_err(database_error)?;
    } else {
        sqlx::query(&format!("DELETE FROM {RECORDS} WHERE kind=$1 AND id=$2"))
            .bind(&resource.plural_name)
            .bind(id)
            .execute(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(())
}
/// Whether a record of `kind` exists: a registered model in either storage,
/// or a built-in resource (always in `app_records`).
pub(super) async fn exists(
    connection: &mut PgConnection,
    registry: &Registry,
    kind: &str,
    id: Uuid,
) -> Result<bool, ApiError> {
    match registry.models.get(kind) {
        Some(model) if in_table(&model.resource) => sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE id=$1)",
            quote(&model.resource.table)
        ))
        .bind(id)
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal),
        _ => sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {RECORDS} WHERE kind=$1 AND id=$2)"
        ))
        .bind(kind)
        .bind(id)
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal),
    }
}
/// Whether any record of `owner` points at `id` through `field`.
pub(super) async fn referenced(
    connection: &mut PgConnection,
    owner: &Resource,
    field: &Field,
    id: Uuid,
) -> Result<bool, ApiError> {
    if in_table(owner) {
        let sql = if field.many {
            format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE target=$1)",
                quote(&join_table(owner, &field.name))
            )
        } else {
            format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE {}=$1)",
                quote(&owner.table),
                quote(&field.name)
            )
        };
        return sqlx::query_scalar(&sql)
            .bind(id)
            .fetch_one(&mut *connection)
            .await
            .map_err(ApiError::internal);
    }
    let sql = if field.many {
        "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind=$1 AND data->$2 @> to_jsonb($3::text))"
    } else {
        "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind=$1 AND data->>$2=$3)"
    };
    let query = sqlx::query_scalar(sql)
        .bind(owner.plural_name.clone())
        .bind(field.name.clone())
        .bind(id.to_string());
    query
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)
}
/// Whether another record already holds these values for a unique combination.
pub(super) async fn duplicate(
    connection: &mut PgConnection,
    resource: &Resource,
    record: &Value,
    fields: &[String],
) -> Result<bool, ApiError> {
    let id =
        Uuid::parse_str(record["id"].as_str().unwrap_or_default()).map_err(ApiError::internal)?;
    let mut query = if in_table(resource) {
        QueryBuilder::<Postgres>::new(format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE id<>",
            quote(&resource.table)
        ))
    } else {
        let mut query = QueryBuilder::<Postgres>::new(format!(
            "SELECT EXISTS(SELECT 1 FROM {RECORDS} WHERE kind="
        ));
        query
            .push_bind(resource.plural_name.clone())
            .push(" AND id<>");
        query
    };
    query.push_bind(id);
    for field in fields {
        if in_table(resource) {
            query.push(format!(" AND to_jsonb({})=", quote(field)));
        } else {
            query.push(" AND data->").push_bind(field.clone()).push("=");
        }
        query.push_bind(record[field].clone());
    }
    query.push(")");
    query
        .build_query_scalar::<bool>()
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)
}

/// A foreign key the schema should have: on `table`, its `column` points at
/// `target`'s ids.
struct ForeignKey {
    table: String,
    column: String,
    target: String,
    cascade: bool,
}
impl ForeignKey {
    fn name(&self) -> String {
        object_name(&format!("{}_{}_fk", self.table, self.column))
    }
}
/// The table a relation's ids are checked against: a model's own table, the
/// shared records table for a model in records storage, or none for a
/// built-in resource, whose records people may remove while others point at
/// them.
fn target_table(registry: &Registry, target: &str) -> Option<String> {
    registry
        .models
        .get(target)
        .map(|model| model.resource.table.clone())
}
fn table_models(registry: &Registry) -> Vec<&Model> {
    registry
        .models
        .values()
        .filter(|model| in_table(&model.resource))
        .collect()
}
fn foreign_keys(registry: &Registry) -> Vec<ForeignKey> {
    let mut keys = vec![];
    for model in table_models(registry) {
        let resource = &model.resource;
        for field in &resource.fields {
            if reserved(&field.name) {
                continue;
            }
            let target = field
                .related_resource
                .as_deref()
                .and_then(|target| target_table(registry, target));
            if field.many {
                let join = join_table(resource, &field.name);
                keys.push(ForeignKey {
                    table: join.clone(),
                    column: "record".into(),
                    target: resource.table.clone(),
                    cascade: true,
                });
                if let Some(target) = target {
                    keys.push(ForeignKey {
                        table: join,
                        column: "target".into(),
                        target,
                        cascade: false,
                    });
                }
            } else if let Some(target) = target {
                keys.push(ForeignKey {
                    table: resource.table.clone(),
                    column: field.name.clone(),
                    target,
                    cascade: false,
                });
            }
        }
    }
    keys
}
fn unique_index(resource: &Resource, fields: &[String]) -> String {
    object_name(&format!("{}_{}_key", resource.table, fields.join("_")))
}
/// A failure while migrating, naming the model and what to do about it.
fn refuse(model: &str, message: &str) -> ApiError {
    ApiError::Parse(format!("Model {model}: {message}"))
}
async fn table_exists(connection: &mut PgConnection, table: &str) -> Result<bool, ApiError> {
    sqlx::query_scalar("SELECT to_regclass(quote_ident($1)) IS NOT NULL")
        .bind(table)
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)
}
/// Columns of a table: name, type (as Postgres spells it), and whether it is `NOT NULL`.
async fn catalog(
    connection: &mut PgConnection,
    table: &str,
) -> Result<BTreeMap<String, (String, bool)>, ApiError> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT a.attname::text,format_type(a.atttypid,a.atttypmod),a.attnotnull FROM pg_attribute a WHERE a.attrelid=to_regclass(quote_ident($1)) AND a.attnum>0 AND NOT a.attisdropped",
    )
    .bind(table)
    .fetch_all(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(name, typ, not_null)| (name, (typ, not_null)))
        .collect())
}
async fn execute(connection: &mut PgConnection, sql: &str) -> Result<(), ApiError> {
    sqlx::raw_sql(sql)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
/// Run `sql` and report whether it succeeded, leaving the transaction usable
/// when it does not.
async fn attempt(connection: &mut PgConnection, sql: &str) -> Result<bool, ApiError> {
    execute(connection, "SAVEPOINT dynamic_storage_attempt").await?;
    if sqlx::raw_sql(sql).execute(&mut *connection).await.is_ok() {
        execute(connection, "RELEASE SAVEPOINT dynamic_storage_attempt").await?;
        Ok(true)
    } else {
        execute(connection, "ROLLBACK TO SAVEPOINT dynamic_storage_attempt").await?;
        execute(connection, "RELEASE SAVEPOINT dynamic_storage_attempt").await?;
        Ok(false)
    }
}
async fn recorded(connection: &mut PgConnection) -> Result<BTreeMap<String, Value>, ApiError> {
    let rows: Vec<(String, Value)> =
        sqlx::query_as(&format!("SELECT model,schema FROM {SCHEMA_TABLE}"))
            .fetch_all(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
    Ok(rows.into_iter().collect())
}

/// Before the app's own migrations: create the tables of models in table
/// storage, add columns for new fields, move records a model kept in
/// `app_records` before it chose table storage, and keep foreign keys and
/// unique indexes in step. Nothing here drops data.
///
/// # Errors
/// Refuses invalid table names, a model that left table storage (or the app)
/// while its table still holds records, and records that cannot move into
/// their table.
pub(super) async fn prepare(
    connection: &mut PgConnection,
    registry: &Registry,
) -> Result<(), ApiError> {
    execute(
        connection,
        &format!("CREATE TABLE IF NOT EXISTS {SCHEMA_TABLE}(model text PRIMARY KEY,schema jsonb NOT NULL,updated timestamptz NOT NULL DEFAULT now())"),
    )
    .await?;
    let recorded = recorded(connection).await?;
    release_departed(connection, registry, &recorded).await?;
    let models = table_models(registry);
    for model in &models {
        check_names(&model.resource)?;
    }
    // Foreign keys first: one that pointed at app_records must go before
    // records move out of it.
    let wanted = foreign_keys(registry);
    drop_stale_keys(connection, &wanted, &recorded).await?;
    for model in &models {
        create_table(connection, &model.resource).await?;
        move_records(connection, &model.resource).await?;
    }
    add_keys(connection, &wanted).await?;
    for model in &models {
        sync_unique(connection, model, recorded.get(&model.resource.plural_name)).await?;
    }
    Ok(())
}
/// Forget tables of models that left table storage, unless rows remain: the
/// app would no longer show them.
async fn release_departed(
    connection: &mut PgConnection,
    registry: &Registry,
    recorded: &BTreeMap<String, Value>,
) -> Result<(), ApiError> {
    for (name, schema) in recorded {
        if registry
            .models
            .get(name)
            .is_some_and(|model| in_table(&model.resource))
        {
            continue;
        }
        let table = schema["table"].as_str().unwrap_or(name);
        if table_exists(connection, table).await? {
            let rows: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {}", quote(table)))
                .fetch_one(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            if rows > 0 {
                let why = if registry.models.contains_key(name) {
                    format!(
                        "its table {table} still holds {rows} records but the model no longer uses table storage; move them into app_records and drop the table in a registry.migration first"
                    )
                } else {
                    format!(
                        "it is no longer registered but its table {table} still holds {rows} records; drop the table in a registry.migration (DROP TABLE {}) to remove them on purpose",
                        quote(table)
                    )
                };
                return Err(refuse(name, &why));
            }
        }
        sqlx::query(&format!("DELETE FROM {SCHEMA_TABLE} WHERE model=$1"))
            .bind(name)
            .execute(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(())
}
fn check_names(resource: &Resource) -> Result<(), ApiError> {
    let name = &resource.plural_name;
    if resource.table.starts_with("app_") || resource.table.starts_with("pg_") {
        return Err(refuse(
            name,
            "names starting with app_ or pg_ are reserved for the runtime's own tables",
        ));
    }
    for field in many(resource) {
        if join_table(resource, &field.name).len() > 63 {
            return Err(refuse(
                name,
                &format!(
                    "the join table for {} would be longer than 63 characters; shorten the model or field name",
                    field.name
                ),
            ));
        }
    }
    Ok(())
}
/// Drop the foreign keys this runtime made that no longer match a relation:
/// its target moved to another storage, or the relation is gone.
async fn drop_stale_keys(
    connection: &mut PgConnection,
    wanted: &[ForeignKey],
    recorded: &BTreeMap<String, Value>,
) -> Result<(), ApiError> {
    let made: Vec<String> = recorded
        .values()
        .filter_map(|schema| schema["foreign_keys"].as_array())
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect();
    let existing: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT conrelid::regclass::text,conname::text,confrelid::regclass::text FROM pg_constraint WHERE contype='f' AND connamespace=current_schema()::regnamespace AND conname::text=ANY($1)",
    )
    .bind(made)
    .fetch_all(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    for (table, constraint, points_at) in existing {
        let keep = wanted.iter().any(|key| {
            key.name() == constraint
                && table.trim_matches('"') == key.table
                && points_at.trim_matches('"') == key.target
        });
        if !keep {
            execute(
                connection,
                &format!("ALTER TABLE {table} DROP CONSTRAINT {}", quote(&constraint)),
            )
            .await?;
        }
    }
    Ok(())
}
/// The model's table, a column per new field, an index per relation, and a
/// join table per many-relation.
async fn create_table(connection: &mut PgConnection, resource: &Resource) -> Result<(), ApiError> {
    let table = quote(&resource.table);
    execute(
        connection,
        &format!("CREATE TABLE IF NOT EXISTS {table}(id uuid PRIMARY KEY,created timestamptz NOT NULL DEFAULT now(),updated timestamptz NOT NULL DEFAULT now())"),
    )
    .await?;
    let present = catalog(connection, &resource.table).await?;
    for field in columns(resource) {
        if !present.contains_key(&field.name) {
            execute(
                connection,
                &format!(
                    "ALTER TABLE {table} ADD COLUMN {} {}",
                    quote(&field.name),
                    column_type(field)
                ),
            )
            .await?;
        }
        if field.related_resource.is_some() {
            execute(
                connection,
                &format!(
                    "CREATE INDEX IF NOT EXISTS {} ON {table}({})",
                    quote(&object_name(&format!(
                        "{}_{}_idx",
                        resource.table, field.name
                    ))),
                    quote(&field.name)
                ),
            )
            .await?;
        }
    }
    for field in many(resource) {
        let join = join_table(resource, &field.name);
        execute(
            connection,
            &format!(
                "CREATE TABLE IF NOT EXISTS {}(record uuid NOT NULL,position integer NOT NULL,target uuid NOT NULL,PRIMARY KEY(record,position)); CREATE INDEX IF NOT EXISTS {} ON {}(target)",
                quote(&join),
                quote(&object_name(&format!("{join}_target_idx"))),
                quote(&join)
            ),
        )
        .await?;
    }
    Ok(())
}
/// Add the foreign keys that are missing. They hold for new rows at once and
/// are checked against existing rows when those allow it, so earlier data with
/// dangling ids does not stop a release.
async fn add_keys(connection: &mut PgConnection, wanted: &[ForeignKey]) -> Result<(), ApiError> {
    for key in wanted {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND conname=$1 AND conrelid=to_regclass(quote_ident($2)))",
        )
        .bind(key.name())
        .bind(&key.table)
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        if exists {
            continue;
        }
        execute(
            connection,
            &format!(
                "ALTER TABLE {} ADD CONSTRAINT {} FOREIGN KEY({}) REFERENCES {}(id){} NOT VALID",
                quote(&key.table),
                quote(&key.name()),
                quote(&key.column),
                quote(&key.target),
                if key.cascade {
                    " ON DELETE CASCADE"
                } else {
                    ""
                }
            ),
        )
        .await?;
    }
    let invalid: Vec<(String, String)> = sqlx::query_as(
        "SELECT conrelid::regclass::text,conname::text FROM pg_constraint WHERE contype='f' AND NOT convalidated AND connamespace=current_schema()::regnamespace AND conname::text=ANY($1)",
    )
    .bind(wanted.iter().map(ForeignKey::name).collect::<Vec<_>>())
    .fetch_all(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    for (table, constraint) in invalid {
        attempt(
            connection,
            &format!(
                "ALTER TABLE {table} VALIDATE CONSTRAINT {}",
                quote(&constraint)
            ),
        )
        .await?;
    }
    Ok(())
}
/// A unique index per declared combination, dropping ones no longer declared.
/// Existing duplicates leave an index for a later release; the runtime still
/// refuses new duplicates itself.
async fn sync_unique(
    connection: &mut PgConnection,
    model: &Model,
    recorded: Option<&Value>,
) -> Result<(), ApiError> {
    let resource = &model.resource;
    let previous: BTreeSet<String> = recorded
        .and_then(|schema| schema["unique"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect();
    let wanted: BTreeSet<String> = model
        .unique
        .iter()
        .map(|fields| unique_index(resource, fields))
        .collect();
    for gone in previous.difference(&wanted) {
        execute(connection, &format!("DROP INDEX IF EXISTS {}", quote(gone))).await?;
    }
    for fields in &model.unique {
        if let Some(field) = fields
            .iter()
            .find(|field| resource.field(field).is_some_and(|f| f.many))
        {
            return Err(refuse(
                &resource.plural_name,
                &format!("{field} is a many-relation and cannot be part of a unique index"),
            ));
        }
        let columns: Vec<String> = fields.iter().map(|field| quote(field)).collect();
        attempt(
            connection,
            &format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {}({})",
                quote(&unique_index(resource, fields)),
                quote(&resource.table),
                columns.join(",")
            ),
        )
        .await?;
    }
    Ok(())
}
/// `INSERT INTO <table>(<prefix>,<columns>) SELECT <select prefix>,p.<columns>`
/// for copying typed values out of a JSON document.
fn insert_columns(table: &str, prefix: &str, select: &str, resource: &Resource) -> String {
    let names: Vec<String> = columns(resource).map(|field| quote(&field.name)).collect();
    let mut sql = format!("INSERT INTO {table}({prefix}");
    for name in &names {
        sql.push(',');
        sql.push_str(name);
    }
    sql.push_str(") SELECT ");
    sql.push_str(select);
    for name in &names {
        sql.push_str(",p.");
        sql.push_str(name);
    }
    sql
}
/// Move a model's records out of `app_records` into its table, typed by the
/// table's columns. A value that does not fit stops the migration.
async fn move_records(connection: &mut PgConnection, resource: &Resource) -> Result<(), ApiError> {
    let waiting: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {RECORDS} WHERE kind=$1"))
        .bind(&resource.plural_name)
        .fetch_one(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    if waiting == 0 {
        return Ok(());
    }
    let table = quote(&resource.table);
    let sql = insert_columns(
        &table,
        "id,created,updated",
        "r.id,r.created,r.updated",
        resource,
    ) + &format!(
        " FROM {RECORDS} r CROSS JOIN LATERAL jsonb_populate_record(NULL::{table},r.data) p WHERE r.kind=$1 ON CONFLICT(id) DO NOTHING"
    );
    let moving = |error: sqlx::Error| {
        refuse(
            &resource.plural_name,
            &format!(
                "its records could not move into table storage: {}",
                database_error(error)
            ),
        )
    };
    sqlx::query(&sql)
        .bind(&resource.plural_name)
        .execute(&mut *connection)
        .await
        .map_err(moving)?;
    for field in many(resource) {
        sqlx::query(&format!("INSERT INTO {}(record,position,target) SELECT r.id,a.position,a.value::uuid FROM {RECORDS} r CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.data->$2)='array' THEN r.data->$2 ELSE '[]'::jsonb END) WITH ORDINALITY AS a(value,position) WHERE r.kind=$1 ON CONFLICT DO NOTHING", quote(&join_table(resource, &field.name))))
            .bind(&resource.plural_name)
            .bind(&field.name)
            .execute(&mut *connection)
            .await
            .map_err(moving)?;
    }
    sqlx::query(&format!("DELETE FROM {RECORDS} WHERE kind=$1"))
        .bind(&resource.plural_name)
        .execute(&mut *connection)
        .await
        .map_err(moving)?;
    Ok(())
}

/// After the app's own migrations: every declared field must have a column of
/// its type, and a column for a field the model no longer declares must have
/// been dealt with. Required fields become `NOT NULL` once no row lacks them.
/// The schema that passes is recorded for the next comparison.
///
/// # Errors
/// Refuses a column of another type than its field declares, a missing column,
/// and a removed field whose column or join table still holds its data, each
/// with the `registry.migration` that would resolve it.
pub(super) async fn verify(
    connection: &mut PgConnection,
    registry: &Registry,
) -> Result<(), ApiError> {
    let recorded = recorded(connection).await?;
    let keys = foreign_keys(registry);
    for model in table_models(registry) {
        let resource = &model.resource;
        let present = catalog(connection, &resource.table).await?;
        check_columns(connection, resource, &present).await?;
        if let Some(schema) = recorded.get(&resource.plural_name) {
            check_removed(connection, resource, &present, schema).await?;
        }
        remember(connection, model, &keys).await?;
    }
    Ok(())
}
/// Each declared field has a column of its type; `NOT NULL` follows `required`.
async fn check_columns(
    connection: &mut PgConnection,
    resource: &Resource,
    present: &BTreeMap<String, (String, bool)>,
) -> Result<(), ApiError> {
    let (name, table) = (&resource.plural_name, quote(&resource.table));
    for field in columns(resource) {
        let expected = column_type(field);
        let column = quote(&field.name);
        let Some((actual, not_null)) = present.get(&field.name) else {
            return Err(refuse(
                name,
                &format!(
                    "its table has no column for {}; a migration must not drop or rename a declared field's column",
                    field.name
                ),
            ));
        };
        if actual != expected {
            return Err(refuse(
                name,
                &format!(
                    "{} is stored as {actual} but declared as {expected}. Convert it in a registry.migration, e.g. ALTER TABLE {table} ALTER COLUMN {column} TYPE {expected} USING {column}::{expected}",
                    field.name
                ),
            ));
        }
        if field.required && !not_null {
            let missing: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT 1 FROM {table} WHERE {column} IS NULL)"
            ))
            .fetch_one(&mut *connection)
            .await
            .map_err(ApiError::internal)?;
            // Rows from before the field was required keep the column nullable
            // until they are filled; writes require it meanwhile.
            if !missing {
                execute(
                    connection,
                    &format!("ALTER TABLE {table} ALTER COLUMN {column} SET NOT NULL"),
                )
                .await?;
            }
        } else if !field.required && *not_null {
            execute(
                connection,
                &format!("ALTER TABLE {table} ALTER COLUMN {column} DROP NOT NULL"),
            )
            .await?;
        }
    }
    Ok(())
}
/// A field the model no longer declares must not leave its data behind.
async fn check_removed(
    connection: &mut PgConnection,
    resource: &Resource,
    present: &BTreeMap<String, (String, bool)>,
    schema: &Value,
) -> Result<(), ApiError> {
    for (gone, spec) in schema["fields"].as_object().into_iter().flatten() {
        if resource.field(gone).is_some() {
            continue;
        }
        let many = spec["many"] == true;
        let still_there = if many {
            table_exists(connection, &join_table(resource, gone)).await?
        } else {
            present.contains_key(gone)
        };
        if still_there {
            let drop = if many {
                format!("DROP TABLE {}", quote(&join_table(resource, gone)))
            } else {
                format!(
                    "ALTER TABLE {} DROP COLUMN {}",
                    quote(&resource.table),
                    quote(gone)
                )
            };
            return Err(refuse(
                &resource.plural_name,
                &format!(
                    "it no longer declares {gone}, whose data is still stored. Remove it deliberately in a registry.migration ({drop}), or keep declaring the field"
                ),
            ));
        }
    }
    Ok(())
}
/// Record the schema that passed, for the next migration to compare with.
async fn remember(
    connection: &mut PgConnection,
    model: &Model,
    keys: &[ForeignKey],
) -> Result<(), ApiError> {
    let resource = &model.resource;
    let fields: serde_json::Map<String, Value> = resource
        .fields
        .iter()
        .filter(|field| !reserved(&field.name))
        .map(|field| {
            (
                field.name.clone(),
                json!({"type":if field.many {"many"} else {column_type(field)},"many":field.many,"required":field.required,"references":field.related_resource}),
            )
        })
        .collect();
    let unique: Vec<String> = model
        .unique
        .iter()
        .map(|fields| unique_index(resource, fields))
        .collect();
    let mut tables = vec![resource.table.clone()];
    tables.extend(many(resource).map(|field| join_table(resource, &field.name)));
    let keys: Vec<String> = keys
        .iter()
        .filter(|key| tables.contains(&key.table))
        .map(ForeignKey::name)
        .collect();
    sqlx::query(&format!("INSERT INTO {SCHEMA_TABLE}(model,schema) VALUES($1,$2) ON CONFLICT(model) DO UPDATE SET schema=EXCLUDED.schema,updated=now()"))
        .bind(&resource.plural_name)
        .bind(json!({"table":resource.table,"fields":fields,"unique":unique,"foreign_keys":keys}))
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
