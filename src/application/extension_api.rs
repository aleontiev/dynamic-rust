use super::{
    App,
    extensions::{Context, lock},
    user,
};
use crate::{ApiDocument, ApiError, PageMeta, QueryFeatures};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn list(
    app: App,
    headers: HeaderMap,
    kind: String,
    query_string: Option<String>,
) -> Result<Json<ApiDocument>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let features = QueryFeatures::parse(query_string.as_deref().unwrap_or(""), 1000)?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    // Consistent count and results in one read snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let mut ctx = Context::new(&mut tx, &app.registry, actor);
    let (mut rows, total) = ctx.list(&kind, &features).await?;
    let mut document = ApiDocument::many(
        kind.clone(),
        vec![],
        PageMeta::new(features.page, features.per_page, total),
    );
    sideload(&mut ctx, &kind, &rows, &features, &mut document).await?;
    for row in &mut rows {
        project(row, &features);
    }
    document.resources.insert(kind, Value::Array(rows));
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(document))
}
/// Sideload the related records a request asks for (`include[]=supplier.*`, as
/// the admin does for every relation it shows), keyed by the related resource,
/// so names can be shown instead of ids. Relations the actor may not read are
/// left out rather than failing the request.
async fn sideload(
    ctx: &mut Context<'_>,
    kind: &str,
    rows: &[Value],
    features: &QueryFeatures,
    document: &mut ApiDocument,
) -> Result<(), ApiError> {
    let relations: Vec<(String, String)> = ctx
        .registry
        .models
        .get(kind)
        .map(|model| {
            model
                .resource
                .fields
                .iter()
                .filter_map(|field| {
                    field
                        .related_resource
                        .clone()
                        .map(|related| (field.name.clone(), related))
                })
                .collect()
        })
        .unwrap_or_default();
    for (field, related) in relations {
        let wanted = features.include.iter().any(|include| {
            include == &field || include == &format!("{field}.*") || include == &format!("{field}.")
        });
        if !wanted || related == kind {
            continue;
        }
        let ids: std::collections::BTreeSet<String> = rows
            .iter()
            .flat_map(|row| match &row[&field] {
                Value::String(id) => vec![id.clone()],
                Value::Array(items) => items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect(),
                _ => vec![],
            })
            .collect();
        if ids.is_empty() {
            continue;
        }
        let query = ids
            .iter()
            .map(|id| format!("filter{{id.in}}={id}"))
            .chain(std::iter::once(format!("per_page={}", ids.len())))
            .collect::<Vec<_>>()
            .join("&");
        let page = u32::try_from(ids.len()).unwrap_or(u32::MAX).max(1);
        let records = match ctx
            .list(&related, &QueryFeatures::parse(&query, page)?)
            .await
        {
            Ok((records, _)) => records,
            Err(ApiError::Forbidden) => continue,
            Err(error) => return Err(error),
        };
        let entry = document
            .resources
            .entry(related)
            .or_insert_with(|| Value::Array(vec![]));
        if let Some(existing) = entry.as_array_mut() {
            let known: std::collections::BTreeSet<String> = existing
                .iter()
                .filter_map(|record| record["id"].as_str().map(str::to_owned))
                .collect();
            existing.extend(
                records
                    .into_iter()
                    .filter(|record| !record["id"].as_str().is_some_and(|id| known.contains(id))),
            );
        }
    }
    Ok(())
}
pub(super) async fn retrieve(
    app: App,
    headers: HeaderMap,
    kind: String,
    id: Uuid,
    query_string: Option<String>,
) -> Result<Json<ApiDocument>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let mut conn = app.pool.acquire().await.map_err(ApiError::internal)?;
    let mut ctx = Context::new(&mut conn, &app.registry, actor);
    let mut row = ctx.get(&kind, id).await?;
    let features = QueryFeatures::parse(query_string.as_deref().unwrap_or(""), 1000)?;
    let mut document = ApiDocument::one(&app.registry.models[&kind].resource.name, Value::Null);
    sideload(
        &mut ctx,
        &kind,
        std::slice::from_ref(&row),
        &features,
        &mut document,
    )
    .await?;
    project(&mut row, &features);
    document
        .resources
        .insert(app.registry.models[&kind].resource.name.clone(), row);
    Ok(Json(document))
}
/// The records a relation field points at, paged like a list
/// (`GET /api/admin/loans/{id}/guarantors/`): the admin reads a many-relation
/// through this endpoint, as it did with Dynamic REST, and shows each as a link.
/// A single relation answers with at most one record. Only records the actor
/// may list are returned; the record itself must be readable.
pub(super) async fn related(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id, field)): Path<(String, Uuid, String)>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<ApiDocument>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let model = app.registry.models.get(&kind).ok_or(ApiError::NotFound)?;
    let related = model
        .resource
        .fields
        .iter()
        .find(|f| f.name == field)
        .and_then(|f| f.related_resource.clone())
        .ok_or(ApiError::NotFound)?;
    if !app.registry.models.contains_key(&related) {
        return Err(ApiError::NotFound);
    }
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let mut ctx = Context::new(&mut tx, &app.registry, actor);
    let record = ctx.get(&kind, id).await?;
    let ids: Vec<String> = match &record[&field] {
        Value::String(id) => vec![id.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    };
    let raw = raw.unwrap_or_default();
    let features = QueryFeatures::parse(&raw, 1000)?;
    if ids.is_empty() {
        return Ok(Json(ApiDocument::many(
            related,
            vec![],
            PageMeta::new(features.page, features.per_page, 0),
        )));
    }
    let query = ids
        .iter()
        .map(|id| format!("filter{{id.in}}={id}"))
        .chain(std::iter::once(raw))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("&");
    let features = QueryFeatures::parse(&query, 1000)?;
    let (mut rows, total) = ctx.list(&related, &features).await?;
    // Keep the order the record lists them in, as far as this page holds them.
    rows.sort_by_key(|record| {
        ids.iter()
            .position(|id| record["id"].as_str() == Some(id))
            .unwrap_or(usize::MAX)
    });
    let mut document = ApiDocument::many(
        related.clone(),
        vec![],
        PageMeta::new(features.page, features.per_page, total),
    );
    sideload(&mut ctx, &related, &rows, &features, &mut document).await?;
    for row in &mut rows {
        project(row, &features);
    }
    document.resources.insert(related, Value::Array(rows));
    Ok(Json(document))
}
fn project(row: &mut Value, features: &QueryFeatures) {
    row.as_object_mut().unwrap().retain(|name, _| {
        name == "id"
            || ((!features.exclude.iter().any(|f| f == "*")
                || features.include.iter().any(|f| f == "*")
                || features.include.contains(name))
                && !features.exclude.contains(name))
    });
}
fn unwrap(app: &App, kind: &str, input: Value) -> Result<Value, ApiError> {
    let model = app.registry.models.get(kind).ok_or(ApiError::NotFound)?;
    if input
        .as_object()
        .is_some_and(|m| m.len() == 1 && m.contains_key(&model.resource.name))
    {
        Ok(input[&model.resource.name].clone())
    } else {
        Ok(input)
    }
}
async fn write(
    app: App,
    headers: HeaderMap,
    kind: String,
    id: Option<Uuid>,
    input: Value,
    operation: &str,
) -> Result<Json<ApiDocument>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let input = unwrap(&app, &kind, input)?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    lock(&mut tx).await?;
    let mut context = Context::new(&mut tx, &app.registry, actor);
    let row = match operation {
        "create" => context.create(&kind, input).await?,
        "update" => context.update(&kind, id.unwrap(), input).await?,
        "delete" => context.delete(&kind, id.unwrap()).await?,
        _ => return Err(ApiError::NotFound),
    };
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(ApiDocument::one(
        &app.registry.models[&kind].resource.name,
        row,
    )))
}
pub(super) async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Path(kind): Path<String>,
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<ApiDocument>), ApiError> {
    Ok((
        StatusCode::CREATED,
        write(app, headers, kind, None, input, "create").await?,
    ))
}
pub(super) async fn update(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
    Json(input): Json<Value>,
) -> Result<Json<ApiDocument>, ApiError> {
    write(app, headers, kind, Some(id), input, "update").await
}
pub(super) async fn replace(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
    Json(input): Json<Value>,
) -> Result<Json<ApiDocument>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let resource = crate::resource_for_principal_operation(
        &app.registry
            .resource_for(&kind, &actor)
            .ok_or(ApiError::NotFound)?,
        Some(actor.principal()),
        "PUT",
        "update",
    );
    let body = unwrap(&app, &kind, input)?;
    resource.validate_input_for(body.clone(), "PUT")?;
    write(app, headers, kind, Some(id), body, "update").await
}
pub(super) async fn delete(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let _ = write(app, headers, kind, Some(id), json!({}), "delete").await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn action(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id, name)): Path<(String, Uuid, String)>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let action = app
        .registry
        .actions
        .get(&(kind.clone(), name))
        .ok_or(ApiError::NotFound)?
        .clone();
    if !actor.may_run(&action) {
        return Err(ApiError::Forbidden);
    }
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    lock(&mut tx).await?;
    let mut context = Context::new(&mut tx, &app.registry, actor);
    // Access to the targeted record is required even if the action uses raw SQL.
    context.get(&kind, id).await?;
    let result = action
        .handler
        .run(&mut context, json!({"id":id,"data":input}))
        .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(result))
}
