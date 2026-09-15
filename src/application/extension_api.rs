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
    let actor = app.actor(&user(&app, &headers).await?);
    let features = QueryFeatures::parse(query_string.as_deref().unwrap_or(""), 1000)?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    // Consistent count and results in one read snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let mut ctx = Context::new(&mut tx, &app.registry, actor);
    let (mut rows, total) = ctx.list(&kind, &features).await?;
    for row in &mut rows {
        project(row, &features);
    }
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(ApiDocument::many(
        kind,
        rows,
        PageMeta::new(features.page, features.per_page, total),
    )))
}
pub(super) async fn retrieve(
    app: App,
    headers: HeaderMap,
    kind: String,
    id: Uuid,
    query_string: Option<String>,
) -> Result<Json<ApiDocument>, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?);
    let mut conn = app.pool.acquire().await.map_err(ApiError::internal)?;
    let mut ctx = Context::new(&mut conn, &app.registry, actor);
    let mut row = ctx.get(&kind, id).await?;
    project(
        &mut row,
        &QueryFeatures::parse(query_string.as_deref().unwrap_or(""), 1000)?,
    );
    Ok(Json(ApiDocument::one(
        &app.registry.models[&kind].resource.name,
        row,
    )))
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
    let actor = app.actor(&user(&app, &headers).await?);
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
    let actor = app.actor(&user(&app, &headers).await?);
    let model = app.registry.models.get(&kind).ok_or(ApiError::NotFound)?;
    let resource = crate::resource_for_principal_operation(
        &model.resource,
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
    let actor = app.actor(&user(&app, &headers).await?);
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
