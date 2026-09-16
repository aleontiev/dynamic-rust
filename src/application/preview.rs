//! One-use handoff from first-party sign-in to an isolated embedded app session.
use super::{App, cookie, hash, random};
use crate::ApiError;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

pub(super) fn origins(app: &App) -> String {
    app.preview_origins.join(" ")
}
pub(super) fn parse_origins(value: &str) -> Result<Vec<String>, ApiError> {
    value
        .split_whitespace()
        .map(|value| {
            let url = url::Url::parse(value)
                .map_err(|_| ApiError::Parse("Invalid preview origin".into()))?;
            if !(url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))))
                || url.origin().ascii_serialization() != value
            {
                return Err(ApiError::Parse(
                    "Preview origins must be explicit HTTPS origins or local development origins"
                        .into(),
                ));
            }
            Ok(value.to_owned())
        })
        .collect()
}
fn same_origin(app: &App, headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(app.origin.as_str()) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Issue {
    nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Redeem {
    nonce: String,
    code: String,
}
fn valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(super) async fn issue(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Issue>,
) -> Result<Response, ApiError> {
    same_origin(&app, &headers)?;
    if app.preview_origins.is_empty() || !valid(&input.nonce) {
        return Err(ApiError::Forbidden);
    }
    let token = cookie(&headers, "dream_app").ok_or(ApiError::Unauthenticated)?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    let owner: Uuid =
        sqlx::query_scalar("SELECT user_id FROM app_sessions WHERE digest=$1 AND expires>now()")
            .bind(hash(&token))
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?
            .ok_or(ApiError::Unauthenticated)?;
    sqlx::query("DELETE FROM app_preview_codes WHERE expires<now()")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let code = random();
    sqlx::query("INSERT INTO app_preview_codes(digest,user_id,challenge,expires) VALUES($1,$2,$3,now()+interval '60 seconds')")
        .bind(hash(&code)).bind(owner).bind(hash(&input.nonce)).execute(&mut *tx).await.map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"code":code})),
    )
        .into_response())
}
pub(super) async fn redeem(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Redeem>,
) -> Result<Response, ApiError> {
    same_origin(&app, &headers)?;
    if app.preview_origins.is_empty() || !valid(&input.nonce) || !valid(&input.code) {
        return Err(ApiError::Unauthenticated);
    }
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    let owner:Uuid=sqlx::query_scalar("DELETE FROM app_preview_codes WHERE digest=$1 AND challenge=$2 AND expires>now() RETURNING user_id")
        .bind(hash(&input.code)).bind(hash(&input.nonce)).fetch_optional(&mut *tx).await.map_err(ApiError::internal)?.ok_or(ApiError::Unauthenticated)?;
    let session = random();
    sqlx::query(
        "INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '12 hours')",
    )
    .bind(hash(&session))
    .bind(owner)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    let mut response = (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"signed_in":true})),
    )
        .into_response();
    response.headers_mut().insert(header::SET_COOKIE,format!("dream_preview={session}; Path=/api; HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=43200").parse().unwrap());
    Ok(response)
}
pub(super) async fn shell() -> Response {
    let nonce = random();
    let html = format!(
        "<!doctype html><html><head><title>Return to preview</title><meta name=\"referrer\" content=\"no-referrer\"></head><body><p>Returning to your app preview…</p><script nonce=\"{nonce}\">{}</script></body></html>",
        include_str!("templates/app-preview.js")
    );
    let mut response = Html(html).into_response();
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,format!("default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'").parse().unwrap());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}
pub(super) async fn script(State(app): State<App>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/javascript"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("templates/app-preview.js").replace(
            "__DREAM_PREVIEW_ORIGINS__",
            &serde_json::to_string(&app.preview_origins).unwrap_or_else(|_| "[]".into()),
        ),
    )
}
