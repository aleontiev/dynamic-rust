//! Platform-operated sessions. The publishing platform (Dreamy) holds the
//! application's operator secret and signs a short-lived grant naming a user;
//! the application exchanges it for an ordinary session of that user, so
//! workers can read and change application data through the same API, hooks,
//! grants and superuser rules as a browser session. Nothing here bypasses them.
use super::{App, hash, random};
use crate::ApiError;
use axum::{Json, extract::State};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

/// Grants are valid for at most this long after they are signed.
pub const GRANT_SECONDS: i64 = 600;
/// Sessions opened through a grant expire after this long.
pub const SESSION_SECONDS: i64 = 900;

/// Read `APP_OPERATOR_SECRET`; a missing or empty value disables operator sessions.
///
/// # Errors
/// A configured secret must be at least 32 characters.
pub fn secret_from_env() -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let value = std::env::var("APP_OPERATOR_SECRET").unwrap_or_default();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() < 32 || value.chars().any(char::is_whitespace) {
        return Err("APP_OPERATOR_SECRET must be at least 32 non-blank characters".into());
    }
    Ok(Some(value))
}

fn mac(secret: &str, email: &str, expires: i64) -> Hmac<Sha256> {
    // HMAC accepts keys of any length, so construction cannot fail.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap_or_else(|_| unreachable!());
    mac.update(format!("operator\n{}\n{expires}", email.trim().to_ascii_lowercase()).as_bytes());
    mac
}

/// Hex signature of a grant for `email` expiring at `expires` (Unix seconds).
#[must_use]
pub fn sign(secret: &str, email: &str, expires: i64) -> String {
    format!("{:x}", mac(secret, email, expires).finalize().into_bytes())
}

fn verify(secret: &str, email: &str, expires: i64, signature: &str) -> bool {
    hex_decode(signature)
        .is_ok_and(|expected| mac(secret, email, expires).verify_slice(&expected).is_ok())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    email: String,
    expires: i64,
    signature: String,
}

/// Exchange a signed grant for a session token of the named user, creating the
/// user record when it does not exist yet (the same record a later email sign-in
/// finds). Replies never reveal whether the secret is configured.
///
/// # Errors
/// Unauthenticated when operator sessions are disabled, the grant is expired,
/// malformed or wrongly signed.
pub async fn session(
    State(app): State<App>,
    Json(input): Json<Grant>,
) -> Result<Json<Value>, ApiError> {
    let secret = app
        .operator_secret
        .as_deref()
        .ok_or(ApiError::Unauthenticated)?;
    let now = chrono_now();
    let email = input.email.trim().to_ascii_lowercase();
    if !email.contains('@')
        || email.len() > 254
        || input.expires <= now
        || input.expires > now + GRANT_SECONDS
        || !verify(secret, &email, input.expires, &input.signature)
    {
        return Err(ApiError::Unauthenticated);
    }
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&email)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let existing:Option<Uuid>=sqlx::query_scalar("SELECT id FROM app_records WHERE kind='users' AND lower(data->>'email')=$1 ORDER BY created,id LIMIT 1").bind(&email).fetch_optional(&mut *tx).await.map_err(ApiError::internal)?;
    let id = existing.unwrap_or_else(Uuid::new_v4);
    if existing.is_none() {
        sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
            .bind(id)
            .bind(json!({"name":email,"email":email,"data":{}}))
            .execute(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    }
    super::core::admit_superuser(&app, &mut tx, id, &email).await?;
    let token = random();
    sqlx::query("DELETE FROM app_sessions WHERE expires<now()")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+make_interval(secs=>$3))")
        .bind(hash(&token))
        .bind(id)
        .bind(f64::from(i32::try_from(SESSION_SECONDS).unwrap_or(900)))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"user":id,"email":email,"expires_in":SESSION_SECONDS,"superuser":app.superusers.contains(&email)}),
    ))
}

fn chrono_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
    )
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_bind_email_and_expiry_case_insensitively() {
        let signature = sign("s".repeat(32).as_str(), "Owner@Example.com", 1_800_000_000);
        assert!(verify(
            &"s".repeat(32),
            "owner@example.com",
            1_800_000_000,
            &signature
        ));
        assert!(!verify(
            &"s".repeat(32),
            "other@example.com",
            1_800_000_000,
            &signature
        ));
        assert!(!verify(
            &"s".repeat(32),
            "owner@example.com",
            1_800_000_001,
            &signature
        ));
        assert!(!verify(
            &"t".repeat(32),
            "owner@example.com",
            1_800_000_000,
            &signature
        ));
        assert!(!verify(
            &"s".repeat(32),
            "owner@example.com",
            1_800_000_000,
            "nothex"
        ));
    }
}
