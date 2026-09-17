#![allow(clippy::too_many_lines)]
//! App-local Google sign-in through the trusted Dreamy identity broker.
//! Google credentials/tokens and workspace privileges never enter this runtime.
use super::{App, cookie, hash, magic_auth, random, redirect};
use crate::ApiError;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct GoogleAuth {
    pub broker_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Only private tests may supply loopback HTTP. Never read from environment.
    pub test_endpoint: Option<String>,
}

/// Validate the identity broker origin.
/// # Errors
/// Rejects non-HTTPS URLs and non-origin components.
pub fn https_origin(value: &str) -> Result<url::Url, &'static str> {
    let url = url::Url::parse(value).map_err(|_| "Invalid APP_AUTH_URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("APP_AUTH_URL must use HTTPS and contain only an origin");
    }
    Ok(url)
}

pub(super) fn from_env() -> Result<Option<GoogleAuth>, &'static str> {
    let values = [
        "APP_AUTH_URL",
        "APP_AUTH_CLIENT_ID",
        "APP_AUTH_CLIENT_SECRET",
    ]
    .map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()));
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(broker_url), Some(client_id), Some(client_secret)] = values else {
        return Err(
            "Configure all APP_AUTH_URL, APP_AUTH_CLIENT_ID and APP_AUTH_CLIENT_SECRET values",
        );
    };
    let broker_url = https_origin(&broker_url)?.origin().ascii_serialization();
    Ok(Some(GoogleAuth {
        broker_url,
        client_id,
        client_secret,
        test_endpoint: None,
    }))
}

fn failure(app: &App, reason: &str) -> Result<Response, ApiError> {
    let mut response = redirect(
        &format!("{}/api/login/?google_error={reason}", app.origin),
        "dream_google",
        "",
        0,
    )?;
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    Ok(response)
}

/// Never follow a broker redirect with the client secret or return broker payloads.
/// # Errors
/// Rejects broker transport errors, redirects and invalid response documents.
pub async fn broker<T: DeserializeOwned>(
    auth: &GoogleAuth,
    path: &str,
    body: Value,
) -> Result<T, ()> {
    let configured = https_origin(&auth.broker_url).map_err(|_| ())?;
    let base = if let Some(endpoint) = &auth.test_endpoint {
        let url = url::Url::parse(endpoint).map_err(|_| ())?;
        if url.scheme() != "http"
            || !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(());
        }
        url
    } else {
        configured
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| ())?;
    let mut response = client
        .post(base.join(path).map_err(|_| ())?)
        .json(&body)
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            "App Google broker request rejected"
        );
        return Err(());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len() + chunk.len() > 16_384 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

#[derive(Deserialize)]
struct Authorization {
    authorization_url: String,
}

#[derive(Deserialize)]
pub(super) struct Start {
    next: Option<String>,
}
pub(super) async fn start(
    State(app): State<App>,
    Query(input): Query<Start>,
) -> Result<Response, ApiError> {
    let Some(auth) = &app.google_auth else {
        return failure(&app, "unavailable");
    };
    let state = random();
    let verifier = random();
    let next = super::next_path(&app, input.next.as_deref());
    sqlx::query("DELETE FROM app_google_states WHERE expires<now()")
        .execute(&app.pool)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("INSERT INTO app_google_states(digest,verifier,client_id,expires,next) VALUES($1,$2,$3,now()+interval '10 minutes',$4)")
        .bind(hash(&state)).bind(&verifier).bind(&auth.client_id).bind(&next)
        .execute(&app.pool).await.map_err(ApiError::internal)?;
    let result: Result<Authorization, ()> = broker(auth, "/v1/requests", json!({
        "client_id":auth.client_id,"client_secret":auth.client_secret,
        "state":state,"code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    })).await;
    let authorization = result.ok().and_then(|result| {
        let url = url::Url::parse(&result.authorization_url).ok()?;
        let origin = https_origin(&auth.broker_url).ok()?;
        (url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && (url.host_str() == Some("accounts.google.com") || url.origin() == origin.origin()))
        .then_some(url)
    });
    let Some(authorization) = authorization else {
        sqlx::query("DELETE FROM app_google_states WHERE digest=$1")
            .bind(hash(&state))
            .execute(&app.pool)
            .await
            .map_err(ApiError::internal)?;
        return failure(&app, "unavailable");
    };
    let mut response = redirect(authorization.as_str(), "dream_google", &state, 600)?;
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    Ok(response)
}

#[derive(Deserialize)]
pub(super) struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}
#[derive(Deserialize)]
struct Identity {
    provider: String,
    sub: String,
    email: String,
    email_verified: bool,
    #[serde(default)]
    name: String,
    hd: Option<String>,
    picture: Option<String>,
}
/// Google's profile photo, accepted only as an https URL on a Google image
/// host; anything else is dropped rather than stored on the user.
fn picture_url(value: Option<&str>) -> Option<&str> {
    let value = value?;
    let parsed = url::Url::parse(value).ok()?;
    let host = parsed.host_str()?;
    (parsed.scheme() == "https"
        && value.len() <= 2048
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && (host == "googleusercontent.com" || host.ends_with(".googleusercontent.com")))
    .then_some(value)
}
fn opaque(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(super) async fn callback(
    State(app): State<App>,
    headers: HeaderMap,
    Query(input): Query<Callback>,
) -> Result<Response, ApiError> {
    let Some(auth) = &app.google_auth else {
        return failure(&app, "unavailable");
    };
    let state = input.state.as_deref().unwrap_or_default();
    if !opaque(state) || cookie(&headers, "dream_google").as_deref() != Some(state) {
        return failure(&app, "expired");
    }
    // Commit consumption before any network request. A failed exchange is never retried.
    let consumed: Option<(String, Option<String>)> = sqlx::query_as(
        "DELETE FROM app_google_states WHERE digest=$1 AND client_id=$2 AND expires>now() RETURNING verifier,next"
    ).bind(hash(state)).bind(&auth.client_id).fetch_optional(&app.pool).await.map_err(ApiError::internal)?;
    let Some((verifier, next)) = consumed else {
        return failure(&app, "expired");
    };
    if input.error.is_some() {
        return failure(&app, "cancelled");
    }
    let code = input.code.as_deref().unwrap_or_default();
    if !opaque(code) {
        return failure(&app, "expired");
    }
    let identity: Identity = match broker(
        auth,
        "/v1/token",
        json!({
            "client_id":auth.client_id,"client_secret":auth.client_secret,
            "code":code,"code_verifier":verifier
        }),
    )
    .await
    {
        Ok(identity) => identity,
        Err(()) => return failure(&app, "unavailable"),
    };
    if identity.provider != "google"
        || !identity.email_verified
        || identity.sub.is_empty()
        || identity.sub.len() > 255
        || identity.sub.chars().any(char::is_control)
    {
        return failure(&app, "unavailable");
    }
    let Ok(email) = magic_auth::email(&identity.email) else {
        return failure(&app, "unavailable");
    };
    let authoritative = email.ends_with("@gmail.com")
        || identity
            .hd
            .as_deref()
            .is_some_and(|hd| !hd.trim().is_empty());
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("google:{}", identity.sub))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    // Share the email lock with magic-link account creation.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&email)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let linked: Option<String> = sqlx::query_scalar("SELECT data->>'user' FROM app_records WHERE kind='identities' AND data->>'provider'='google' AND data->>'subject'=$1")
        .bind(&identity.sub).fetch_optional(&mut *tx).await.map_err(ApiError::internal)?;
    let id = if let Some(linked) = linked {
        Uuid::parse_str(&linked).map_err(ApiError::internal)?
    } else {
        let existing:Option<Uuid> = sqlx::query_scalar("SELECT id FROM app_records WHERE kind='users' AND lower(data->>'email')=$1 ORDER BY created,id LIMIT 1")
            .bind(&email).fetch_optional(&mut *tx).await.map_err(ApiError::internal)?;
        if existing.is_some() && !authoritative {
            return failure(&app, "email_link");
        }
        let id = existing.unwrap_or_else(Uuid::new_v4);
        if existing.is_none() {
            let name = if identity.name.trim().is_empty() {
                &email
            } else {
                &identity.name
            };
            sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'users',$2)")
                .bind(id)
                .bind(json!({"name":name,"email":email,"data":{}}))
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
        }
        for (kind, data) in [
            (
                "identities",
                json!({"name":email,"user":id,"provider":"google","subject":identity.sub}),
            ),
            (
                "identity_verifications",
                json!({"name":email,"user":id,"verified":true,"method":"google"}),
            ),
        ] {
            sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,$2,$3)")
                .bind(Uuid::new_v4())
                .bind(kind)
                .bind(data)
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
        }
        id
    };
    // A person without a profile photo gets the one Google shows for them.
    if let Some(picture) = picture_url(identity.picture.as_deref()) {
        sqlx::query("UPDATE app_records SET data=jsonb_set(data,'{photo}',$2),updated=now() WHERE kind='users' AND id=$1 AND coalesce(data->>'photo','')=''")
            .bind(id).bind(json!(picture)).execute(&mut *tx).await.map_err(ApiError::internal)?;
    }
    super::core::admit_superuser(&app, &mut tx, id, &email).await?;
    let session = random();
    sqlx::query("DELETE FROM app_sessions WHERE expires<now()")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query(
        "INSERT INTO app_sessions(digest,user_id,expires) VALUES($1,$2,now()+interval '12 hours')",
    )
    .bind(hash(&session))
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    let destination = match super::next_path(&app, next.as_deref()) {
        Some(path) => format!("{}{path}", app.origin),
        None => app.origin.clone(),
    };
    let mut response = redirect(&destination, "dream_app", &session, 43200)?;
    response.headers_mut().append(
        header::SET_COOKIE,
        "dream_google=; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_configuration_is_an_https_origin() {
        assert!(https_origin("https://auth.dreamy.so").is_ok());
        for value in [
            "http://auth.dreamy.so",
            "https://user:secret@auth.dreamy.so",
            "https://auth.dreamy.so/path",
            "https://auth.dreamy.so/?query=secret",
            "https://auth.dreamy.so/#fragment",
            "not a URL",
        ] {
            assert!(https_origin(value).is_err());
        }
    }
}
