//! Connections to outside services: accounting, rides, chat, other APIs.
//!
//! An app registers each service it talks to with [`Integration`]. Every
//! registered integration is a `providers` record whose `integration` names it,
//! and administrators (anyone whose roles grant `providers` `update`) connect it
//! there:
//!
//! - **OAuth 2** ([`Integration::oauth2`]): they enter the client ID and secret
//!   from the service's developer console, register the record's
//!   `redirect_uri` there, and press **Connect**. The service sends the browser
//!   back to `/api/integrations/<name>/callback`, and the runtime exchanges the
//!   code for tokens.
//! - **Token** ([`Integration::token`]): they paste an API token (key) the
//!   service issued and press **Connect**, which checks it against the service.
//!
//! Either kind may name the service's base URL for each stage the app runs in
//! (`APP_STAGE`: `dev` or `production`); an administrator may replace it on the
//! record (another tenant, a sandbox). Secrets and tokens are kept in
//! `app_integration_secrets`, which no API returns. Code uses the connection
//! through [`Context::integration`], which refreshes an OAuth access token when
//! it is about to expire.
use super::{App, DOCUMENT, extensions::Context, hash, random, user};
use crate::{ApiError, FieldErrors};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use serde_json::{Map, Value, json};
use sqlx::{PgConnection, PgPool};
use std::{collections::BTreeMap, sync::OnceLock, time::Duration};
use uuid::Uuid;

/// How the client authenticates at the token endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientAuth {
    /// HTTP Basic with the client ID and secret (`client_secret_basic`).
    #[default]
    Basic,
    /// The ID and secret as form fields (`client_secret_post`).
    Body,
}

/// How a service lets the app in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Auth {
    /// OAuth 2 authorization codes, with refreshed access tokens.
    #[default]
    OAuth2,
    /// A token (API key) an administrator pastes in, sent on every request.
    Token,
}

/// A service the app connects to.
#[derive(Clone, Debug)]
#[must_use]
pub struct Integration {
    pub name: String,
    pub label: String,
    pub description: Option<String>,
    pub auth: Auth,
    /// The service's API location when no stage-specific one applies.
    pub base_url: Option<String>,
    /// The API location for a stage (`dev`, `production`), e.g. a sandbox.
    pub stage_base_urls: BTreeMap<String, String>,
    /// A token is sent in this header…
    pub token_header: String,
    /// …formatted like this, with `{token}` replaced by the token.
    pub token_format: String,
    /// A path under the base URL that answers 2xx to a valid token; Connect
    /// requests it to check the token before marking the provider connected.
    pub check: Option<String>,
    pub authorize_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    /// Extra query parameters for the authorization page (e.g. Google's
    /// `access_type=offline`).
    pub authorize_params: BTreeMap<String, String>,
    /// Callback query parameters that identify the connected account and are
    /// kept on the provider record (`QuickBooks` sends `realmId`).
    pub account_params: Vec<String>,
    pub client_auth: ClientAuth,
}
impl Integration {
    /// An OAuth 2 integration named `name` (lowercase letters, digits and
    /// underscores), shown to people as `label`.
    pub fn oauth2(name: &str, label: &str) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            description: None,
            auth: Auth::OAuth2,
            base_url: None,
            stage_base_urls: BTreeMap::new(),
            token_header: "Authorization".into(),
            token_format: "Bearer {token}".into(),
            check: None,
            authorize_url: String::new(),
            token_url: String::new(),
            scopes: vec![],
            authorize_params: BTreeMap::new(),
            account_params: vec![],
            client_auth: ClientAuth::Basic,
        }
    }
    /// A service that takes a token (API key) an administrator pastes in, sent
    /// as `Authorization: Bearer <token>` unless [`Self::token_header`] says
    /// otherwise.
    pub fn token(name: &str, label: &str) -> Self {
        Self {
            auth: Auth::Token,
            ..Self::oauth2(name, label)
        }
    }
    /// How a token is sent: the header, and its value with `{token}` standing
    /// for the token, e.g. `("Authorization", "JWT {token}")` or
    /// `("X-Api-Key", "{token}")`.
    pub fn token_header(mut self, header: &str, format: &str) -> Self {
        self.token_header = header.into();
        self.token_format = format.into();
        self
    }
    /// The service's API location, used when no stage-specific one applies.
    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = Some(url.trim_end_matches('/').into());
        self
    }
    /// The API location while the app runs as `stage` (`dev` or `production`),
    /// e.g. a sandbox for `dev`.
    pub fn stage_base_url(mut self, stage: &str, url: &str) -> Self {
        self.stage_base_urls
            .insert(stage.into(), url.trim_end_matches('/').into());
        self
    }
    /// A path under the base URL that answers 2xx to a valid token (one page
    /// of something the token may read); Connect requests it before marking a
    /// token provider connected.
    pub fn check(mut self, path: &str) -> Self {
        self.check = Some(path.into());
        self
    }
    /// The API location for the stage the app runs in, before an
    /// administrator's override.
    #[must_use]
    pub fn default_base_url(&self) -> Option<String> {
        self.stage_base_urls
            .get(&stage())
            .or(self.base_url.as_ref())
            .cloned()
    }
    pub(super) fn kind(&self) -> &'static str {
        match self.auth {
            Auth::OAuth2 => "oauth2",
            Auth::Token => "token",
        }
    }
    pub fn authorize_url(mut self, url: &str) -> Self {
        self.authorize_url = url.into();
        self
    }
    pub fn token_url(mut self, url: &str) -> Self {
        self.token_url = url.into();
        self
    }
    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| (*s).into()).collect();
        self
    }
    pub fn authorize_param(mut self, name: &str, value: &str) -> Self {
        self.authorize_params.insert(name.into(), value.into());
        self
    }
    pub fn account_params(mut self, names: &[&str]) -> Self {
        self.account_params = names.iter().map(|s| (*s).into()).collect();
        self
    }
    /// Send the client credentials as form fields rather than HTTP Basic.
    pub fn client_secret_in_body(mut self) -> Self {
        self.client_auth = ClientAuth::Body;
        self
    }
    /// One sentence for administrators about what the connection is used for.
    pub fn describe(mut self, text: &str) -> Self {
        self.description = Some(text.into());
        self
    }
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        let invalid =
            |message: &str| ApiError::Parse(format!("Integration {}: {message}", self.name));
        if !super::extensions::identifier(&self.name) {
            return Err(invalid("use lowercase letters, digits and underscores"));
        }
        if self.label.trim().is_empty() {
            return Err(invalid("give it a label"));
        }
        for (stage, url) in self
            .stage_base_urls
            .iter()
            .map(|(stage, url)| (Some(stage), url))
            .chain(self.base_url.iter().map(|url| (None, url)))
        {
            if stage.is_some_and(|stage| !super::extensions::identifier(stage)) {
                return Err(invalid("name stages like dev and production"));
            }
            base_url(url).map_err(|message| invalid(&format!("base URL: {message}")))?;
        }
        match self.auth {
            Auth::OAuth2 => {
                for url in [&self.authorize_url, &self.token_url] {
                    if !secure(url) {
                        return Err(invalid("authorize and token URLs must use HTTPS"));
                    }
                }
            }
            Auth::Token => {
                if reqwest::header::HeaderName::from_bytes(self.token_header.as_bytes()).is_err()
                    || !self.token_format.contains("{token}")
                {
                    return Err(invalid(
                        "send the token in a valid header whose value contains {token}",
                    ));
                }
                if self
                    .check
                    .as_ref()
                    .is_some_and(|path| !path.starts_with('/'))
                {
                    return Err(invalid("the check is a path starting with /"));
                }
            }
        }
        Ok(())
    }
}
/// Whether `url` is HTTPS, or plain HTTP to this machine (tests' stand-ins).
fn secure(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|parsed| {
        let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost"));
        parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback)
    })
}
/// A base URL as kept: an HTTPS location without credentials, query or
/// fragment, and without a trailing slash.
fn base_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let parsed = url::Url::parse(url)
        .map_err(|_| "enter a full URL such as https://api.example.com".to_owned())?;
    if !secure(url) {
        return Err("use an https:// URL".into());
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || url.len() > 500
    {
        return Err(
            "give only the location, up to 500 characters, without credentials or a query".into(),
        );
    }
    Ok(url.trim_end_matches('/').to_owned())
}
/// The stage this app runs as: `APP_STAGE`, or `dev` when unset (local runs
/// and tests).
fn stage() -> String {
    std::env::var("APP_STAGE")
        .ok()
        .map(|stage| stage.trim().to_owned())
        .filter(|stage| !stage.is_empty())
        .unwrap_or_else(|| "dev".into())
}

/// A live connection: a current access token (or the saved token), where the
/// service is, and the account it reaches.
#[derive(Clone, Debug)]
pub struct Connection {
    pub name: String,
    pub access_token: String,
    /// The service's API location for this app: the provider record's base
    /// URL, else the integration's default for the stage; empty if neither.
    pub base_url: String,
    /// The account parameters the service identified at connection time,
    /// e.g. `{"realmId": "9130..."}` for `QuickBooks`.
    pub account: Value,
    header: String,
    value: String,
}
impl Connection {
    /// `path` under the base URL; a full URL is kept as it is.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{path}", self.base_url)
        } else {
            path.to_owned()
        }
    }
    /// A request to the service carrying the credentials. A `url` starting with
    /// `/` is a path under the base URL.
    pub fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        http()
            .request(method, self.url(url))
            .header(self.header.as_str(), self.value.as_str())
    }
    pub fn get(&self, url: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, url)
    }
    pub fn post(&self, url: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, url)
    }
    pub fn put(&self, url: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PUT, url)
    }
    pub fn patch(&self, url: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PATCH, url)
    }
    pub fn delete(&self, url: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::DELETE, url)
    }
}
/// A connection to `integration` with `token`, at the record's base URL or
/// the integration's default.
fn connection(integration: &Integration, record: &Value, token: String) -> Connection {
    let (header, value) = match integration.auth {
        Auth::OAuth2 => ("Authorization".to_owned(), format!("Bearer {token}")),
        Auth::Token => (
            integration.token_header.clone(),
            integration.token_format.replace("{token}", &token),
        ),
    };
    Connection {
        name: integration.name.clone(),
        base_url: effective_base_url(integration, record),
        access_token: token,
        account: record["account"].clone(),
        header,
        value,
    }
}
fn effective_base_url(integration: &Integration, record: &Value) -> String {
    record["base_url"]
        .as_str()
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .or_else(|| integration.default_base_url())
        .unwrap_or_default()
}

/// The shared outbound HTTP client: 10 s to connect, 25 s per request.
#[must_use]
pub fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(25))
            .user_agent("dynamic-rust")
            .build()
            .unwrap_or_default()
    })
}

fn invalid(field: &str, message: &str) -> ApiError {
    ApiError::Validation(FieldErrors::from([(field.into(), vec![message.into()])]))
}
fn callback_url(origin: &str, name: &str) -> String {
    format!("{origin}/api/integrations/{name}/callback")
}

/// Keep one `providers` record per registered integration, adding new ones,
/// named after the integration's label, as needing credentials, and refreshing
/// the description of the rest. Administrators may rename them.
pub(super) async fn sync_providers(
    connection: &mut PgConnection,
    integrations: &BTreeMap<String, Integration>,
) -> Result<(), ApiError> {
    for integration in integrations.values() {
        let presentation = json!({"kind":integration.kind(),"description":integration.description});
        let updated = sqlx::query(
            "UPDATE app_records SET data=data||$2,updated=now() WHERE kind='providers' AND data->>'integration'=$1 AND NOT (data @> $2)",
        )
        .bind(&integration.name)
        .bind(&presentation)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        if updated.rows_affected() > 0 {
            continue;
        }
        let mut data = presentation;
        data["name"] = json!(integration.label);
        data["integration"] = json!(integration.name);
        data["enabled"] = json!(true);
        data["status"] = json!("needs_credentials");
        data["account"] = json!({});
        sqlx::query(
            "INSERT INTO app_records(id,kind,data) SELECT $1,'providers',$2 WHERE NOT EXISTS (SELECT 1 FROM app_records WHERE kind='providers' AND data->>'integration'=$3)",
        )
        .bind(Uuid::new_v4())
        .bind(&data)
        .bind(&integration.name)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    }
    Ok(())
}

/// Add what a provider record shows but does not store: the redirect URI to
/// register with an OAuth service, the base URL used when the record names
/// none, and whether a client secret or token is saved.
pub(super) fn present(app: &App, record: &mut Value, secret_saved: bool) {
    let Some(name) = record["integration"].as_str().map(str::to_owned) else {
        return;
    };
    let integration = app.registry.integrations.get(&name);
    let token = integration.is_some_and(|integration| integration.auth == Auth::Token);
    if let Some(integration) = integration {
        if !token {
            record["redirect_uri"] = json!(callback_url(&app.origin, &name));
        }
        record["default_base_url"] = json!(integration.default_base_url());
    }
    let saved = |shown: bool| json!(if secret_saved && shown { "Saved" } else { "" });
    record["client_secret"] = saved(!token);
    record["token"] = saved(token);
}
/// Whether a provider record has a saved client secret.
pub(super) fn secret_saved(saved: &[String], record: &Value) -> bool {
    record["integration"]
        .as_str()
        .is_some_and(|name| saved.iter().any(|saved| saved == name))
}
fn provider_name(value: &Value) -> Result<String, ApiError> {
    value
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty() && name.chars().count() <= 200)
        .map(str::to_owned)
        .ok_or_else(|| invalid("name", "Name must be 1 to 200 characters."))
}
fn provider_kind(value: &Value) -> Result<String, ApiError> {
    value
        .as_str()
        .map(str::trim)
        .filter(|kind| !kind.is_empty() && kind.chars().count() <= 100)
        .map(str::to_owned)
        .ok_or_else(|| invalid("kind", "Kind must be 1 to 100 characters."))
}
fn provider_enabled(value: &Value) -> Result<bool, ApiError> {
    value
        .as_bool()
        .ok_or_else(|| invalid("enabled", "Must be true or false."))
}
/// A provider an administrator adds by hand (a mail or sign-in service the
/// app's code reads): a `name`, a `kind` and whether it is `enabled`. Other
/// input is ignored.
pub(super) async fn create(connection: &mut PgConnection, input: &Value) -> Result<Uuid, ApiError> {
    let name = provider_name(input.get("name").unwrap_or(&Value::Null))?;
    let kind = provider_kind(input.get("kind").unwrap_or(&Value::Null))?;
    let enabled = match input.get("enabled") {
        None | Some(Value::Null) => true,
        Some(value) => provider_enabled(value)?,
    };
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO app_records(id,kind,data) VALUES($1,'providers',$2)")
        .bind(id)
        .bind(json!({"name":name,"kind":kind,"enabled":enabled}))
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(id)
}
/// Remove a provider an administrator added. Integrations belong to the app's
/// code, which would add them back, so they are disconnected instead.
pub(super) async fn delete(connection: &mut PgConnection, current: &Value) -> Result<(), ApiError> {
    if current["integration"].is_string() {
        return Err(ApiError::Conflict(
            "This provider comes from the app's code and cannot be removed; disconnect it instead."
                .into(),
        ));
    }
    sqlx::query("DELETE FROM app_records WHERE kind='providers' AND id=$1")
        .bind(
            Uuid::parse_str(current["id"].as_str().unwrap_or_default())
                .map_err(ApiError::internal)?,
        )
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
pub(super) async fn secrets_saved(pool: &PgPool) -> Result<Vec<String>, ApiError> {
    sqlx::query_scalar(
        "SELECT provider FROM app_integration_secrets WHERE client_secret IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(ApiError::internal)
}

/// Apply an administrator's changes to a provider: its `name`, `kind` and
/// `enabled`, and for an integration its `client_id` and a new `client_secret`
/// (blank keeps the saved one). Other input, and anything else the record
/// holds, is left alone. An integration's kind belongs to the code, and
/// changing its client clears the connection, since the tokens belong to the
/// old one.
pub(super) async fn update(
    connection: &mut PgConnection,
    id: Uuid,
    input: &Value,
) -> Result<(), ApiError> {
    let current: Value = sqlx::query_scalar(&format!(
        "SELECT {DOCUMENT} FROM app_records WHERE kind='providers' AND id=$1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?
    .ok_or(ApiError::NotFound)?;
    let integration = current["integration"].as_str().map(str::to_owned);
    let mut data = current.clone();
    for reserved in ["id", "created", "updated"] {
        data.as_object_mut().map(|o| o.remove(reserved));
    }
    if let Some(name) = input.get("name") {
        data["name"] = json!(provider_name(name)?);
    }
    if let Some(kind) = input.get("kind") {
        let kind = provider_kind(kind)?;
        if integration.is_some() && current["kind"].as_str() != Some(kind.as_str()) {
            return Err(invalid(
                "kind",
                "This provider's kind is set by the app's code.",
            ));
        }
        data["kind"] = json!(kind);
    }
    if let Some(enabled) = input.get("enabled") {
        data["enabled"] = json!(provider_enabled(enabled)?);
    }
    let Some(name) = integration else {
        for field in ["client_id", "client_secret", "token", "base_url"] {
            if input
                .get(field)
                .is_some_and(|value| !value.is_null() && value != "")
            {
                return Err(invalid(
                    field,
                    "Only providers from the app's code take credentials or a base URL.",
                ));
            }
        }
        sqlx::query(
            "UPDATE app_records SET data=$2,updated=now() WHERE kind='providers' AND id=$1",
        )
        .bind(id)
        .bind(&data)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        return Ok(());
    };
    let token = current["kind"] == "token";
    // A token provider takes no client credentials, an OAuth one no token.
    let (wrong, kind): (&[&str], _) = if token {
        (&["client_id", "client_secret"], "an OAuth")
    } else {
        (&["token"], "a token")
    };
    for &field in wrong {
        if input
            .get(field)
            .is_some_and(|value| !value.is_null() && value != "" && value != "Saved")
        {
            return Err(invalid(field, &format!("Only {kind} provider takes this.")));
        }
    }
    let moved = match input.get("base_url") {
        None => false,
        Some(Value::Null) => data
            .as_object_mut()
            .and_then(|o| o.remove("base_url"))
            .is_some(),
        Some(Value::String(url)) if url.trim().is_empty() => data
            .as_object_mut()
            .and_then(|o| o.remove("base_url"))
            .is_some(),
        Some(Value::String(url)) => {
            let url =
                base_url(url).map_err(|message| invalid("base_url", &capitalize(&message)))?;
            let moved = current["base_url"].as_str() != Some(url.as_str());
            data["base_url"] = json!(url);
            moved
        }
        Some(_) => return Err(invalid("base_url", "Must be text.")),
    };
    if token {
        save_token(connection, &name, input, moved, &mut data).await?;
    } else {
        credentials(connection, &name, &current, input, &mut data).await?;
    }
    sqlx::query("UPDATE app_records SET data=$2,updated=now() WHERE kind='providers' AND id=$1")
        .bind(id)
        .bind(&data)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

fn capitalize(message: &str) -> String {
    let mut chars = message.chars();
    chars.next().map_or_else(String::new, |first| {
        format!("{}{}.", first.to_uppercase(), chars.as_str())
    })
}
/// Save a token provider's new token. A new token, or a new base URL, needs
/// checking again, so the provider waits to be connected.
async fn save_token(
    connection: &mut PgConnection,
    name: &str,
    input: &Value,
    moved: bool,
    data: &mut Value,
) -> Result<(), ApiError> {
    let token = match input.get("token") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.trim().is_empty() || text == "Saved" => None,
        Some(Value::String(text)) if text.len() <= 4000 => Some(text.trim().to_owned()),
        Some(_) => return Err(invalid("token", "Must be text up to 4000 characters.")),
    };
    if let Some(token) = &token {
        sqlx::query("INSERT INTO app_integration_secrets(provider,client_secret) VALUES($1,$2) ON CONFLICT(provider) DO UPDATE SET client_secret=EXCLUDED.client_secret,access_token=NULL,refresh_token=NULL,expires=NULL,updated=now()")
            .bind(name).bind(token).execute(&mut *connection).await.map_err(ApiError::internal)?;
    }
    if token.is_none() && !moved {
        return Ok(());
    }
    let has_token: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_integration_secrets WHERE provider=$1 AND client_secret IS NOT NULL)")
        .bind(name).fetch_one(&mut *connection).await.map_err(ApiError::internal)?;
    data["status"] = json!(if has_token {
        "disconnected"
    } else {
        "needs_credentials"
    });
    data["account"] = json!({});
    data["error"] = Value::Null;
    data["connected_at"] = Value::Null;
    Ok(())
}

/// Save an integration's new client ID or secret; either clears its
/// connection, since the tokens belong to the old client.
async fn credentials(
    connection: &mut PgConnection,
    name: &str,
    current: &Value,
    input: &Value,
    data: &mut Value,
) -> Result<(), ApiError> {
    let mut reset = false;
    if let Some(client_id) = input.get("client_id") {
        let client_id = match client_id {
            Value::Null => "",
            Value::String(text) => text.trim(),
            _ => return Err(invalid("client_id", "Must be text.")),
        };
        if client_id.len() > 500 {
            return Err(invalid("client_id", "Must be at most 500 characters."));
        }
        reset |= current["client_id"].as_str().unwrap_or_default() != client_id;
        data["client_id"] = json!(client_id);
    }
    let secret = match input.get("client_secret") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.trim().is_empty() || text == "Saved" => None,
        Some(Value::String(text)) if text.len() <= 2000 => Some(text.trim().to_owned()),
        Some(_) => {
            return Err(invalid(
                "client_secret",
                "Must be text up to 2000 characters.",
            ));
        }
    };
    if let Some(secret) = &secret {
        reset = true;
        sqlx::query("INSERT INTO app_integration_secrets(provider,client_secret) VALUES($1,$2) ON CONFLICT(provider) DO UPDATE SET client_secret=EXCLUDED.client_secret,updated=now()")
            .bind(name).bind(secret).execute(&mut *connection).await.map_err(ApiError::internal)?;
    }
    if reset {
        sqlx::query("UPDATE app_integration_secrets SET access_token=NULL,refresh_token=NULL,expires=NULL,updated=now() WHERE provider=$1")
            .bind(name).execute(&mut *connection).await.map_err(ApiError::internal)?;
        let has_secret: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_integration_secrets WHERE provider=$1 AND client_secret IS NOT NULL)")
            .bind(name).fetch_one(&mut *connection).await.map_err(ApiError::internal)?;
        let configured = has_secret && !data["client_id"].as_str().unwrap_or_default().is_empty();
        data["status"] = json!(if configured {
            "disconnected"
        } else {
            "needs_credentials"
        });
        data["account"] = json!({});
        data["error"] = Value::Null;
        data["connected_at"] = Value::Null;
    }
    Ok(())
}

/// The record actions a provider offers, for its admin metadata.
pub(super) fn actions() -> Value {
    json!([
        {"name":"connect","label":"Connect","icon":"link-variant","method":"post","methods":["POST"],"detail":true,"navigate":true,
         "description":"Sign in to the service and allow this app to use it, or check the saved token with it.",
         "url":"/api/admin/providers/:id/actions/connect/",
         "when":{"instance.status.in":["disconnected","connected","error"]}},
        {"name":"disconnect","label":"Disconnect","icon":"link-variant-off","method":"post","methods":["POST"],"detail":true,
         "confirm":"Disconnect this service? Anything that uses it stops working until someone connects it again.",
         "url":"/api/admin/providers/:id/actions/disconnect/",
         "when":{"instance.status.in":["connected","error"]}}
    ])
}

/// `POST /api/admin/providers/{id}/actions/{connect|disconnect}/`.
pub(super) async fn action(
    app: &App,
    headers: &HeaderMap,
    id: Uuid,
    name: &str,
    input: &Value,
) -> Result<Value, ApiError> {
    let person = user(app, headers).await?;
    let actor = app.actor(&person).await?;
    if !actor.granted("providers", "update") {
        return Err(ApiError::Forbidden);
    }
    let record: Value = sqlx::query_scalar(&format!(
        "SELECT {DOCUMENT} FROM app_records WHERE kind='providers' AND id=$1"
    ))
    .bind(id)
    .fetch_optional(&app.pool)
    .await
    .map_err(ApiError::internal)?
    .ok_or(ApiError::NotFound)?;
    let provider = record["integration"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let integration = app
        .registry
        .integrations
        .get(&provider)
        .ok_or(ApiError::NotFound)?;
    if integration.auth == Auth::Token {
        return token_action(app, &person, id, record, integration, name).await;
    }
    match name {
        "connect" => {
            let client_id = record["client_id"].as_str().unwrap_or_default();
            let has_secret: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_integration_secrets WHERE provider=$1 AND client_secret IS NOT NULL)")
                .bind(&provider).fetch_one(&app.pool).await.map_err(ApiError::internal)?;
            if client_id.is_empty() || !has_secret {
                return Err(ApiError::Conflict(
                    "Enter the client ID and client secret from the service's developer console first.".into(),
                ));
            }
            // Where to come back to: a page of this app, given as a path or a URL
            // on its origin. A preview frame's page is elsewhere, so it comes back
            // to the provider's own page.
            let next = super::next_path(app, input["next"].as_str());
            let state = random();
            sqlx::query("DELETE FROM app_integration_states WHERE expires<=now()")
                .execute(&app.pool)
                .await
                .map_err(ApiError::internal)?;
            sqlx::query("INSERT INTO app_integration_states(digest,provider,user_id,next,expires) VALUES($1,$2,$3,$4,now()+interval '10 minutes')")
                .bind(hash(&state))
                .bind(&provider)
                .bind(Uuid::parse_str(person["id"].as_str().unwrap_or_default()).map_err(ApiError::internal)?)
                .bind(next)
                .execute(&app.pool)
                .await
                .map_err(ApiError::internal)?;
            let mut url =
                url::Url::parse(&integration.authorize_url).map_err(ApiError::internal)?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("response_type", "code")
                    .append_pair("client_id", client_id)
                    .append_pair("redirect_uri", &callback_url(&app.origin, &provider))
                    .append_pair("state", &state);
                if !integration.scopes.is_empty() {
                    query.append_pair("scope", &integration.scopes.join(" "));
                }
                for (key, value) in &integration.authorize_params {
                    query.append_pair(key, value);
                }
            }
            Ok(json!({"redirect":url.as_str()}))
        }
        "disconnect" => {
            let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
            sqlx::query("UPDATE app_integration_secrets SET access_token=NULL,refresh_token=NULL,expires=NULL,updated=now() WHERE provider=$1")
                .bind(&provider).execute(&mut *tx).await.map_err(ApiError::internal)?;
            let record: Value = sqlx::query_scalar(&format!(
                "UPDATE app_records SET data=data||jsonb_build_object('status','disconnected','account','{{}}'::jsonb,'error',NULL,'connected_at',NULL),updated=now() WHERE kind='providers' AND id=$1 RETURNING {DOCUMENT}"
            ))
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
            tx.commit().await.map_err(ApiError::internal)?;
            Ok(json!({"provider":super::public_record("providers", record)}))
        }
        _ => Err(ApiError::NotFound),
    }
}

/// Connect a token provider by checking its token with the service, or
/// disconnect it by forgetting the token.
async fn token_action(
    app: &App,
    person: &Value,
    id: Uuid,
    record: Value,
    integration: &Integration,
    name: &str,
) -> Result<Value, ApiError> {
    let provider = &integration.name;
    // Connecting stamps `connected_at` with the database's clock.
    let update = |patch: Value, connected: bool| async move {
        let record: Value = sqlx::query_scalar(&format!(
            "UPDATE app_records SET data=data||$2||CASE WHEN $3 THEN jsonb_build_object('connected_at',now()) ELSE '{{}}'::jsonb END,updated=now() WHERE kind='providers' AND id=$1 RETURNING {DOCUMENT}"
        ))
        .bind(id)
        .bind(patch)
        .bind(connected)
        .fetch_one(&app.pool)
        .await
        .map_err(ApiError::internal)?;
        Ok::<_, ApiError>(json!({"provider":super::public_record("providers", record)}))
    };
    match name {
        "connect" => {
            let token: Option<String> = sqlx::query_scalar(
                "SELECT client_secret FROM app_integration_secrets WHERE provider=$1",
            )
            .bind(provider)
            .fetch_optional(&app.pool)
            .await
            .map_err(ApiError::internal)?
            .flatten();
            let Some(token) = token else {
                return Err(ApiError::Conflict(
                    "Enter the token the service issued first.".into(),
                ));
            };
            let connection = connection(integration, &record, token);
            if connection.base_url.is_empty() {
                return Err(ApiError::Conflict(
                    "Enter the service's base URL first.".into(),
                ));
            }
            if let Some(check) = &integration.check {
                let refused = match connection.get(check).send().await {
                    Ok(response) if response.status().is_success() => None,
                    Ok(response) => Some(format!(
                        "the service answered {} at {}",
                        response.status(),
                        connection.url(check)
                    )),
                    Err(_) => Some(format!("{} could not be reached", connection.base_url)),
                };
                if let Some(message) = refused {
                    let message =
                        format!("Connecting failed: {message}. Check the token and base URL.");
                    update(
                        json!({"status":"error","error":message,"connected_at":null}),
                        false,
                    )
                    .await?;
                    return Err(ApiError::Conflict(message));
                }
            }
            update(
                json!({"status":"connected","error":null,"connected_by":person["id"]}),
                true,
            )
            .await
        }
        "disconnect" => {
            sqlx::query("UPDATE app_integration_secrets SET client_secret=NULL,access_token=NULL,refresh_token=NULL,expires=NULL,updated=now() WHERE provider=$1")
                .bind(provider).execute(&app.pool).await.map_err(ApiError::internal)?;
            update(
                json!({"status":"needs_credentials","account":{},"error":null,"connected_at":null}),
                false,
            )
            .await
        }
        _ => Err(ApiError::NotFound),
    }
}

/// `GET /api/integrations/{name}/callback`: finish a connection the app started.
pub(super) async fn callback(
    State(app): State<App>,
    Path(provider): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Result<Response, ApiError> {
    let integration = app
        .registry
        .integrations
        .get(&provider)
        .ok_or(ApiError::NotFound)?
        .clone();
    let state = params.get("state").map(String::as_str).unwrap_or_default();
    let started: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "DELETE FROM app_integration_states WHERE digest=$1 AND provider=$2 AND expires>now() RETURNING user_id,next",
    )
    .bind(hash(state))
    .bind(&provider)
    .fetch_optional(&app.pool)
    .await
    .map_err(ApiError::internal)?;
    let Some((user_id, next)) = started else {
        return Err(ApiError::Parse(
            "This connection request has expired or was already used. Start again from the app."
                .into(),
        ));
    };
    let (id, record): (Uuid, Value) = sqlx::query_as(
        "SELECT id,data FROM app_records WHERE kind='providers' AND data->>'integration'=$1",
    )
    .bind(&provider)
    .fetch_one(&app.pool)
    .await
    .map_err(ApiError::internal)?;
    let back = format!(
        "{}{}",
        app.origin,
        next.unwrap_or_else(|| format!("/providers/{id}/"))
    );
    let outcome = match (params.get("code"), params.get("error")) {
        (_, Some(error)) => Err(params
            .get("error_description")
            .cloned()
            .unwrap_or_else(|| error.clone())),
        (Some(code), None) => {
            let secret: Option<String> = sqlx::query_scalar(
                "SELECT client_secret FROM app_integration_secrets WHERE provider=$1",
            )
            .bind(&provider)
            .fetch_optional(&app.pool)
            .await
            .map_err(ApiError::internal)?
            .flatten();
            let client_id = record["client_id"].as_str().unwrap_or_default();
            exchange(
                &integration,
                client_id,
                secret.as_deref().unwrap_or_default(),
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", &callback_url(&app.origin, &provider)),
                ],
            )
            .await
        }
        (None, None) => Err("The service did not return an authorization code.".to_owned()),
    };
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    match outcome {
        Ok(tokens) => {
            store(&mut tx, &provider, &tokens).await?;
            let account: Map<String, Value> = integration
                .account_params
                .iter()
                .filter_map(|name| params.get(name).map(|value| (name.clone(), json!(value))))
                .collect();
            sqlx::query("UPDATE app_records SET data=data||jsonb_build_object('status','connected','account',$2::jsonb,'error',NULL,'connected_at',now(),'connected_by',$3::text),updated=now() WHERE kind='providers' AND id=$1")
                .bind(id)
                .bind(Value::Object(account))
                .bind(user_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
        }
        Err(message) => {
            sqlx::query("UPDATE app_records SET data=data||jsonb_build_object('status',CASE WHEN data->>'status'='connected' THEN 'connected' ELSE 'error' END,'error',$2::text),updated=now() WHERE kind='providers' AND id=$1")
                .bind(id)
                .bind(format!("Connecting failed: {}", truncate(&message)))
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
        }
    }
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Redirect::to(&back).into_response())
}

/// The access token, refresh token, client secret, and whether the access
/// token expires within a minute.
type TokenRow = (Option<String>, Option<String>, Option<String>, bool);
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
}
fn truncate(message: &str) -> String {
    message.chars().take(300).collect()
}
/// POST to the token endpoint; an error carries the service's explanation.
async fn exchange(
    integration: &Integration,
    client_id: &str,
    client_secret: &str,
    form: &[(&str, &str)],
) -> Result<Tokens, String> {
    let mut form: Vec<(&str, &str)> = form.to_vec();
    let mut request = http()
        .post(&integration.token_url)
        .header("accept", "application/json");
    match integration.client_auth {
        ClientAuth::Basic => request = request.basic_auth(client_id, Some(client_secret)),
        ClientAuth::Body => {
            form.push(("client_id", client_id));
            form.push(("client_secret", client_secret));
        }
    }
    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|_| "The service could not be reached.".to_owned())?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(body["error_description"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .map_or_else(|| format!("the service answered {status}"), str::to_owned));
    }
    let access_token = body["access_token"]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| "The service returned no access token.".to_owned())?;
    Ok(Tokens {
        access_token: access_token.to_owned(),
        refresh_token: body["refresh_token"].as_str().map(str::to_owned),
        expires_in: body["expires_in"]
            .as_i64()
            .or_else(|| body["expires_in"].as_str().and_then(|s| s.parse().ok())),
    })
}
async fn store(
    connection: &mut PgConnection,
    provider: &str,
    tokens: &Tokens,
) -> Result<(), ApiError> {
    // A service that does not rotate refresh tokens omits them on refresh.
    sqlx::query("INSERT INTO app_integration_secrets(provider,access_token,refresh_token,expires) VALUES($1,$2,$3,now()+$4::bigint*interval '1 second') ON CONFLICT(provider) DO UPDATE SET access_token=EXCLUDED.access_token,refresh_token=coalesce(EXCLUDED.refresh_token,app_integration_secrets.refresh_token),expires=EXCLUDED.expires,updated=now()")
        .bind(provider)
        .bind(&tokens.access_token)
        .bind(&tokens.refresh_token)
        .bind(tokens.expires_in)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// The current connection to `name`, refreshing its access token first when it
/// expires within a minute. Refreshes commit on their own connection when one
/// is available, so a rotated refresh token survives the caller rolling back.
pub(super) async fn connect(
    context: &mut Context<'_>,
    pool: Option<&PgPool>,
    name: &str,
) -> Result<Connection, ApiError> {
    let integration = context
        .registry
        .integrations
        .get(name)
        .ok_or_else(|| ApiError::Parse(format!("Unknown integration: {name}")))?
        .clone();
    match pool {
        Some(pool) => {
            let mut tx = pool.begin().await.map_err(ApiError::internal)?;
            let result = current(&mut tx, &integration).await;
            tx.commit().await.map_err(ApiError::internal)?;
            result
        }
        None => current(&mut *context.connection, &integration).await,
    }
}
async fn current(
    connection: &mut PgConnection,
    integration: &Integration,
) -> Result<Connection, ApiError> {
    let name = &integration.name;
    let record: Value = sqlx::query_scalar(
        "SELECT data FROM app_records WHERE kind='providers' AND data->>'integration'=$1",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?
    .unwrap_or(Value::Null);
    let not_connected = || {
        ApiError::Conflict(format!(
            "{} is not connected. An administrator can connect it under Providers.",
            integration.label
        ))
    };
    if record["enabled"] == false {
        return Err(ApiError::Conflict(format!(
            "{} is turned off under Providers.",
            integration.label
        )));
    }
    if integration.auth == Auth::Token {
        // A token is used once an administrator has connected it.
        if record["status"] != "connected" {
            return Err(not_connected());
        }
        let token: Option<String> = sqlx::query_scalar(
            "SELECT client_secret FROM app_integration_secrets WHERE provider=$1",
        )
        .bind(name)
        .fetch_optional(&mut *connection)
        .await
        .map_err(ApiError::internal)?
        .flatten();
        return token
            .map(|token| self::connection(integration, &record, token))
            .ok_or_else(not_connected);
    }
    // Lock the tokens: a refresh token may be single-use.
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT access_token,refresh_token,client_secret,coalesce(expires<now()+interval '60 seconds',false) FROM app_integration_secrets WHERE provider=$1 FOR UPDATE",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    let Some((Some(access_token), refresh_token, client_secret, expiring)) = row else {
        return Err(not_connected());
    };
    if !expiring {
        return Ok(self::connection(integration, &record, access_token));
    }
    let Some(refresh_token) = refresh_token else {
        return Err(not_connected());
    };
    match exchange(
        integration,
        record["client_id"].as_str().unwrap_or_default(),
        client_secret.as_deref().unwrap_or_default(),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ],
    )
    .await
    {
        Ok(tokens) => {
            store(connection, name, &tokens).await?;
            Ok(self::connection(integration, &record, tokens.access_token))
        }
        Err(message) => {
            sqlx::query("UPDATE app_records SET data=data||jsonb_build_object('status','error','error',$2::text),updated=now() WHERE kind='providers' AND data->>'integration'=$1")
                .bind(name)
                .bind(format!("Refreshing access failed: {}. Connect it again.", truncate(&message)))
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            Err(ApiError::Conflict(format!(
                "{} needs to be connected again: {}",
                integration.label,
                truncate(&message)
            )))
        }
    }
}
