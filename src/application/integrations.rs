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
use super::{
    App, DOCUMENT,
    extensions::{Action, ActionDetails, Actor, Context, Handler, Hook, Model, Registry},
    hash, random, user,
};
use crate::{ApiError, FieldErrors, FieldKind};
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
    /// kept on the provider record (an accounting service may send its company id).
    pub account_params: Vec<String>,
    pub client_auth: ClientAuth,
    /// The provider field naming the record each connection serves, when
    /// connections belong to records rather than the whole app (see
    /// [`Self::per`]).
    pub per: Option<String>,
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
            per: None,
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
    /// Connect records to the service each on their own, rather than the whole
    /// app once: a company or entity to its own books, or each person to their
    /// own account. `field` is a relation the app adds to the providers model
    /// for the record a connection serves:
    ///
    /// ```ignore
    /// registry.extend("providers", |providers| {
    ///     providers.relation("entity", "entities").label("entity", "Entity")
    /// })?;
    /// registry.integration(Integration::oauth2("books", "Books").per("entity"))?;
    /// ```
    ///
    /// Each record's provider names it in that field; code reaches it with
    /// [`Context::integration_for`](super::extensions::Context::integration_for),
    /// and roles may grant people their own (`{"providers": {"create": {"user":
    /// "$user.id"}, "update": {"user": "$user.id"}, "connect": {"user":
    /// "$user.id"}}}`). The provider the code registers keeps the client ID and
    /// secret every connection shares, and may itself serve a record.
    pub fn per(mut self, field: &str) -> Self {
        self.per = Some(field.into());
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
        if self
            .per
            .as_ref()
            .is_some_and(|model| !super::extensions::identifier(model))
        {
            return Err(invalid(
                "name the provider field it connects per, like entity or user",
            ));
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
    /// e.g. `{"companyId": "9130..."}`.
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
/// A connection to `integration` with `token`, at the record's base URL, else
/// the base URL of the code's provider (`main`, for a connection serving a
/// record), else the integration's default.
fn connection(
    integration: &Integration,
    record: &Value,
    main: Option<&Value>,
    token: String,
) -> Connection {
    let (header, value) = match integration.auth {
        Auth::OAuth2 => ("Authorization".to_owned(), format!("Bearer {token}")),
        Auth::Token => (
            integration.token_header.clone(),
            integration.token_format.replace("{token}", &token),
        ),
    };
    Connection {
        name: integration.name.clone(),
        base_url: effective_base_url(integration, record, main),
        access_token: token,
        account: record["account"].clone(),
        header,
        value,
    }
}
fn effective_base_url(integration: &Integration, record: &Value, main: Option<&Value>) -> String {
    [Some(record), main]
        .into_iter()
        .flatten()
        .find_map(|record| {
            record["base_url"]
                .as_str()
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
        })
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

/// Whether a provider is the one the app's code registers for its service,
/// rather than one added to serve a record. Records from before connections
/// could serve records carry no flag and are.
pub(super) fn primary(record: &Value) -> bool {
    record["primary"] != false
}
/// Where a provider's secrets are kept: under the service's name for the
/// provider the code registers, under the name and the provider's id for one
/// serving a record.
fn key(record: &Value) -> String {
    let name = record["integration"].as_str().unwrap_or_default();
    if primary(record) {
        name.to_owned()
    } else {
        format!("{name}:{}", record["id"].as_str().unwrap_or_default())
    }
}
/// The provider the app's code registers for `name`.
async fn main_record(connection: &mut PgConnection, name: &str) -> Result<Value, ApiError> {
    sqlx::query_scalar(&format!(
        "SELECT {DOCUMENT} FROM app_records WHERE kind='providers' AND data->>'integration'=$1 AND coalesce(data->>'primary','true')='true' ORDER BY created LIMIT 1"
    ))
    .bind(name)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::Conflict(format!("{name} has no provider yet; restart the app.")))
}

/// Shown in place of a saved client secret or token, which the record never
/// holds.
const SAVED: &str = "Saved";

/// The built-in `providers` model: every outside service the app connects to,
/// and the providers an administrator adds by hand (a mail or sign-in service
/// the app's code reads). It is an ordinary model, so roles grant its
/// operations, its Connect and Disconnect actions and its fields as they do
/// any other's, with conditions (`{"providers": {"update": {"user":
/// "$user.id"}, "connect": {"user": "$user.id"}}}`), and an app may add fields
/// to it with [`Registry::extend`], such as the record each connection serves
/// (see [`Integration::per`]). Its hook keeps secrets out of the record and
/// the fields the service owns consistent.
#[allow(clippy::too_many_lines)]
pub(super) fn model() -> Model {
    let text = |model: Model, name: &str, label: &str, description: &str| {
        model
            .field(name, FieldKind::String)
            .label(name, label)
            .describe(name, description)
    };
    let mut model = Model::new("providers", "provider").metadata(json!({
        "icon":"connection","section":"Core","label":"Providers",
        "list_fields":["name","kind","status","enabled"],
    }));
    model = text(model, "name", "Name", "What people call this provider.");
    model = text(
        model,
        "kind",
        "Kind",
        "What sort of provider this is; a service in the app's code sets its own.",
    );
    model = model
        .field("enabled", FieldKind::Boolean)
        .label("enabled", "Enabled")
        .describe(
            "enabled",
            "Turn off to stop the app from using this service without disconnecting it.",
        );
    model = text(
        model,
        "integration",
        "Integration",
        "The service in the app's code this provider connects, if any. Choose one to add a connection serving one record.",
    );
    model = text(
        model,
        "description",
        "Description",
        "What the app uses this service for.",
    )
    .readonly("description");
    model = text(model, "status", "Status", "For an integration: needs_credentials until its client ID and secret, or its token, are saved; then disconnected until someone presses Connect; connected; or error when access was refused or lost.").readonly("status");
    model = model
        .field("account", FieldKind::Json)
        .label("account", "Account")
        .describe(
            "account",
            "The account this app is connected to, as the service identified it.",
        )
        .readonly("account");
    model = model
        .field("connected_at", FieldKind::DateTime)
        .label("connected_at", "Connected at")
        .describe("connected_at", "When the service was last connected.")
        .readonly("connected_at");
    model = text(
        model,
        "connected_by",
        "Connected by",
        "The id of the person who last connected it.",
    )
    .readonly("connected_by");
    model = text(
        model,
        "error",
        "Error",
        "Why the last attempt to connect or refresh access failed.",
    )
    .readonly("error");
    model = text(
        model,
        "client_id",
        "Client ID",
        "The OAuth client ID from the service's developer console.",
    );
    model = text(
        model,
        "client_secret",
        "Client secret",
        "The OAuth client secret. It is kept privately and never shown again; enter a new one to replace it.",
    );
    model = text(
        model,
        "token",
        "Token",
        "The API token (key) the service issued for this app. It is kept privately and never shown again; enter a new one to replace it.",
    );
    model = text(
        model,
        "redirect_uri",
        "Redirect URI",
        "Register this exact URL as a redirect URI in the service's developer console.",
    )
    .readonly("redirect_uri");
    model = text(
        model,
        "base_url",
        "Base URL",
        "Where the service's API is, when not the default: another tenant, a sandbox or a test server.",
    );
    model = text(
        model,
        "default_base_url",
        "Default base URL",
        "The service's API location for this environment, used when Base URL is blank.",
    )
    .readonly("default_base_url");
    model = model
        .field("primary", FieldKind::Boolean)
        .label("primary", "From the app's code")
        .describe("primary", "Whether the app's code registers this provider: it holds the client ID and secret every connection to the service signs in with, and serves the whole app unless it names a record.")
        .readonly("primary");
    if let Some(field) = model
        .resource
        .fields
        .iter_mut()
        .find(|f| f.name == "integration")
    {
        // Chosen when a connection is added, then fixed.
        field.immutable = true;
    }
    // Each kind of integration shows only its own fields, and only the code's
    // provider holds the client.
    for (field, extra) in [
        ("kind", json!({"depends":{"integration.isnull":true}})),
        (
            "client_id",
            json!({"depends":{"kind":"oauth2","primary":true}}),
        ),
        (
            "client_secret",
            json!({"secret":true,"depends":{"kind":"oauth2","primary":true}}),
        ),
        (
            "redirect_uri",
            json!({"depends":{"kind":"oauth2","primary":true}}),
        ),
        ("token", json!({"secret":true,"depends":{"kind":"token"}})),
        ("base_url", json!({"depends":{"integration.isnull":false}})),
        (
            "default_base_url",
            json!({"depends":{"integration.isnull":false},"hide":true}),
        ),
    ] {
        model = model.field_metadata(field, extra);
    }
    model.hook(Providers)
}
/// Register the providers model and its Connect and Disconnect actions; every
/// registry starts with them.
pub(super) fn register(registry: &mut Registry) {
    registry.models.insert("providers".into(), model());
    let action = |label: &str,
                  icon: &str,
                  description: &str,
                  confirm: Option<&str>,
                  status: &[&str],
                  navigate: bool| Action {
        roles: std::collections::BTreeSet::new(),
        handler: std::sync::Arc::new(Elsewhere),
        details: ActionDetails {
            label: Some(label.into()),
            icon: Some(icon.into()),
            description: Some(description.into()),
            confirm: confirm.map(str::to_owned),
            when: Map::from_iter([("status__in".to_owned(), json!(status))]),
            parameters: Map::new(),
            navigate,
        },
    };
    registry.actions.insert(
        ("providers".into(), "connect".into()),
        action("Connect", "link-variant", "Sign in to the service and allow this app to use it, or check the saved token with it.", None, &["disconnected", "connected", "error"], true),
    );
    registry.actions.insert(
        ("providers".into(), "disconnect".into()),
        action("Disconnect", "link-variant-off", "Forget this app's access to the service, and a saved token.", Some("Disconnect this service? Anything that uses it stops working until someone connects it again."), &["disconnected", "connected", "error"], false),
    );
}
/// Provider actions run outside the application write lock, since they call
/// the service; the API routes them to [`action`].
struct Elsewhere;
#[async_trait::async_trait]
impl Handler for Elsewhere {
    async fn run(&self, _: &mut Context<'_>, _: Value) -> Result<Value, ApiError> {
        Err(ApiError::Parse(
            "Run provider actions through /api/admin/providers/<id>/actions/<name>/.".into(),
        ))
    }
}

/// Keeps a provider consistent with its service: what a service's provider
/// may hold, its secrets out of the record, its status in step with them.
struct Providers;
#[async_trait::async_trait]
impl Hook for Providers {
    async fn before(
        &self,
        context: &mut Context<'_>,
        operation: &str,
        previous: Option<&Value>,
        record: &mut Value,
    ) -> Result<(), ApiError> {
        match (operation, previous) {
            ("create", _) => created(context, record).await,
            ("update", Some(previous)) => changed(context, previous, record).await,
            ("delete", Some(previous)) => removed(context, previous).await,
            _ => Ok(()),
        }
    }
}
fn filled(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}
/// Keep `field` trimmed, refusing a blank or overlong one.
fn trimmed(record: &mut Value, field: &str, label: &str, limit: usize) -> Result<(), ApiError> {
    let text = record[field]
        .as_str()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if text.is_empty() || text.chars().count() > limit {
        return Err(invalid(
            field,
            &format!("{label} must be 1 to {limit} characters."),
        ));
    }
    record[field] = json!(text);
    Ok(())
}
/// A provider added by hand takes a name and a kind, and no credentials.
fn by_hand(record: &mut Value) -> Result<(), ApiError> {
    trimmed(record, "name", "Name", 200)?;
    trimmed(record, "kind", "Kind", 100)?;
    for field in ["client_id", "client_secret", "token", "base_url"] {
        if filled(&record[field]) {
            return Err(invalid(
                field,
                "Only providers from the app's code take credentials or a base URL.",
            ));
        }
    }
    if record["enabled"].is_null() {
        record["enabled"] = json!(true);
    }
    Ok(())
}
/// A new secret given for `field`, if any; the record keeps only whether one
/// is saved (`Saved`), as before.
fn take_secret(
    record: &mut Value,
    previous: Option<&Value>,
    field: &str,
    limit: usize,
) -> Result<Option<String>, ApiError> {
    if !(record[field].is_null() || record[field].is_string()) {
        return Err(invalid(
            field,
            &format!("Must be text up to {limit} characters."),
        ));
    }
    let given = record[field]
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty() && *text != SAVED)
        .map(str::to_owned);
    if given.as_ref().is_some_and(|text| text.len() > limit) {
        return Err(invalid(
            field,
            &format!("Must be text up to {limit} characters."),
        ));
    }
    match previous.map(|previous| &previous[field]) {
        Some(Value::String(saved)) if saved == SAVED => record[field] = json!(SAVED),
        _ => {
            record.as_object_mut().map(|o| o.remove(field));
        }
    }
    Ok(given)
}
async fn store_secret(context: &mut Context<'_>, key: &str, secret: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO app_integration_secrets(provider,client_secret) VALUES($1,$2) ON CONFLICT(provider) DO UPDATE SET client_secret=EXCLUDED.client_secret,access_token=NULL,refresh_token=NULL,expires=NULL,updated=now()")
        .bind(key)
        .bind(secret)
        .execute(&mut *context.connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
/// Keep a base URL as [`base_url`] does, or drop a blank one. Returns whether
/// it moved.
fn keep_base_url(record: &mut Value, previous: Option<&Value>) -> Result<bool, ApiError> {
    let before = previous.and_then(|previous| previous["base_url"].as_str());
    match &record["base_url"] {
        Value::String(url) if !url.trim().is_empty() => {
            let url =
                base_url(url).map_err(|message| invalid("base_url", &capitalize(&message)))?;
            let moved = before != Some(url.as_str());
            record["base_url"] = json!(url);
            Ok(moved)
        }
        Value::Null | Value::String(_) => {
            record.as_object_mut().map(|o| o.remove("base_url"));
            Ok(before.is_some())
        }
        _ => Err(invalid("base_url", "Must be text.")),
    }
}
fn capitalize(message: &str) -> String {
    let mut chars = message.chars();
    chars.next().map_or_else(String::new, |first| {
        format!("{}{}.", first.to_uppercase(), chars.as_str())
    })
}
/// The noun for a link field in messages: `user`, `entity`.
fn noun(field: &str) -> String {
    field.replace('_', " ")
}
/// Refuse a second connection to the same service for one record.
async fn taken(
    context: &mut Context<'_>,
    integration: &Integration,
    field: &str,
    target: &Value,
    id: &Value,
) -> Result<(), ApiError> {
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind='providers' AND data->>'integration'=$1 AND data->>$2=$3 AND id::text IS DISTINCT FROM $4)",
    )
    .bind(&integration.name)
    .bind(field)
    .bind(target.as_str().unwrap_or_default())
    .bind(id.as_str())
    .fetch_one(&mut *context.connection)
    .await
    .map_err(ApiError::internal)?;
    if taken {
        return Err(invalid(
            field,
            &format!(
                "This {} already has a {} connection.",
                noun(field),
                integration.label
            ),
        ));
    }
    Ok(())
}
/// A provider being added: one by hand, or a connection to a service the app
/// connects per record, serving the record its link field names (a person
/// adding their own connection serves themselves when they name nobody).
async fn created(context: &mut Context<'_>, record: &mut Value) -> Result<(), ApiError> {
    let Some(name) = record["integration"].as_str().map(str::to_owned) else {
        record.as_object_mut().map(|o| o.remove("integration"));
        return by_hand(record);
    };
    let integration = context
        .registry
        .integrations
        .get(&name)
        .cloned()
        .ok_or_else(|| invalid("integration", "Choose a service the app connects to."))?;
    let Some(field) = integration.per.clone() else {
        return Err(invalid(
            "integration",
            &format!(
                "{} has one connection for the whole app; set it up on its provider.",
                integration.label
            ),
        ));
    };
    let to_people = context
        .registry
        .models
        .get("providers")
        .and_then(|model| model.resource.field(&field))
        .and_then(|field| field.related_resource.as_deref())
        == Some("users");
    if record[&field].is_null() && to_people && !context.actor.id.is_empty() {
        record[&field] = json!(context.actor.id);
    }
    if !filled(&record[&field]) {
        return Err(invalid(
            &field,
            &format!("Choose the {} this connection serves.", noun(&field)),
        ));
    }
    let target = record[&field].clone();
    taken(context, &integration, &field, &target, &record["id"]).await?;
    if !filled(&record["name"]) {
        let served: Option<String> = sqlx::query_scalar(
            "SELECT coalesce(data->>'name',data->>'email') FROM app_records WHERE id::text=$1",
        )
        .bind(target.as_str().unwrap_or_default())
        .fetch_optional(&mut *context.connection)
        .await
        .map_err(ApiError::internal)?
        .flatten();
        record["name"] = json!(served.map_or_else(
            || integration.label.clone(),
            |served| format!("{} ({served})", integration.label)
        ));
    }
    trimmed(record, "name", "Name", 200)?;
    for field in ["client_id", "client_secret"] {
        if filled(&record[field]) {
            return Err(invalid(
                field,
                "This connection signs in with the client ID and secret saved on the service's main provider.",
            ));
        }
    }
    record.as_object_mut().map(|o| o.remove("client_id"));
    // A connection serving a record keeps its secrets under its own key.
    record["primary"] = json!(false);
    let token = integration.auth == Auth::Token;
    let secret = take_secret(record, None, "token", 4000)?;
    if !token && secret.is_some() {
        return Err(invalid("token", "Only a token provider takes this."));
    }
    take_secret(record, None, "client_secret", 2000)?;
    keep_base_url(record, None)?;
    if let Some(secret) = &secret {
        store_secret(context, &key(record), secret).await?;
        record["token"] = json!(SAVED);
    }
    let ready = if token {
        secret.is_some()
    } else {
        client_ready(&mut *context.connection, &name).await?
    };
    record["kind"] = json!(integration.kind());
    record["description"] = json!(integration.description);
    record["primary"] = json!(false);
    record["account"] = json!({});
    record["status"] = json!(if ready {
        "disconnected"
    } else {
        "needs_credentials"
    });
    if record["enabled"].is_null() {
        record["enabled"] = json!(true);
    }
    Ok(())
}
/// A provider being changed. A service's provider keeps its kind; a new token
/// or base URL waits to be checked again; a new client on the code's provider
/// clears every connection to the service, since the tokens belong to the old
/// one.
#[allow(clippy::too_many_lines)]
async fn changed(
    context: &mut Context<'_>,
    previous: &Value,
    record: &mut Value,
) -> Result<(), ApiError> {
    for fixed in ["integration", "primary"] {
        record[fixed] = previous[fixed].clone();
    }
    let Some(name) = previous["integration"].as_str().map(str::to_owned) else {
        return by_hand(record);
    };
    trimmed(record, "name", "Name", 200)?;
    if record["kind"] != previous["kind"] {
        return Err(invalid(
            "kind",
            "This provider's kind is set by the app's code.",
        ));
    }
    let Some(integration) = context.registry.integrations.get(&name).cloned() else {
        // The code no longer registers the service: only names and switches change.
        return Ok(());
    };
    let main = primary(previous);
    if let Some(field) = &integration.per {
        if record[field] != previous[field] {
            if record[field].is_null() {
                if !main {
                    return Err(invalid(
                        field,
                        &format!("Choose the {} this connection serves.", noun(field)),
                    ));
                }
            } else {
                let target = record[field].clone();
                taken(context, &integration, field, &target, &previous["id"]).await?;
            }
        }
    }
    let token = integration.auth == Auth::Token;
    let new_token = take_secret(record, Some(previous), "token", 4000)?;
    let new_secret = take_secret(record, Some(previous), "client_secret", 2000)?;
    let client_id = |value: &Value| value.as_str().map(str::trim).unwrap_or_default().to_owned();
    match &record["client_id"] {
        Value::String(text) if text.trim().len() > 500 => {
            return Err(invalid("client_id", "Must be at most 500 characters."));
        }
        Value::String(text) => record["client_id"] = json!(text.trim()),
        Value::Null => {}
        _ => return Err(invalid("client_id", "Must be text.")),
    }
    let new_client = client_id(&record["client_id"]) != client_id(&previous["client_id"]);
    if token {
        if new_secret.is_some() || (new_client && filled(&record["client_id"])) {
            let field = if new_secret.is_some() {
                "client_secret"
            } else {
                "client_id"
            };
            return Err(invalid(field, "Only an OAuth provider takes this."));
        }
    } else {
        if new_token.is_some() {
            return Err(invalid("token", "Only a token provider takes this."));
        }
        if !main && (new_secret.is_some() || new_client) {
            return Err(invalid(
                if new_secret.is_some() {
                    "client_secret"
                } else {
                    "client_id"
                },
                "This connection signs in with the client ID and secret saved on the service's main provider.",
            ));
        }
    }
    let moved = keep_base_url(record, Some(previous))?;
    let secrets = key(previous);
    let reset = |record: &mut Value, ready: bool| {
        record["status"] = json!(if ready {
            "disconnected"
        } else {
            "needs_credentials"
        });
        record["account"] = json!({});
        record["error"] = Value::Null;
        record["connected_at"] = Value::Null;
    };
    if token {
        if let Some(secret) = &new_token {
            store_secret(context, &secrets, secret).await?;
            record["token"] = json!(SAVED);
        }
        if new_token.is_some() || moved {
            reset(record, record["token"] == SAVED);
        }
    } else if main && (new_client || new_secret.is_some()) {
        if let Some(secret) = &new_secret {
            store_secret(context, &secrets, secret).await?;
            record["client_secret"] = json!(SAVED);
        }
        sqlx::query("UPDATE app_integration_secrets SET access_token=NULL,refresh_token=NULL,expires=NULL,updated=now() WHERE split_part(provider,':',1)=$1")
            .bind(&name)
            .execute(&mut *context.connection)
            .await
            .map_err(ApiError::internal)?;
        let ready = record["client_secret"] == SAVED && filled(&record["client_id"]);
        reset(record, ready);
        // Every connection serving a record signed in with the old client.
        sqlx::query("UPDATE app_records SET data=data||jsonb_build_object('status',$2::text,'account','{}'::jsonb,'error',NULL,'connected_at',NULL),updated=now() WHERE kind='providers' AND data->>'integration'=$1 AND data->>'primary'='false'")
            .bind(&name)
            .bind(if ready { "disconnected" } else { "needs_credentials" })
            .execute(&mut *context.connection)
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(())
}
/// A provider being removed. The one the app's code registers would come
/// back, so it is disconnected instead; a connection serving a record takes
/// its secrets with it.
async fn removed(context: &mut Context<'_>, previous: &Value) -> Result<(), ApiError> {
    if !previous["integration"].is_string() {
        return Ok(());
    }
    if primary(previous) {
        return Err(ApiError::Conflict(
            "This provider comes from the app's code and cannot be removed; disconnect it instead."
                .into(),
        ));
    }
    sqlx::query("DELETE FROM app_integration_secrets WHERE provider=$1")
        .bind(key(previous))
        .execute(&mut *context.connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
/// Whether the provider the code registers for `name` has its client ID and
/// secret, so connections serving records can sign in with them.
async fn client_ready(connection: &mut PgConnection, name: &str) -> Result<bool, ApiError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app_records p JOIN app_integration_secrets s ON s.provider=$1 AND s.client_secret IS NOT NULL WHERE p.kind='providers' AND p.data->>'integration'=$1 AND coalesce(p.data->>'primary','true')='true' AND coalesce(p.data->>'client_id','')<>'')",
    )
    .bind(name)
    .fetch_one(&mut *connection)
    .await
    .map_err(ApiError::internal)
}
/// The provider fields linking connections to people.
pub(super) fn user_links(registry: &Registry) -> Vec<String> {
    registry
        .models
        .get("providers")
        .map(|model| {
            model
                .resource
                .fields
                .iter()
                .filter(|field| field.related_resource.as_deref() == Some("users") && !field.many)
                .map(|field| field.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Keep one `providers` record per registered integration, the one its code
/// registers (`primary`), adding new ones, named after the integration's
/// label, as needing credentials, and refreshing the kind and description of
/// every provider of the service. Administrators may rename them.
pub(super) async fn sync_providers(
    connection: &mut PgConnection,
    registry: &Registry,
) -> Result<(), ApiError> {
    let providers = registry
        .models
        .get("providers")
        .map(|model| &model.resource);
    for integration in registry.integrations.values() {
        if let Some(per) = &integration.per {
            let linked = providers
                .and_then(|resource| resource.field(per))
                .is_some_and(|field| field.related_resource.is_some() && !field.many);
            if !linked {
                return Err(ApiError::Parse(format!(
                    "Integration {}: add a relation field {per} to providers with registry.extend(\"providers\", ...) to connect it per record",
                    integration.name
                )));
            }
        }
        sqlx::query(
            "UPDATE app_records SET data=data||'{\"primary\":true}'::jsonb WHERE kind='providers' AND data->>'integration'=$1 AND NOT data ? 'primary'",
        )
        .bind(&integration.name)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        let presentation = json!({"kind":integration.kind(),"description":integration.description});
        sqlx::query(
            "UPDATE app_records SET data=data||$2,updated=now() WHERE kind='providers' AND data->>'integration'=$1 AND NOT (data @> $2)",
        )
        .bind(&integration.name)
        .bind(&presentation)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
        let mut data = presentation;
        data["name"] = json!(integration.label);
        data["integration"] = json!(integration.name);
        data["enabled"] = json!(true);
        data["status"] = json!("needs_credentials");
        data["account"] = json!({});
        data["primary"] = json!(true);
        sqlx::query(
            "INSERT INTO app_records(id,kind,data) SELECT $1,'providers',$2 WHERE NOT EXISTS (SELECT 1 FROM app_records WHERE kind='providers' AND data->>'integration'=$3 AND data->>'primary'='true')",
        )
        .bind(Uuid::new_v4())
        .bind(&data)
        .bind(&integration.name)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    }
    // Records from before secrets were marked on them show what is saved.
    sqlx::query("UPDATE app_records p SET data=p.data||jsonb_build_object(CASE WHEN p.data->>'kind'='token' THEN 'token' ELSE 'client_secret' END,'Saved') FROM app_integration_secrets s WHERE p.kind='providers' AND p.data ? 'integration' AND coalesce(p.data->>'primary','true')='true' AND s.provider=p.data->>'integration' AND s.client_secret IS NOT NULL AND NOT p.data ? 'client_secret' AND NOT p.data ? 'token'")
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// Add what a provider shows but does not store, where the person may see it:
/// the redirect URI to register with an OAuth service, and the base URL used
/// when the record names none.
pub(super) fn present(app: &App, record: &mut Value) {
    let Some(integration) = record["integration"]
        .as_str()
        .and_then(|name| app.registry.integrations.get(name))
    else {
        return;
    };
    let shown = |record: &Value, field: &str| record.get(field).is_some();
    if integration.auth == Auth::OAuth2 && primary(record) && shown(record, "redirect_uri") {
        record["redirect_uri"] = json!(callback_url(&app.origin, &integration.name));
    }
    if shown(record, "default_base_url") {
        record["default_base_url"] = json!(integration.default_base_url());
    }
}
/// A stored provider as `actor` sees it through the API.
fn provider_output(app: &App, actor: &Actor, record: Value) -> Value {
    let mut record = match app.registry.resource_for("providers", actor) {
        Some(resource) => super::extensions::output(
            &crate::resource_for_principal(&resource, Some(actor.principal()), "GET"),
            record,
        ),
        None => record,
    };
    present(app, &mut record);
    record
}

/// The provider serving the record `id` for an integration connected per
/// record, adding one that waits to be connected when there is none: what
/// [`Context::add_connection`] does.
pub(super) async fn ensure(
    context: &mut Context<'_>,
    name: &str,
    id: Uuid,
) -> Result<Uuid, ApiError> {
    let integration = context
        .registry
        .integrations
        .get(name)
        .ok_or_else(|| ApiError::Parse(format!("Unknown integration: {name}")))?;
    let field = integration
        .per
        .clone()
        .ok_or_else(|| per_only(integration))?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM app_records WHERE kind='providers' AND data->>'integration'=$1 AND data->>$2=$3",
    )
    .bind(name)
    .bind(&field)
    .bind(id.to_string())
    .fetch_optional(&mut *context.connection)
    .await
    .map_err(ApiError::internal)?;
    if let Some(existing) = existing {
        return Ok(existing);
    }
    let created = context
        .elevated()
        .create("providers", json!({"integration": name, field: id}))
        .await?;
    Uuid::parse_str(created["id"].as_str().unwrap_or_default()).map_err(ApiError::internal)
}
fn per_only(integration: &Integration) -> ApiError {
    ApiError::Parse(format!(
        "Integration {} has one connection for the whole app; register it with .per(\"<field>\") to connect each record on its own.",
        integration.name
    ))
}

/// `POST /api/admin/providers/{id}/actions/{connect|disconnect}/`.
#[allow(clippy::too_many_lines)]
pub(super) async fn action(
    app: &App,
    headers: &HeaderMap,
    id: Uuid,
    name: &str,
    input: &Value,
) -> Result<Value, ApiError> {
    let person = user(app, headers).await?;
    let actor = app.actor(&person).await?;
    // Allowed as any model's action: a role granting it (on this record, when
    // its rule is a condition) to someone who may read the record.
    let registered = app
        .registry
        .actions
        .get(&("providers".to_owned(), name.to_owned()))
        .ok_or(ApiError::NotFound)?
        .clone();
    if !actor.may_run_action("providers", name, &registered) {
        return Err(ApiError::Forbidden);
    }
    let record = {
        let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
        let mut context = Context::new(&mut tx, &app.registry, actor.clone());
        let record = context.get("providers", id).await?;
        tx.rollback().await.map_err(ApiError::internal)?;
        record
    };
    if !actor.may_run_on("providers", name, &registered, &record) {
        return Err(ApiError::Forbidden);
    }
    if !registered.details.applies_to(&record) {
        return Err(ApiError::Conflict(
            "This action does not apply to the record in its current state.".into(),
        ));
    }
    // The stored record: what a person may not read still counts here.
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
        return token_action(app, &person, &actor, id, record, integration, name).await;
    }
    // Secrets of this connection; its client is the code's provider's.
    let secrets = key(&record);
    match name {
        "connect" => {
            let mut pool = app.pool.acquire().await.map_err(ApiError::internal)?;
            let main = main_record(&mut pool, &provider).await?;
            let client_id = main["client_id"].as_str().unwrap_or_default();
            let has_secret: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app_integration_secrets WHERE provider=$1 AND client_secret IS NOT NULL)")
                .bind(&provider).fetch_one(&app.pool).await.map_err(ApiError::internal)?;
            if client_id.is_empty() || !has_secret {
                return Err(ApiError::Conflict(if primary(&record) {
                    "Enter the client ID and client secret from the service's developer console first.".into()
                } else {
                    format!(
                        "Enter the client ID and client secret on the {} provider first; this connection signs in with them.",
                        main["name"].as_str().unwrap_or(&integration.label)
                    )
                }));
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
                .bind(&secrets)
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
                .bind(&secrets).execute(&mut *tx).await.map_err(ApiError::internal)?;
            let record: Value = sqlx::query_scalar(&format!(
                "UPDATE app_records SET data=data||jsonb_build_object('status','disconnected','account','{{}}'::jsonb,'error',NULL,'connected_at',NULL),updated=now() WHERE kind='providers' AND id=$1 RETURNING {DOCUMENT}"
            ))
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
            tx.commit().await.map_err(ApiError::internal)?;
            Ok(json!({"provider":provider_output(app, &actor, record)}))
        }
        _ => Err(ApiError::NotFound),
    }
}

/// Connect a token provider by checking its token with the service, or
/// disconnect it by forgetting the token.
async fn token_action(
    app: &App,
    person: &Value,
    actor: &Actor,
    id: Uuid,
    record: Value,
    integration: &Integration,
    name: &str,
) -> Result<Value, ApiError> {
    let provider = &key(&record);
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
        Ok::<_, ApiError>(json!({"provider":provider_output(app, actor, record)}))
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
            let main = if primary(&record) {
                None
            } else {
                let mut pool = app.pool.acquire().await.map_err(ApiError::internal)?;
                Some(main_record(&mut pool, &integration.name).await?)
            };
            let connection = connection(integration, &record, main.as_ref(), token);
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
                json!({"status":"needs_credentials","token":null,"account":{},"error":null,"connected_at":null}),
                false,
            )
            .await
        }
        _ => Err(ApiError::NotFound),
    }
}

/// `GET /api/integrations/{name}/callback`: finish a connection the app started.
#[allow(clippy::too_many_lines)]
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
    // The state names the connection: the service, or the service and the id
    // of a provider serving a record.
    let started: Option<(String, Uuid, Option<String>)> = sqlx::query_as(
        "DELETE FROM app_integration_states WHERE digest=$1 AND split_part(provider,':',1)=$2 AND expires>now() RETURNING provider,user_id,next",
    )
    .bind(hash(state))
    .bind(&provider)
    .fetch_optional(&app.pool)
    .await
    .map_err(ApiError::internal)?;
    let Some((secrets, user_id, next)) = started else {
        return Err(ApiError::Parse(
            "This connection request has expired or was already used. Start again from the app."
                .into(),
        ));
    };
    let mut pool = app.pool.acquire().await.map_err(ApiError::internal)?;
    let main = main_record(&mut pool, &provider).await?;
    let record = match secrets.split_once(':') {
        None => main.clone(),
        Some((_, id)) => sqlx::query_scalar(&format!(
            "SELECT {DOCUMENT} FROM app_records WHERE kind='providers' AND id::text=$1 AND data->>'integration'=$2"
        ))
        .bind(id)
        .bind(&provider)
        .fetch_optional(&mut *pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::Parse("This connection was removed. Start again from the app.".into()))?,
    };
    drop(pool);
    let id =
        Uuid::parse_str(record["id"].as_str().unwrap_or_default()).map_err(ApiError::internal)?;
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
            let client_id = main["client_id"].as_str().unwrap_or_default();
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
            store(&mut tx, &secrets, &tokens).await?;
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

/// Which provider of a service a connection comes from.
#[derive(Clone, Copy, Debug)]
pub(super) enum Serving {
    /// The one the app's code registers: the whole app's.
    App,
    /// The one serving this record of the model the service connects per.
    Record(Uuid),
}

/// The current connection to `name`, refreshing its access token first when it
/// expires within a minute. Refreshes commit on their own connection when one
/// is available, so a rotated refresh token survives the caller rolling back.
pub(super) async fn connect(
    context: &mut Context<'_>,
    pool: Option<&PgPool>,
    name: &str,
    serving: Serving,
) -> Result<Connection, ApiError> {
    let integration = context
        .registry
        .integrations
        .get(name)
        .ok_or_else(|| ApiError::Parse(format!("Unknown integration: {name}")))?
        .clone();
    let field = match serving {
        Serving::App => None,
        Serving::Record(_) => Some(
            integration
                .per
                .clone()
                .ok_or_else(|| per_only(&integration))?,
        ),
    };
    match pool {
        Some(pool) => {
            let mut tx = pool.begin().await.map_err(ApiError::internal)?;
            let result = current(&mut tx, &integration, field.as_deref(), serving).await;
            tx.commit().await.map_err(ApiError::internal)?;
            result
        }
        None => {
            current(
                &mut *context.connection,
                &integration,
                field.as_deref(),
                serving,
            )
            .await
        }
    }
}
#[allow(clippy::too_many_lines)]
async fn current(
    connection: &mut PgConnection,
    integration: &Integration,
    field: Option<&str>,
    serving: Serving,
) -> Result<Connection, ApiError> {
    let name = &integration.name;
    let main = main_record(connection, name).await.unwrap_or(Value::Null);
    let record = match (serving, field) {
        (Serving::Record(id), Some(field)) => sqlx::query_scalar(&format!(
            "SELECT {DOCUMENT} FROM app_records WHERE kind='providers' AND data->>'integration'=$1 AND data->>$2=$3"
        ))
        .bind(name)
        .bind(field)
        .bind(id.to_string())
        .fetch_optional(&mut *connection)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::Conflict(format!(
                "{} has no connection for this {field}. {}",
                integration.label,
                if field == "user" {
                    "They can connect their own under Providers."
                } else {
                    "An administrator can add one under Providers."
                }
            ))
        })?,
        _ => main.clone(),
    };
    let main = (!primary(&record)).then_some(&main);
    let not_connected = || {
        ApiError::Conflict(format!(
            "{} is not connected. An administrator can connect it under Providers.",
            record["name"].as_str().unwrap_or(&integration.label)
        ))
    };
    if record["enabled"] == false {
        return Err(ApiError::Conflict(format!(
            "{} is turned off under Providers.",
            record["name"].as_str().unwrap_or(&integration.label)
        )));
    }
    let secrets = key(&record);
    if integration.auth == Auth::Token {
        // A token is used once an administrator has connected it.
        if record["status"] != "connected" {
            return Err(not_connected());
        }
        let token: Option<String> = sqlx::query_scalar(
            "SELECT client_secret FROM app_integration_secrets WHERE provider=$1",
        )
        .bind(&secrets)
        .fetch_optional(&mut *connection)
        .await
        .map_err(ApiError::internal)?
        .flatten();
        return token
            .map(|token| self::connection(integration, &record, main, token))
            .ok_or_else(not_connected);
    }
    // Lock the tokens: a refresh token may be single-use.
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT access_token,refresh_token,client_secret,coalesce(expires<now()+interval '60 seconds',false) FROM app_integration_secrets WHERE provider=$1 FOR UPDATE",
    )
    .bind(&secrets)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    let Some((Some(access_token), refresh_token, client_secret, expiring)) = row else {
        return Err(not_connected());
    };
    if !expiring {
        return Ok(self::connection(integration, &record, main, access_token));
    }
    let Some(refresh_token) = refresh_token else {
        return Err(not_connected());
    };
    // A connection serving a record refreshes with the code's provider's client.
    let (client_id, client_secret) = match main {
        None => (
            record["client_id"].as_str().unwrap_or_default().to_owned(),
            client_secret,
        ),
        Some(main) => (
            main["client_id"].as_str().unwrap_or_default().to_owned(),
            sqlx::query_scalar(
                "SELECT client_secret FROM app_integration_secrets WHERE provider=$1",
            )
            .bind(name)
            .fetch_optional(&mut *connection)
            .await
            .map_err(ApiError::internal)?
            .flatten(),
        ),
    };
    match exchange(
        integration,
        &client_id,
        client_secret.as_deref().unwrap_or_default(),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ],
    )
    .await
    {
        Ok(tokens) => {
            store(connection, &secrets, &tokens).await?;
            Ok(self::connection(
                integration,
                &record,
                main,
                tokens.access_token,
            ))
        }
        Err(message) => {
            sqlx::query("UPDATE app_records SET data=data||jsonb_build_object('status','error','error',$2::text),updated=now() WHERE kind='providers' AND id::text=$1")
                .bind(record["id"].as_str().unwrap_or_default())
                .bind(format!("Refreshing access failed: {}. Connect it again.", truncate(&message)))
                .execute(&mut *connection)
                .await
                .map_err(ApiError::internal)?;
            Err(ApiError::Conflict(format!(
                "{} needs to be connected again: {}",
                record["name"].as_str().unwrap_or(&integration.label),
                truncate(&message)
            )))
        }
    }
}
