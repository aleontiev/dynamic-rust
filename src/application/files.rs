//! Files a model's file fields hold ([`Model::file`](super::extensions::Model::file)).
//!
//! They live in the app's bucket when it has one: any store speaking the S3
//! protocol (S3, R2, GCS's interoperability API), configured by
//! `APP_STORAGE_BUCKET` and its siblings, each app under its own
//! `APP_STORAGE_PREFIX`. Without one they are `PostgreSQL` large objects in the
//! app's own database. Both work the same way to people and code:
//!
//! 1. `POST /api/admin/files/` with the model, field, file name, size and
//!    type, by someone who may create or change that model's records and that
//!    field, answers where to `PUT` the bytes: a short-lived signed URL of the
//!    bucket, or the app's own `/api/admin/files/<id>/`.
//! 2. A create or update then sets the field to `{"upload": "<id>"}`; the app
//!    checks the upload is complete and theirs, moves it beside the record and
//!    keeps its name, size and type. Replacing or clearing the field, or
//!    deleting the record, removes the old file once the change commits.
//! 3. Reading the record shows the file's name, size, type and `url`
//!    (`/api/admin/<model>/<id>/files/<field>/`), which, for someone who may
//!    read the record and see the field, answers the file: a redirect to a
//!    short-lived signed URL of the bucket, or the bytes.
//!
//! Code stores files it makes (a PDF, an export) with
//! [`Context::put_file`](super::extensions::Context::put_file) and sets the
//! returned value with an elevated write.
use super::{
    App,
    extensions::{Context, Handler, lock},
    user,
};
use crate::{ApiError, FieldErrors, FieldKind};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::{
    fmt::Write as _,
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

/// The task that removes a bucket file once the change that let go of it
/// commits.
pub(super) const DELETE_TASK: &str = "_files_delete";
/// How long an upload may wait to be attached to a record.
const UPLOAD_MINUTES: i64 = 60;
/// How long a signed URL stays good.
const SIGNED_SECONDS: u64 = 900;

/// An S3-protocol bucket and the part of it that is this app's.
#[derive(Clone, Eq, PartialEq)]
pub struct Bucket {
    /// `https://s3.<region>.amazonaws.com`, `https://<account>.r2.cloudflarestorage.com`, ...
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Where this app's files go, e.g. `apps/<project>/<stage>/`.
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    /// `endpoint/bucket/key` rather than `bucket.endpoint/key` (R2, `MinIO`).
    pub path_style: bool,
}

// Its keys never reach logs.
impl std::fmt::Debug for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bucket")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .finish_non_exhaustive()
    }
}

/// Where files go.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Store {
    /// `PostgreSQL` large objects in the app's database.
    Postgres,
    Bucket(Bucket),
}

static STORE: RwLock<Option<Store>> = RwLock::new(None);

impl Store {
    /// The store the environment configures: a bucket when `APP_STORAGE_BUCKET`
    /// is set (credentials from `APP_STORAGE_ACCESS_KEY_ID` and
    /// `APP_STORAGE_SECRET_ACCESS_KEY`, else the AWS runtime's own), otherwise
    /// `PostgreSQL`.
    #[must_use]
    pub fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        let Some(bucket) = var("APP_STORAGE_BUCKET") else {
            return Self::Postgres;
        };
        let region = var("APP_STORAGE_REGION")
            .or_else(|| var("AWS_REGION"))
            .unwrap_or_else(|| "us-east-1".into());
        let endpoint = var("APP_STORAGE_ENDPOINT")
            .unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com"));
        let (access_key, secret_key, session_token) = match var("APP_STORAGE_ACCESS_KEY_ID") {
            Some(key) => (
                key,
                var("APP_STORAGE_SECRET_ACCESS_KEY").unwrap_or_default(),
                None,
            ),
            None => (
                var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                var("AWS_SESSION_TOKEN"),
            ),
        };
        Self::Bucket(Bucket {
            endpoint: endpoint.trim_end_matches('/').into(),
            region,
            bucket,
            prefix: prefix(&var("APP_STORAGE_PREFIX").unwrap_or_default()),
            access_key,
            secret_key,
            session_token,
            path_style: var("APP_STORAGE_PATH_STYLE").is_some_and(|value| value == "true"),
        })
    }
}

/// A prefix as kept: no leading slash, a trailing one unless empty.
fn prefix(value: &str) -> String {
    let value = value.trim().trim_matches('/');
    if value.is_empty() {
        String::new()
    } else {
        format!("{value}/")
    }
}

/// The store files go to: the one set with [`use_store`], else the
/// environment's.
#[must_use]
pub fn store() -> Store {
    if let Some(store) = STORE.read().ok().and_then(|store| store.clone()) {
        return store;
    }
    let configured = Store::from_env();
    if let Ok(mut store) = STORE.write() {
        store.get_or_insert(configured.clone());
    }
    configured
}

/// Choose where files go, instead of the environment (hosts and tests).
pub fn use_store(store: Store) {
    if let Ok(mut current) = STORE.write() {
        *current = Some(store);
    }
}

/// The largest file people may upload: `APP_STORAGE_MAX_BYTES`, else 100 MiB
/// to a bucket and 10 MiB to `PostgreSQL`.
fn limit(store: &Store) -> u64 {
    std::env::var("APP_STORAGE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(match store {
            Store::Bucket(_) => 100 * 1024 * 1024,
            Store::Postgres => 10 * 1024 * 1024,
        })
}

// --- Signing (AWS Signature Version 4, which every S3-protocol store takes) ---

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
fn hex(data: &[u8]) -> String {
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}
/// RFC 3986 percent-encoding of everything but unreserved characters (and `/`
/// in paths).
fn encode(value: &str, path: bool) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            b'/' if path => "/".into(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
/// `YYYYMMDD` and `YYYYMMDDTHHMMSSZ` for a time.
fn stamp(time: SystemTime) -> (String, String) {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    let time = format!(
        "{date}T{:02}{:02}{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    );
    (date, time)
}

impl Bucket {
    /// The host to sign, the object's path, and the URL's origin.
    fn locate(&self, key: &str) -> (String, String, String) {
        let parsed = url::Url::parse(&self.endpoint).ok();
        let scheme = parsed.as_ref().map_or("https", url::Url::scheme).to_owned();
        let mut host = parsed
            .as_ref()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default();
        if let Some(port) = parsed.as_ref().and_then(url::Url::port) {
            host = format!("{host}:{port}");
        }
        let key = encode(key, true);
        if self.path_style {
            let path = format!("/{}/{key}", encode(&self.bucket, false));
            (host.clone(), path, format!("{scheme}://{host}"))
        } else {
            let host = format!("{}.{host}", self.bucket);
            (
                host.clone(),
                format!("/{key}"),
                format!("{scheme}://{host}"),
            )
        }
    }
    fn signature(&self, date: &str, string_to_sign: &str) -> String {
        let key = [
            date.as_bytes(),
            self.region.as_bytes(),
            b"s3",
            b"aws4_request",
        ]
        .iter()
        .fold(
            format!("AWS4{}", self.secret_key).into_bytes(),
            |key, part| hmac(&key, part),
        );
        hex(&hmac(&key, string_to_sign.as_bytes()))
    }
    /// A URL anyone holding it may use for `method` on `key` until it
    /// expires; `headers` the request must send are signed too (say
    /// `content-type`), and `query` adds response overrides.
    #[must_use]
    pub fn presign(
        &self,
        method: &str,
        key: &str,
        seconds: u64,
        headers: &[(&str, &str)],
        query: &[(&str, &str)],
        now: SystemTime,
    ) -> String {
        let (host, path, origin) = self.locate(key);
        let (date, time) = stamp(now);
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let mut signed: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .chain(std::iter::once(("host".to_owned(), host)))
            .collect();
        signed.sort();
        let signed_names = signed
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let mut params: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            (
                "X-Amz-Credential".into(),
                format!("{}/{scope}", self.access_key),
            ),
            ("X-Amz-Date".into(), time.clone()),
            ("X-Amz-Expires".into(), seconds.to_string()),
            ("X-Amz-SignedHeaders".into(), signed_names.clone()),
        ];
        if let Some(token) = &self.session_token {
            params.push(("X-Amz-Security-Token".into(), token.clone()));
        }
        params.extend(
            query
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        let mut encoded: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| (encode(k, false), encode(v, false)))
            .collect();
        encoded.sort();
        let canonical_query = encoded
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let canonical_headers: String =
            signed.iter().fold(String::new(), |mut out, (name, value)| {
                let _ = writeln!(out, "{name}:{value}");
                out
            });
        let request = format!(
            "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_names}\nUNSIGNED-PAYLOAD"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
            sha256_hex(request.as_bytes())
        );
        let signature = self.signature(&date, &string_to_sign);
        format!("{origin}{path}?{canonical_query}&X-Amz-Signature={signature}")
    }
    /// A request to the bucket signed in its headers, the payload unsigned.
    fn request(
        &self,
        method: reqwest::Method,
        key: &str,
        extra: &[(&str, String)],
    ) -> reqwest::RequestBuilder {
        let (host, path, origin) = self.locate(key);
        let (date, time) = stamp(SystemTime::now());
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host),
            ("x-amz-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
            ("x-amz-date".into(), time.clone()),
        ];
        if let Some(token) = &self.session_token {
            headers.push(("x-amz-security-token".into(), token.clone()));
        }
        headers.extend(
            extra
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value.clone())),
        );
        headers.sort();
        let names = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical: String = headers
            .iter()
            .fold(String::new(), |mut out, (name, value)| {
                let _ = writeln!(out, "{name}:{}", value.trim());
                out
            });
        let request = format!("{method}\n{path}\n\n{canonical}\n{names}\nUNSIGNED-PAYLOAD");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
            sha256_hex(request.as_bytes())
        );
        let signature = self.signature(&date, &string_to_sign);
        let mut builder = super::integrations::http().request(method, format!("{origin}{path}"));
        for (name, value) in headers.iter().filter(|(name, _)| name != "host") {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder.header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
                self.access_key
            ),
        )
    }
    async fn send(
        &self,
        builder: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<reqwest::Response, ApiError> {
        builder.send().await.map_err(|_| {
            ApiError::Conflict(format!("The file store could not be reached to {what}."))
        })
    }
    /// The size of `key`, or `None` when there is no such object.
    ///
    /// # Errors
    /// The store could not be reached or refused.
    pub async fn head(&self, key: &str) -> Result<Option<u64>, ApiError> {
        let response = self
            .send(
                self.request(reqwest::Method::HEAD, key, &[]),
                "check a file",
            )
            .await?;
        match response.status().as_u16() {
            // The object's size is in the header: a HEAD response's own body is empty.
            200 => Ok(response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())),
            404 => Ok(None),
            status => Err(ApiError::Conflict(format!(
                "The file store answered {status} checking a file."
            ))),
        }
    }
    /// Store `bytes` at `key`.
    ///
    /// # Errors
    /// The store could not be reached or refused.
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), ApiError> {
        let response = self
            .send(
                self.request(
                    reqwest::Method::PUT,
                    key,
                    &[("content-type", content_type.to_owned())],
                )
                .body(bytes),
                "save a file",
            )
            .await?;
        if !response.status().is_success() {
            return Err(ApiError::Conflict(format!(
                "The file store answered {} saving a file.",
                response.status()
            )));
        }
        Ok(())
    }
    /// Copy `from` to `to` within the bucket.
    ///
    /// # Errors
    /// The store could not be reached or refused.
    pub async fn copy(&self, from: &str, to: &str) -> Result<(), ApiError> {
        let source = format!("/{}/{}", self.bucket, encode(from, true));
        let response = self
            .send(
                self.request(reqwest::Method::PUT, to, &[("x-amz-copy-source", source)]),
                "keep a file",
            )
            .await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        // A copy can answer 200 with an error document.
        if !status.is_success() || body.contains("<Error>") {
            return Err(ApiError::Conflict(format!(
                "The file store answered {status} keeping a file."
            )));
        }
        Ok(())
    }
    /// Remove `key`; a missing object is fine.
    ///
    /// # Errors
    /// The store could not be reached or refused.
    pub async fn delete(&self, key: &str) -> Result<(), ApiError> {
        let response = self
            .send(
                self.request(reqwest::Method::DELETE, key, &[]),
                "remove a file",
            )
            .await?;
        if !(response.status().is_success() || response.status() == StatusCode::NOT_FOUND) {
            return Err(ApiError::Conflict(format!(
                "The file store answered {} removing a file.",
                response.status()
            )));
        }
        Ok(())
    }
}

fn invalid(field: &str, message: &str) -> ApiError {
    ApiError::Validation(FieldErrors::from([(field.into(), vec![message.into()])]))
}
fn now_iso() -> String {
    let (_, time) = stamp(SystemTime::now());
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &time[0..4],
        &time[4..6],
        &time[6..8],
        &time[9..11],
        &time[11..13],
        &time[13..15]
    )
}
/// A file name people gave, made safe to keep and to send back in a header.
fn clean_name(name: &str) -> Option<String> {
    let name: String = name
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    (!name.is_empty() && name.len() <= 255).then_some(name)
}
fn clean_type(value: &str) -> String {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.len() <= 255
        && value.contains('/')
        && value
            .chars()
            .all(|c| c.is_ascii_graphic() || c == ' ' || c == ';' || c == '=');
    if valid {
        value.to_owned()
    } else {
        "application/octet-stream".into()
    }
}

/// `POST /api/admin/files/`: where to put the bytes of a file for a field.
pub(super) async fn begin(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let person = user(&app, &headers).await?;
    let actor = app.actor(&person).await?;
    let kind = input["model"].as_str().unwrap_or_default().to_owned();
    let field = input["field"].as_str().unwrap_or_default().to_owned();
    let resource = app
        .registry
        .resource_for(&kind, &actor)
        .ok_or_else(|| invalid("model", "Choose a model of this app."))?;
    let declared = resource
        .field(&field)
        .filter(|f| f.kind == FieldKind::File)
        .ok_or_else(|| invalid("field", "Choose a file field of this model."))?;
    let may = |operation: &str| {
        crate::operation_granted(&resource, Some(actor.principal()), operation, true)
    };
    if !(may("create") || may("update")) {
        return Err(ApiError::Forbidden);
    }
    let effective = crate::resource_for_principal(&resource, Some(actor.principal()), "PATCH");
    if effective.field(&declared.name).is_some_and(|f| f.read_only) && !actor.is_superuser {
        return Err(ApiError::Forbidden);
    }
    let name = clean_name(input["name"].as_str().unwrap_or_default())
        .ok_or_else(|| invalid("name", "Give the file a name."))?;
    let content_type = clean_type(input["content_type"].as_str().unwrap_or_default());
    let store = store();
    let size = input["size"]
        .as_u64()
        .ok_or_else(|| invalid("size", "Give the file's size in bytes."))?;
    if size == 0 || size > limit(&store) {
        return Err(invalid(
            "size",
            &format!(
                "A file may hold 1 byte to {} MiB.",
                limit(&store) / 1024 / 1024
            ),
        ));
    }
    let id = Uuid::new_v4();
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    sweep(&mut tx).await?;
    let (store_name, key) = match &store {
        Store::Bucket(bucket) => ("bucket", Some(format!("{}pending/{id}", bucket.prefix))),
        Store::Postgres => ("postgres", None),
    };
    sqlx::query("INSERT INTO app_uploads(id,kind,field,user_id,name,size,content_type,store,key,expires) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+make_interval(mins=>$10::int))")
        .bind(id)
        .bind(&kind)
        .bind(&field)
        .bind(Uuid::parse_str(&actor.id).ok())
        .bind(&name)
        .bind(i64::try_from(size).map_err(ApiError::internal)?)
        .bind(&content_type)
        .bind(store_name)
        .bind(&key)
        .bind(i32::try_from(UPLOAD_MINUTES).unwrap_or(60))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    let (url, headers) = match (&store, key) {
        (Store::Bucket(bucket), Some(key)) => (
            bucket.presign(
                "PUT",
                &key,
                SIGNED_SECONDS,
                &[("content-type", &content_type)],
                &[],
                SystemTime::now(),
            ),
            json!({"Content-Type": content_type}),
        ),
        _ => (
            format!("{}/api/admin/files/{id}/", app.origin),
            json!({"Content-Type": content_type}),
        ),
    };
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"upload":{"id":id,"method":"PUT","url":url,"headers":headers,"expires_in":UPLOAD_MINUTES * 60}}),
        ),
    ))
}

/// Queue removing a bucket object, as the app itself: whoever let it go may
/// be gone by the time it runs. Removing it twice is harmless.
async fn queue_delete(connection: &mut PgConnection, key: &str) -> Result<(), ApiError> {
    sqlx::query(QUEUE_DELETE)
        .bind(key)
        .bind(DELETE_TASK)
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
const QUEUE_DELETE: &str = "INSERT INTO app_tasks(id,name,idempotency_key,input,actor) SELECT gen_random_uuid(),$2,'delete:'||encode(sha256(convert_to(k,'UTF8')),'hex'),jsonb_build_object('key',k),'{\"system\":true}'::jsonb FROM (SELECT $1::text AS k) keys ON CONFLICT(name,idempotency_key) DO NOTHING";

/// An upload as kept: who made it, for which model and field, its name, size
/// and type, its store, bucket key or large object, and its state.
type UploadRow = (
    Option<Uuid>,
    String,
    String,
    String,
    i64,
    String,
    String,
    Option<String>,
    Option<i64>,
    String,
);

/// Forget uploads nobody attached in time: their large objects, and what
/// may have been put in the bucket for them.
async fn sweep(connection: &mut PgConnection) -> Result<(), ApiError> {
    sqlx::query("SELECT lo_unlink(oid) FROM app_uploads WHERE expires<now() AND state<>'attached' AND oid IS NOT NULL AND EXISTS(SELECT 1 FROM pg_largeobject_metadata m WHERE m.oid=app_uploads.oid)")
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM app_uploads WHERE expires<now() AND state<>'attached' AND key IS NOT NULL",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(ApiError::internal)?;
    for key in keys {
        queue_delete(connection, &key).await?;
    }
    sqlx::query("DELETE FROM app_uploads WHERE expires<now() AND state<>'attached'")
        .execute(&mut *connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// `PUT /api/admin/files/{id}/`: the bytes of an upload, without a bucket.
pub(super) async fn receive(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let person = user(&app, &headers).await?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    let row: Option<(Option<Uuid>, i64, String, String)> = sqlx::query_as(
        "SELECT user_id,size,store,state FROM app_uploads WHERE id=$1 AND expires>now() FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    let Some((owner, size, store_name, state)) = row else {
        return Err(ApiError::NotFound);
    };
    if owner.map(|owner| owner.to_string()).as_deref() != person["id"].as_str() {
        return Err(ApiError::NotFound);
    }
    if store_name != "postgres" || state != "pending" {
        return Err(ApiError::Conflict(
            "This upload takes no bytes here.".into(),
        ));
    }
    if i64::try_from(body.len()).unwrap_or(i64::MAX) != size {
        return Err(invalid(
            "size",
            "The file is not the size its upload was given.",
        ));
    }
    sqlx::query("UPDATE app_uploads SET oid=lo_from_bytea(0,$2),state='received' WHERE id=$1")
        .bind(id)
        .bind(body.as_ref())
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Turn the value a write gives a file field into the file it keeps: an
/// upload by its id (`{"upload": "<id>"}`) the writer made, complete, for this
/// model and field; nothing (`null`); or, for code writing with the app's
/// authority, a file [`Context::put_file`] stored. Anything else keeps the
/// file the record had. Returns the files to let go of once the write commits.
pub(super) async fn resolve(
    context: &mut Context<'_>,
    kind: &str,
    id: Uuid,
    field: &str,
    previous: Option<&Value>,
    value: &mut Value,
    elevated: bool,
) -> Result<Option<Value>, ApiError> {
    let before = previous.map_or(Value::Null, |previous| previous[field].clone());
    let upload = value
        .get("upload")
        .and_then(Value::as_str)
        .map(str::to_owned);
    match (&*value, upload) {
        (Value::Null, _) => {}
        (_, Some(upload)) => *value = attach(context, kind, id, field, &upload, elevated).await?,
        (Value::Object(file), None) if elevated && file.contains_key("store") => {}
        _ => {
            *value = before.clone();
            return Ok(None);
        }
    }
    Ok((before.is_object() && before != *value).then_some(before))
}

async fn attach(
    context: &mut Context<'_>,
    kind: &str,
    id: Uuid,
    field: &str,
    upload: &str,
    elevated: bool,
) -> Result<Value, ApiError> {
    let missing = || {
        invalid(
            field,
            "This upload is not one you made for this field, or it has expired.",
        )
    };
    let upload_id = Uuid::parse_str(upload).map_err(|_| missing())?;
    let row: Option<UploadRow> = sqlx::query_as(
        "SELECT user_id,kind,field,name,size,content_type,store,key,oid::int8,state FROM app_uploads WHERE id=$1 AND expires>now() FOR UPDATE",
    )
    .bind(upload_id)
    .fetch_optional(&mut *context.connection)
    .await
    .map_err(ApiError::internal)?;
    let Some((
        owner,
        upload_kind,
        upload_field,
        name,
        size,
        content_type,
        store_name,
        key,
        oid,
        state,
    )) = row
    else {
        return Err(missing());
    };
    let theirs = elevated
        || owner.map(|owner| owner.to_string()).as_deref() == Some(context.actor.id.as_str());
    if !theirs || upload_kind != kind || upload_field != field || state == "attached" {
        return Err(missing());
    }
    let mut file =
        json!({"name":name,"size":size,"content_type":content_type,"uploaded":now_iso()});
    match (store(), store_name.as_str()) {
        (Store::Bucket(bucket), "bucket") => {
            let pending = key.ok_or_else(missing)?;
            match bucket.head(&pending).await? {
                Some(found) if i64::try_from(found).ok() == Some(size) => {}
                Some(_) => {
                    return Err(invalid(
                        field,
                        "The uploaded file is not the size its upload was given.",
                    ));
                }
                None => return Err(invalid(field, "The file has not been uploaded yet.")),
            }
            let kept = format!("{}files/{kind}/{id}/{field}/{upload_id}", bucket.prefix);
            bucket.copy(&pending, &kept).await?;
            // The pending copy expires on its own if this fails.
            let _ = bucket.delete(&pending).await;
            file["store"] = json!("bucket");
            file["key"] = json!(kept);
        }
        (_, "postgres") => {
            let oid = oid
                .filter(|_| state == "received")
                .ok_or_else(|| invalid(field, "The file has not been uploaded yet."))?;
            file["store"] = json!("postgres");
            file["oid"] = json!(oid);
        }
        _ => {
            return Err(invalid(
                field,
                "This upload was made for another file store.",
            ));
        }
    }
    sqlx::query("UPDATE app_uploads SET state='attached' WHERE id=$1")
        .bind(upload_id)
        .execute(&mut *context.connection)
        .await
        .map_err(ApiError::internal)?;
    Ok(file)
}

/// Resolve every file field of a record being written: on a delete, every
/// file it holds is let go of; otherwise uploads it names become its files.
/// Returns the files to [`release`] once the write is made.
pub(super) async fn resolve_all(
    context: &mut Context<'_>,
    resource: &crate::Resource,
    operation: &str,
    id: Uuid,
    previous: Option<&Value>,
    record: &mut Value,
) -> Result<Vec<Value>, ApiError> {
    let mut released = vec![];
    for field in resource.fields.iter().filter(|f| f.kind == FieldKind::File) {
        if operation == "delete" {
            if let Some(file) = previous
                .map(|p| p[&field.name].clone())
                .filter(Value::is_object)
            {
                released.push(file);
            }
        } else if let Some(mut value) = record.get(&field.name).cloned() {
            let elevated = context.elevated;
            if let Some(old) = resolve(
                context,
                &resource.plural_name,
                id,
                &field.name,
                previous,
                &mut value,
                elevated,
            )
            .await?
            {
                released.push(old);
            }
            record[&field.name] = value;
        }
    }
    Ok(released)
}

/// Let go of a file a record no longer holds: a large object goes with the
/// transaction; a bucket object is removed by a task once it commits.
pub(super) async fn release(context: &mut Context<'_>, file: &Value) -> Result<(), ApiError> {
    match file["store"].as_str() {
        Some("postgres") => {
            if let Some(oid) = file["oid"].as_i64() {
                sqlx::query("SELECT lo_unlink($1::bigint::oid) WHERE EXISTS(SELECT 1 FROM pg_largeobject_metadata WHERE oid=$1::bigint::oid)")
                    .bind(oid)
                    .execute(&mut *context.connection)
                    .await
                    .map_err(ApiError::internal)?;
            }
        }
        Some("bucket") => {
            if let Some(key) = file["key"].as_str() {
                queue_delete(context.connection, key).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Removes a bucket file a record let go of.
pub(super) struct DeleteFile;
#[async_trait::async_trait]
impl Handler for DeleteFile {
    async fn run(&self, _: &mut Context<'_>, input: Value) -> Result<Value, ApiError> {
        let key = &input["data"]["key"];
        if let (Store::Bucket(bucket), Some(key)) = (store(), key.as_str()) {
            bucket.delete(key).await?;
        }
        Ok(json!({"deleted": key}))
    }
}

/// What people see of a file a record holds: its name, size, type and where
/// to fetch it.
#[must_use]
pub(super) fn public(kind: &str, id: &str, field: &str, file: &Value) -> Value {
    if !file.is_object() {
        return Value::Null;
    }
    json!({
        "name": file["name"], "size": file["size"], "content_type": file["content_type"],
        "uploaded": file["uploaded"],
        "url": format!("/api/admin/{kind}/{id}/files/{field}/"),
    })
}

/// `GET /api/admin/{kind}/{id}/files/{field}/`: the file, for someone who may
/// read the record and see the field.
pub(super) async fn download(
    State(app): State<App>,
    headers: HeaderMap,
    Path((kind, id, field)): Path<(String, Uuid, String)>,
) -> Result<Response, ApiError> {
    let actor = app.actor(&user(&app, &headers).await?).await?;
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    let mut context = Context::new(&mut tx, &app.registry, actor.clone());
    // Reading through the model applies its grants, row filters and field rules.
    let shown = context.get(&kind, id).await?;
    if !shown.get(&field).is_some_and(Value::is_object) {
        return Err(ApiError::NotFound);
    }
    let file: Value =
        sqlx::query_scalar("SELECT data->$3 FROM app_records WHERE kind=$1 AND id=$2")
            .bind(&kind)
            .bind(id)
            .bind(&field)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    let name = file["name"].as_str().unwrap_or("file").to_owned();
    let content_type = file["content_type"]
        .as_str()
        .unwrap_or("application/octet-stream")
        .to_owned();
    let disposition = format!("attachment; filename*=UTF-8''{}", encode(&name, false));
    match (file["store"].as_str(), store()) {
        (Some("bucket"), Store::Bucket(bucket)) => {
            let key = file["key"].as_str().unwrap_or_default();
            let url = bucket.presign(
                "GET",
                key,
                SIGNED_SECONDS,
                &[],
                &[
                    ("response-content-disposition", &disposition),
                    ("response-content-type", &content_type),
                ],
                SystemTime::now(),
            );
            Ok((
                StatusCode::FOUND,
                [
                    (header::LOCATION, url),
                    (header::CACHE_CONTROL, "no-store".into()),
                ],
            )
                .into_response())
        }
        (Some("postgres"), _) => {
            let oid = file["oid"].as_i64().ok_or(ApiError::NotFound)?;
            let bytes: Vec<u8> = sqlx::query_scalar("SELECT lo_get($1::bigint::oid)")
                .bind(oid)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| ApiError::NotFound)?;
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::CACHE_CONTROL, "private, no-store".into()),
                ],
                Body::from(bytes),
            )
                .into_response())
        }
        _ => Err(ApiError::Conflict(
            "This file's store is not available to the app.".into(),
        )),
    }
}

/// Store a file code made and return the value to set on a file field, with
/// an elevated write: `ctx.elevated().update("orders", id, json!({"pdf": file}))`.
///
/// # Errors
/// The store refused or could not be reached.
pub(super) async fn put(
    context: &mut Context<'_>,
    name: &str,
    content_type: &str,
    bytes: Vec<u8>,
) -> Result<Value, ApiError> {
    let name = clean_name(name).ok_or_else(|| ApiError::Parse("A file needs a name.".into()))?;
    let content_type = clean_type(content_type);
    let size = bytes.len();
    let mut file =
        json!({"name":name,"size":size,"content_type":content_type,"uploaded":now_iso()});
    match store() {
        Store::Bucket(bucket) => {
            let key = format!("{}files/code/{}", bucket.prefix, Uuid::new_v4());
            bucket.put(&key, bytes, &content_type).await?;
            file["store"] = json!("bucket");
            file["key"] = json!(key);
        }
        Store::Postgres => {
            lock(&mut *context.connection).await.ok();
            let oid: i64 = sqlx::query_scalar("SELECT lo_from_bytea(0,$1)::int8")
                .bind(bytes)
                .fetch_one(&mut *context.connection)
                .await
                .map_err(ApiError::internal)?;
            file["store"] = json!("postgres");
            file["oid"] = json!(oid);
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn presigned_urls_match_the_published_signature_v4_example() {
        // AWS's example: GET examplebucket/test.txt, 24 hours, 2013-05-24.
        let bucket = Bucket {
            endpoint: "https://s3.amazonaws.com".into(),
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            prefix: String::new(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            path_style: false,
        };
        let at = UNIX_EPOCH + Duration::from_secs(1_369_353_600);
        let url = bucket.presign("GET", "test.txt", 86_400, &[], &[], at);
        assert!(
            url.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"),
            "{url}"
        );
        assert!(
            url.ends_with(
                "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "{url}"
        );
    }

    #[test]
    fn dates_and_names_are_kept_safely() {
        assert_eq!(
            stamp(UNIX_EPOCH + Duration::from_secs(1_369_353_600)).1,
            "20130524T000000Z"
        );
        assert_eq!(
            stamp(UNIX_EPOCH + Duration::from_secs(951_782_400)).0,
            "20000229"
        );
        assert_eq!(clean_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(clean_name("C:\\docs\\a\nb.pdf").as_deref(), Some("ab.pdf"));
        assert_eq!(clean_name("  "), None);
        assert_eq!(clean_type("text/html\r\nX: y"), "application/octet-stream");
        assert_eq!(prefix("/apps/p/dev"), "apps/p/dev/");
        assert_eq!(encode("a b/ü", true), "a%20b/%C3%BC");
    }
}
