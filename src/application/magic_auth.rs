#![allow(clippy::items_after_statements, clippy::map_unwrap_or)]
//! Email-only authentication for the shared application runtime.
use super::{App, hash, random};
use crate::ApiError;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn color<'a>(branding: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    branding[key]
        .as_str()
        .filter(|v| {
            v.len() == 7 && v.starts_with('#') && v[1..].bytes().all(|b| b.is_ascii_hexdigit())
        })
        .unwrap_or(fallback)
}
fn safe_logo(value: &str) -> bool {
    if [
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/webp;base64,",
        "data:image/svg+xml;base64,",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
    {
        return value.len() <= 1_400_000
            && value.split_once(',').is_some_and(|(_, data)| {
                data.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
            });
    }
    url::Url::parse(value).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}
pub(super) async fn login(State(app): State<App>) -> Response {
    let nonce = random();
    let company = app.branding["company_name"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&app.name);
    let logo = app
        .branding
        .get("logo_light_url")
        .unwrap_or(&app.branding["logo_url"])
        .as_str()
        .filter(|s| safe_logo(s))
        .map(|src| {
            format!(
                "<img id=\"brand-logo\" src=\"{}\" alt=\"{}\">",
                escape(src),
                escape(company)
            )
        })
        .unwrap_or_else(|| "<img id=\"brand-logo\" hidden alt=\"Company logo\">".into());
    let name = escape(&app.name);
    let icon = app
        .branding
        .get("icon_light_url")
        .unwrap_or(&app.branding["icon_url"])
        .as_str()
        .filter(|s| safe_logo(s))
        .map(|src| {
            format!(
                "<link id=\"brand-favicon\" rel=\"icon\" href=\"{}\">",
                escape(src)
            )
        })
        .unwrap_or_else(|| "<link id=\"brand-favicon\" rel=\"icon\">".into());
    let company = escape(company);
    // Substituted branding is never interpreted as another template marker.
    let preview_script = super::preview::bridge_script(&app.preview_origins);
    let html: String = include_str!("templates/app-login.html")
        .split("@@")
        .enumerate()
        .map(|(index, part)| {
            if index % 2 == 0 {
                part
            } else {
                match part {
                    "APP" => &name,
                    "COMPANY" => &company,
                    "LOGO" => &logo,
                    "ICON" => &icon,
                    "NONCE" => &nonce,
                    "PREVIEW_SCRIPT" => &preview_script,
                    "GOOGLE" => {
                        if app.google_auth.is_some() {
                            "<a class=\"google\" href=\"/api/auth/google\"><svg viewBox=\"0 0 48 48\" aria-hidden=\"true\"><path fill=\"#EA4335\" d=\"M24 9.5c3.5 0 6.6 1.2 9.1 3.5l6.8-6.8C35.8 2.4 30.3 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z\"/><path fill=\"#4285F4\" d=\"M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.7 6c4.5-4.2 6.9-10.3 6.9-17.7z\"/><path fill=\"#FBBC05\" d=\"M10.5 28.6A14.5 14.5 0 0 1 9.8 24c0-1.6.3-3.1.7-4.6l-7.9-6.1A24 24 0 0 0 0 24c0 3.9.9 7.5 2.6 10.8l7.9-6.2z\"/><path fill=\"#34A853\" d=\"M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.7-6c-2.1 1.4-4.9 2.3-8.2 2.3-6.3 0-11.6-4.2-13.5-9.9l-7.9 6.2C6.5 42.6 14.6 48 24 48z\"/></svg>Continue with Google</a><div class=\"or\" aria-hidden=\"true\">or</div>"
                        } else {
                            ""
                        }
                    }
                    "PRIMARY" => color(&app.branding, "primary_color", "#000f14"),
                    "ACCENT" => color(&app.branding, "accent_color", "#b5e3d1"),
                    _ => "",
                }
            }
        })
        .collect();
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    let ancestors = if app.preview_origins.is_empty() {
        "'none'".into()
    } else {
        super::preview::origins(&app)
    };
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,format!("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; img-src https: data:; base-uri 'none'; frame-ancestors {ancestors}; form-action 'self'").parse().unwrap());
    response
}
fn same_origin(app: &App, headers: &HeaderMap) -> Result<(), ApiError> {
    if headers
        .get("sec-fetch-site")
        .is_some_and(|value| value == "cross-site")
    {
        return Err(ApiError::Forbidden);
    }
    if let Some(value) = headers.get(header::ORIGIN) {
        let origin = url::Url::parse(value.to_str().map_err(|_| ApiError::Forbidden)?)
            .map_err(|_| ApiError::Forbidden)?;
        let configured = url::Url::parse(&app.origin).map_err(ApiError::internal)?;
        if origin.origin() != configured.origin() {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}
pub(super) fn email(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    let valid = value.is_ascii()
        && value.len() <= 254
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && local.len() <= 64
                && !local.starts_with('.')
                && !local.ends_with('.')
                && !local.contains("..")
                && local
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
                && domain.contains('.')
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        });
    if valid {
        Ok(value)
    } else {
        Err(ApiError::Parse("Enter a valid email address.".into()))
    }
}
fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestLink {
    email: String,
    /// The page to return to after confirming, carried in the emailed link.
    next: Option<String>,
}
pub(super) async fn request_link(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<RequestLink>,
) -> Result<Response, ApiError> {
    same_origin(&app, &headers)?;
    let email = email(&input.email)?;
    let token = random();
    let token_digest = hash(&token);
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    // One short shared transaction makes both limits hold across Lambda instances.
    sqlx::query("SELECT pg_advisory_xact_lock(738341902)")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("DELETE FROM app_magic_requests WHERE created<now()-interval '1 hour'")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("DELETE FROM app_magic_links WHERE expires<now()")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let (all_minute,all_hour,email_minute,email_hour):(i64,i64,i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE created>now()-interval '1 minute'), count(*), count(*) FILTER(WHERE email_digest=$1 AND created>now()-interval '1 minute'), count(*) FILTER(WHERE email_digest=$1) FROM app_magic_requests").bind(hash(&email)).fetch_one(&mut *tx).await.map_err(ApiError::internal)?;
    if all_minute >= 30 || all_hour >= 200 || email_minute >= 1 || email_hour >= 5 {
        let mut response = json_response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"detail":"Please wait before requesting another sign-in link."}),
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, "60".parse().unwrap());
        return Ok(response);
    }
    sqlx::query("INSERT INTO app_magic_requests(email_digest) VALUES($1)")
        .bind(hash(&email))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    if !super::core::member(&app, &mut tx, &email).await? {
        // The attempt still counts against the limits above.
        tx.commit().await.map_err(ApiError::internal)?;
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            json!({"detail":"There is no account for this email address. Ask an administrator of this app to add you."}),
        ));
    }
    sqlx::query("INSERT INTO app_magic_links(digest,email,expires) VALUES($1,$2,now()+interval '15 minutes')").bind(&token_digest).bind(&email).execute(&mut *tx).await.map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    let link = format!(
        "{}#token={token}",
        super::login_url(&app, input.next.as_deref())
    );
    if let Err(error) = send(&app, &email, &link).await {
        let _ = sqlx::query("DELETE FROM app_magic_links WHERE digest=$1")
            .bind(&token_digest)
            .execute(&app.pool)
            .await;
        // Neither mail payloads nor SDK errors containing a request are logged.
        let (class, code) = safe_mail_error(error.as_ref());
        tracing::error!(
            error_class = class,
            service_code = code.as_deref().unwrap_or("unknown"),
            "App magic-link email delivery failed"
        );
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"detail":"Email delivery is temporarily unavailable. Please try again shortly."}),
        ));
    }
    Ok(json_response(
        StatusCode::ACCEPTED,
        json!({"message":"Check your inbox for a sign-in link. The link expires in 15 minutes."}),
    ))
}
fn safe_service_code(code: Option<&str>) -> Option<String> {
    code.filter(|code| {
        !code.is_empty()
            && code.len() <= 80
            && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
    .map(str::to_owned)
}
fn safe_mail_error(
    error: &(dyn std::error::Error + Send + Sync + 'static),
) -> (&'static str, Option<String>) {
    use aws_sdk_sesv2::{error::SdkError, operation::send_email::SendEmailError};
    if let Some(error) = error.downcast_ref::<SdkError<SendEmailError>>() {
        let class = match error {
            SdkError::ConstructionFailure(_) => "ses_request_construction",
            SdkError::TimeoutError(_) => "ses_timeout",
            SdkError::DispatchFailure(_) => "ses_transport",
            SdkError::ResponseError(_) => "ses_response_parse",
            SdkError::ServiceError(_) => "ses_service",
            _ => "ses_unknown",
        };
        return (
            class,
            safe_service_code(error.as_service_error().and_then(|e| e.meta().code())),
        );
    }
    if error.is::<std::env::VarError>() {
        return ("lambda_credentials_missing", None);
    }
    if error.is::<aws_sdk_sesv2::error::BuildError>() {
        return ("mail_message_construction", None);
    }
    if let Some(error) = error.downcast_ref::<reqwest::Error>() {
        return (
            if error.is_timeout() {
                "mail_http_timeout"
            } else {
                "mail_http_transport"
            },
            error.status().map(|s| format!("HTTP{}", s.as_u16())),
        );
    }
    ("mail_configuration", None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mail_diagnostics_do_not_include_error_messages_or_unsafe_codes() {
        use aws_sdk_sesv2::{error::SdkError, operation::send_email::SendEmailError};
        let error: SdkError<SendEmailError> = SdkError::construction_failure(
            std::io::Error::other("private payload /api/login/#token=DO_NOT_LOG"),
        );
        assert_eq!(safe_mail_error(&error), ("ses_request_construction", None));
        assert_eq!(
            safe_service_code(Some("AccountSuspendedException")),
            Some("AccountSuspendedException".into())
        );
        assert_eq!(safe_service_code(Some("unsafe\nsecret")), None);
        assert_eq!(
            safe_service_code(Some("https://app/login/#token=secret")),
            None
        );
    }
}
async fn send(
    app: &App,
    to: &str,
    link: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subject = format!("Sign in to {}", app.name.replace(['\r', '\n'], " "));
    let text = format!(
        "Sign in to {}\n\nOpen this link, then select Confirm sign in:\n{link}\n\nThis link can be used once and expires in 15 minutes. If you did not request it, you can ignore this email.",
        app.name
    );
    let html = format!(
        "<h1>Sign in to {}</h1><p><a href=\"{}\">Continue to sign in</a></p><p>Confirm sign in on the page that opens. This link can be used once and expires in 15 minutes.</p><p>If you did not request it, you can ignore this email.</p>",
        escape(&app.name),
        escape(link)
    );
    if let Some(endpoint) = &app.mail_endpoint {
        let parsed = url::Url::parse(endpoint)?;
        if parsed.scheme() != "http"
            || !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
        {
            return Err("Test mail transport must be loopback HTTP".into());
        }
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?
            .post(endpoint)
            .json(&json!({"from":app.mail_from,"to":to,"subject":subject,"text":text,"html":html}))
            .send()
            .await?
            .error_for_status()?;
        return Ok(());
    }
    if let Some(api_key) = &app.mail_api_key {
        reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?
            .post("https://api.sendgrid.com/v3/mail/send")
            .bearer_auth(api_key)
            .json(&json!({
                "personalizations":[{"to":[{"email":to}]}],
                "from":{"email":app.mail_from,"name":app.name},
                "subject":subject,
                "content":[{"type":"text/plain","value":text},{"type":"text/html","value":html}],
                "tracking_settings":{"click_tracking":{"enable":false,"enable_text":false},"open_tracking":{"enable":false},"subscription_tracking":{"enable":false},"ganalytics":{"enable":false}}
            }))
            .send().await?.error_for_status()?;
        return Ok(());
    }
    use aws_sdk_sesv2::{
        config::{Credentials, Region, retry::RetryConfig, timeout::TimeoutConfig},
        types::{Body, Content, Destination, EmailContent, Message},
    };
    let credentials = Credentials::new(
        std::env::var("AWS_ACCESS_KEY_ID")?,
        std::env::var("AWS_SECRET_ACCESS_KEY")?,
        Some(std::env::var("AWS_SESSION_TOKEN")?),
        None,
        "lambda-role",
    );
    let config = aws_sdk_sesv2::Config::builder()
        .behavior_version_latest()
        .region(Region::new(app.mail_region.clone()))
        .credentials_provider(credentials)
        .retry_config(RetryConfig::standard().with_max_attempts(2))
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(15))
                .build(),
        )
        .build();
    let message = Message::builder()
        .subject(Content::builder().charset("UTF-8").data(subject).build()?)
        .body(
            Body::builder()
                .text(Content::builder().charset("UTF-8").data(text).build()?)
                .html(Content::builder().charset("UTF-8").data(html).build()?)
                .build(),
        )
        .build();
    aws_sdk_sesv2::Client::from_conf(config)
        .send_email()
        .from_email_address(&app.mail_from)
        .destination(Destination::builder().to_addresses(to).build())
        .content(EmailContent::builder().simple(message).build())
        .send()
        .await?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Verify {
    token: String,
}
pub(super) async fn verify(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Verify>,
) -> Result<Response, ApiError> {
    same_origin(&app, &headers)?;
    if input.token.len() != 64 || !input.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::Unauthenticated);
    }
    let mut tx = app.pool.begin().await.map_err(ApiError::internal)?;
    let email: String = sqlx::query_scalar(
        "DELETE FROM app_magic_links WHERE digest=$1 AND expires>now() RETURNING email",
    )
    .bind(hash(&input.token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?
    .ok_or(ApiError::Unauthenticated)?;
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
    let subject = format!("email:{email}");
    let identity: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app_records WHERE kind='identities' AND data->>'provider'='email_magic_link' AND data->>'subject'=$1)",
    )
    .bind(&subject)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    if !identity {
        for (kind, data) in [
            (
                "identities",
                json!({"name":email,"user":id,"provider":"email_magic_link","subject":subject}),
            ),
            (
                "identity_verifications",
                json!({"name":email,"user":id,"verified":true,"method":"email_magic_link"}),
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
    }
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
    let mut response = json_response(StatusCode::OK, json!({"redirect":app.origin}));
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("dream_app={session}; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=43200")
            .parse()
            .map_err(ApiError::internal)?,
    );
    Ok(response)
}
