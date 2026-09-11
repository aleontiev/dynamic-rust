use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[cfg(feature = "axum")]
use axum::{Json, http::StatusCode, response::IntoResponse};

pub type FieldErrors = BTreeMap<String, Vec<String>>;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub detail: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Authentication credentials were not provided.")]
    Unauthenticated,
    #[error("You do not have permission to perform this action.")]
    Forbidden,
    #[error("Not found.")]
    NotFound,
    #[error("{0}")]
    NotFoundDetail(String),
    #[error("Method \"{0}\" not allowed.")]
    MethodNotAllowed(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("{0}")]
    Parse(String),
    #[error("{0}")]
    RawBadRequest(String),
    #[error("validation failed")]
    Validation(FieldErrors),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal server error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ApiError {
    #[must_use]
    pub fn internal(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal(Box::new(error))
    }
}

#[cfg(feature = "axum")]
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let error = match self {
            Self::RawBadRequest(message) => {
                return (StatusCode::BAD_REQUEST, Json(Value::String(message))).into_response();
            }
            error => error,
        };
        let (status, detail) = match error {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                Value::String("Authentication credentials were not provided.".into()),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                Value::String("You do not have permission to perform this action.".into()),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, Value::String("Not found.".into())),
            Self::NotFoundDetail(message) => (StatusCode::NOT_FOUND, Value::String(message)),
            Self::MethodNotAllowed(method) => (
                StatusCode::METHOD_NOT_ALLOWED,
                Value::String(format!("Method \"{method}\" not allowed.")),
            ),
            Self::NotImplemented(name) => (
                StatusCode::NOT_IMPLEMENTED,
                Value::String(format!("Not implemented: {name}")),
            ),
            Self::Parse(message) => (StatusCode::BAD_REQUEST, Value::String(message)),
            Self::RawBadRequest(_) => unreachable!(),
            Self::Validation(errors) => (
                StatusCode::BAD_REQUEST,
                serde_json::to_value(errors).unwrap_or(Value::Null),
            ),
            Self::Conflict(message) => (StatusCode::CONFLICT, Value::String(message)),
            Self::Internal(error) => {
                tracing_error(&*error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Value::String("Internal Server Error".into()),
                )
            }
        };
        (status, Json(ErrorBody { detail })).into_response()
    }
}

#[cfg(feature = "axum")]
fn tracing_error(error: &(dyn std::error::Error + Send + Sync)) {
    tracing::error!(error = %error, "dynamic REST request failed");
}
