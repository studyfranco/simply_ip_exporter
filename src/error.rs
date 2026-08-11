//! Application errors.

use axum::{Json, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::json;
use thiserror::Error;

/// Global application error type. Every handler returns `Result<_, AppError>`; the
/// [`IntoResponse`] implementation is the single place that decides status codes and what detail
/// reaches the client.
#[derive(Error, Debug)]
pub enum AppError {
    /// Database error.
    #[error("Database error: {0}")]
    DbError(#[from] sea_orm::DbErr),

    /// Invalid input (malformed payload, failed validation, missing required parameters).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Missing or invalid credentials.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated, but lacking the required permission.
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Resource not found.
    #[error("Not Found")]
    NotFound,

    /// The request conflicts with current state.
    #[error("Conflict: {0}")]
    Conflict(String),

    /// The caller exceeded the anti-DoS rate limit.
    #[error("Too Many Requests: {0}")]
    TooManyRequests(String),

    /// Internal server error.
    #[error("Internal Server Error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::DbError(err) => {
                tracing::error!("Database error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error".to_owned())
            }
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_owned()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            AppError::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal server error occurred".to_owned())
            }
        };

        (status, Json(json!({ "error": error_message }))).into_response()
    }
}
