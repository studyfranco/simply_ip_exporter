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

    /// A conflict the caller is expected to *resolve*, carrying the structured detail needed to do
    /// so — e.g. deleting an API key that still owns endpoints: the inventory of what it owns, so
    /// the caller can decide whether to reassign or delete them without a second round-trip to
    /// discover what's blocking the delete. `details` is merged into the response body alongside
    /// `error`, so a client that only reads `error` behaves exactly as it does for [`Self::Conflict`].
    #[error("Conflict: {message}")]
    ConflictWithDetails {
        /// Human-readable summary, in the same `error` field every other variant uses.
        message: String,
        /// Machine-readable detail, merged into the response body at the top level.
        details: serde_json::Value,
    },

    /// The caller exceeded the anti-DoS rate limit.
    #[error("Too Many Requests: {0}")]
    TooManyRequests(String),

    /// A request body an extractor refused before any handler ran, carrying the extractor's own
    /// status verbatim (see [`crate::extract::StrictJson`]).
    ///
    /// Exists so a malformed-body rejection can be normalized into this service's `{"error": ...}`
    /// envelope without flattening an *unrelated* rejection into it too — the body-size limit
    /// surfaces as the same underlying `JsonRejection` type, and collapsing it here would turn a
    /// `413 Payload Too Large` into an indistinguishable `400`. The status is passed through
    /// verbatim; only the response body's shape is normalized.
    #[error("Request rejected: {1}")]
    BodyRejected(StatusCode, String),

    /// Internal server error.
    #[error("Internal Server Error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Handled ahead of the flat match: it's the one variant whose body is not just
        // `{"error": ...}` — the structured detail is merged in at the top level rather than
        // nested, so `error` reads identically to every other variant for a client that ignores
        // the rest.
        if let AppError::ConflictWithDetails { message, details } = self {
            let mut body = json!({ "error": message });
            if let (Some(object), Some(extra)) = (body.as_object_mut(), details.as_object()) {
                for (k, v) in extra {
                    object.insert(k.clone(), v.clone());
                }
            }
            return (StatusCode::CONFLICT, Json(body)).into_response();
        }

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
            // Returned above; repeated here only because the match must stay exhaustive.
            AppError::ConflictWithDetails { message, .. } => (StatusCode::CONFLICT, message),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            AppError::BodyRejected(status, msg) => (status, msg),
            AppError::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal server error occurred".to_owned())
            }
        };

        (status, Json(json!({ "error": error_message }))).into_response()
    }
}
