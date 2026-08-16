//! Request extractors that make a rejection's shape a property of the **type**, not of a handler.
//!
//! Axum's built-in `Json<T>`/`Path<T>` extractors reject a malformed request *before* any handler
//! runs, with a plain-text body of their own — not the `{"error": ...}` envelope every other
//! refusal in this service uses ([`crate::error::AppError::into_response`]). A client (including
//! this crate's own `static/app.js`, whose `apiCall` does `JSON.parse(text)` on every response)
//! that only ever expects that envelope gets an inconsistent shape back for exactly the malformed
//! requests it's most likely to be debugging. [`StrictJson`] and [`StrictPath`] wrap the built-in
//! extractors and remap their rejections through [`AppError`] instead.

use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Path, Request, rejection::JsonRejection},
    http::request::Parts,
};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::AppError;

/// [`Json`], with a body that failed to parse reported as [`AppError::InvalidInput`] (`400`, this
/// service's normal error envelope) instead of axum's own plain-text rejection body.
///
/// A body rejected for a reason *other* than its content — the router-wide
/// [`crate::MAX_REQUEST_BODY_BYTES`] limit surfaces as a `JsonRejection` too — keeps whatever
/// status axum chose (`413`, not `400`) via [`AppError::BodyRejected`], so an oversized payload is
/// never misreported as merely malformed.
pub struct StrictJson<T>(pub T);

impl<T, S> FromRequest<S> for StrictJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection @ (JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_))) => {
                Err(AppError::InvalidInput(rejection.body_text()))
            }
            Err(other) => Err(AppError::BodyRejected(other.status(), other.body_text())),
        }
    }
}

/// [`Path`]`<Uuid>`, with a malformed path segment reported as [`AppError::InvalidInput`] rather
/// than axum's plain-text rejection body.
pub struct StrictPath(pub Uuid);

impl<S> FromRequestParts<S> for StrictPath
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<Uuid>::from_request_parts(parts, state).await {
            Ok(Path(id)) => Ok(Self(id)),
            Err(rejection) => Err(AppError::InvalidInput(rejection.body_text())),
        }
    }
}
