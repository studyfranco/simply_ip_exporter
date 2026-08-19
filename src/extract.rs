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
    extract::{FromRequest, FromRequestParts, Path, Query, Request, rejection::JsonRejection},
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

/// [`Query`]`<T>`, with a malformed or unrecognized query-string parameter reported as
/// [`AppError::InvalidInput`] (`400`, this service's normal error envelope) instead of axum's own
/// plain-text rejection body.
///
/// `T` deriving `#[serde(deny_unknown_fields)]` is what makes an unrecognized query parameter a
/// rejection at all (`?limit=10&limit_typo=5` would otherwise be silently ignored, the same gap
/// `StrictJson`'s module doc comment describes for JSON bodies) — this extractor only normalizes
/// the *shape* of that rejection once serde has already decided to produce one.
pub struct StrictQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for StrictQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::InvalidInput(rejection.body_text())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, request::Parts};

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestQuery {
        #[serde(default)]
        limit: Option<u64>,
    }

    fn parts_for(uri: &str) -> Parts {
        Request::builder().uri(uri).body(()).expect("a request with no body always builds").into_parts().0
    }

    #[tokio::test]
    async fn a_well_formed_query_string_parses() {
        let mut parts = parts_for("/x?limit=10");
        let StrictQuery(value) =
            StrictQuery::<TestQuery>::from_request_parts(&mut parts, &()).await.expect("parses");
        assert_eq!(value.limit, Some(10));
    }

    #[tokio::test]
    async fn an_absent_query_string_uses_field_defaults() {
        let mut parts = parts_for("/x");
        let StrictQuery(value) =
            StrictQuery::<TestQuery>::from_request_parts(&mut parts, &()).await.expect("parses");
        assert_eq!(value.limit, None);
    }

    #[tokio::test]
    async fn a_malformed_value_is_reported_as_invalid_input_not_axum_plain_text() {
        let mut parts = parts_for("/x?limit=not-a-number");
        match StrictQuery::<TestQuery>::from_request_parts(&mut parts, &()).await {
            Err(AppError::InvalidInput(_)) => {}
            Err(_) => panic!("expected AppError::InvalidInput"),
            Ok(_) => panic!("a non-numeric limit must not parse"),
        }
    }

    /// The extractor only normalizes rejection *shape*; `deny_unknown_fields` on the target type is
    /// what makes a stray query parameter a rejection in the first place — see this type's own doc
    /// comment.
    #[tokio::test]
    async fn an_unknown_field_is_rejected_and_named_in_the_message() {
        let mut parts = parts_for("/x?limit=10&stray=1");
        match StrictQuery::<TestQuery>::from_request_parts(&mut parts, &()).await {
            Err(AppError::InvalidInput(msg)) => {
                assert!(msg.contains("stray"), "the error should name the rejected field: {msg}");
            }
            Err(_) => panic!("expected AppError::InvalidInput"),
            Ok(_) => panic!("an unknown field must not parse"),
        }
    }
}
