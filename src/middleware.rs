//! Authentication middleware for `/api/*`: mandatory `CANONICAL_V1` HMAC-SHA256 request signing,
//! single-use anti-replay enforcement, and `bound_ips` CIDR restriction.

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use ipnet::IpNet;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::config::resolve_client_ip;
use crate::crypto::{SignatureRejection, canonical_v1_payload, verify_signature};
use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

/// Header carrying the caller's secret key.
const API_KEY_HEADER: &str = "X-API-Key";
/// Header carrying the `sha256=<hex>` request signature.
const SIGNATURE_HEADER: &str = "X-Signature-256";
/// Header carrying the Unix-seconds timestamp a signature was computed at.
const TIMESTAMP_HEADER: &str = "X-Timestamp";
/// Largest request body buffered to verify a signature. The same constant the router enforces via
/// `DefaultBodyLimit`, so the two layers can never drift apart.
const MAX_SIGNED_BODY_BYTES: usize = crate::MAX_REQUEST_BODY_BYTES;

/// The resolved client IP for the current request, inserted into request extensions.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub std::net::IpAddr);

/// Rejects a timestamp outside the anti-replay window, symmetrically in both directions.
fn validate_timestamp(raw: &str, max_age_seconds: i64) -> Result<(), AppError> {
    let presented: i64 = raw
        .trim()
        .parse()
        .map_err(|_| AppError::Unauthorized(format!("{TIMESTAMP_HEADER} must be a Unix timestamp")))?;

    let skew = (chrono::Utc::now().timestamp() - presented).abs();
    if skew > max_age_seconds {
        return Err(AppError::Unauthorized(format!(
            "Request timestamp is outside the permitted {max_age_seconds}s window (off by {skew}s)"
        )));
    }
    Ok(())
}

fn reject_signature(rejection: SignatureRejection, key_prefix: &str) -> AppError {
    match rejection {
        SignatureRejection::MissingPrefix => {
            AppError::Unauthorized("Signature must be formatted as sha256=<hex>".to_owned())
        }
        SignatureRejection::MalformedHex => {
            AppError::Unauthorized("Signature is not valid hexadecimal".to_owned())
        }
        SignatureRejection::Mismatch => AppError::Unauthorized("Invalid request signature".to_owned()),
        SignatureRejection::KeyUnusable => {
            tracing::error!(key = %key_prefix, "Stored signing secret is unusable as HMAC key material");
            AppError::Internal
        }
    }
}

fn recover_signing_secret(
    state: &AppState,
    key_record: &crate::entities::api_key::Model,
) -> Result<String, AppError> {
    let stored = key_record.signing_secret.as_deref().ok_or_else(|| {
        AppError::Unauthorized("This API key has no signing secret; rotate it to obtain one".to_owned())
    })?;
    state.cipher.open(stored).map_err(|e| {
        tracing::error!(key = %key_record.prefix, "Failed to decrypt a stored signing secret: {e}");
        AppError::Internal
    })
}

/// Enforces API key authentication, `CANONICAL_V1` signing, single-use replay protection, and
/// `bound_ips` for every `/api/*` route.
///
/// Ordering matters: the timestamp is validated before the database is touched, so a stale or
/// malformed one costs an unauthenticated caller nothing; `bound_ips` is checked only after the
/// signature verifies, so a caller holding a leaked `X-API-Key` alone cannot use the 403-vs-401
/// split to map a key's network binding.
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // `resolved()` is what turns a hostname entry into addresses. Awaited per request so a
    // container that moved is picked up within the DNS reuse window rather than at the next
    // restart; with no hostnames configured it's a refcount bump and touches neither lock nor
    // resolver — see `config::TrustedProxies::resolved`.
    let trusted_proxies = state.config.trusted_proxies.resolved().await;
    let client_ip = resolve_client_ip(addr.ip(), &headers, &trusted_proxies);

    let presented_key = headers
        .get(API_KEY_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            AppError::Unauthorized(format!("Missing credentials: provide an {API_KEY_HEADER} header"))
        })?;

    let timestamp_header = headers
        .get(TIMESTAMP_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized(format!("A signed request must include {TIMESTAMP_HEADER}")))?
        .to_owned();
    validate_timestamp(&timestamp_header, state.config.signature_max_age_seconds)?;

    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized(format!("A signed request must include {SIGNATURE_HEADER}")))?
        .to_owned();

    let mut hasher = Sha256::new();
    hasher.update(presented_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let mut key_record = ApiKey::find()
        .filter(crate::entities::api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or(AppError::Unauthorized("Invalid API Key".to_owned()))?;

    state.master_pin.authenticate(&state.db, &mut key_record).await;

    let secret = recover_signing_secret(&state, &key_record)?;

    let (parts, body) = req.into_parts();

    // A declared `Content-Length` over the limit is rejected as `413` before any of the body is
    // read — the correct status for "this body is too large", which `to_bytes`'s own limit below
    // cannot express (it has no way to distinguish "too large" from any other read failure, so it
    // is mapped to a generic `400`). This only covers requests carrying the header; a chunked body
    // with no `Content-Length` still falls through to that fallback.
    if let Some(declared) = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && declared > MAX_SIGNED_BODY_BYTES
    {
        return Err(AppError::BodyRejected(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the maximum allowed size".to_owned(),
        ));
    }

    let bytes = axum::body::to_bytes(body, MAX_SIGNED_BODY_BYTES).await.map_err(|_| {
        AppError::BodyRejected(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the maximum allowed size".to_owned(),
        )
    })?;

    let original_uri = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map(|o| &o.0)
        .unwrap_or(&parts.uri);
    let path_and_query =
        original_uri.path_and_query().map(|pq| pq.as_str()).unwrap_or_else(|| original_uri.path());
    let payload =
        canonical_v1_payload(parts.method.as_str(), path_and_query, &timestamp_header, &bytes);

    let digest = verify_signature(&secret, &payload, &signature)
        .map_err(|rejection| reject_signature(rejection, &key_record.prefix))?;

    if !state.replay_guard.check_and_record(key_record.id, &digest) {
        tracing::warn!(key = %key_record.prefix, "Rejected replay of an already-used signature");
        return Err(AppError::Unauthorized(
            "This signature has already been used; sign a fresh request".to_owned(),
        ));
    }

    let bound_ips_str = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNet> = bound_ips_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            tracing::error!("Invalid CIDR in database: {:?}", key_record.bound_ips);
            AppError::Internal
        })?;

    let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(&client_ip));
    if !is_allowed {
        tracing::warn!(
            key = %key_record.prefix,
            "Access denied: client IP {client_ip} not in bound networks {:?}",
            key_record.bound_ips
        );
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_inside_the_window_are_accepted() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(&now.to_string(), 300).is_ok());
        assert!(validate_timestamp(&(now - 299).to_string(), 300).is_ok());
        assert!(validate_timestamp(&(now + 299).to_string(), 300).is_ok());
    }

    #[test]
    fn timestamps_outside_the_window_are_rejected() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(&(now - 301).to_string(), 300).is_err());
        assert!(validate_timestamp(&(now + 301).to_string(), 300).is_err());
        assert!(validate_timestamp("not-a-number", 300).is_err());
    }
}
