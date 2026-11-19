//! `GET /feed/v1/<token_secret>/list.txt` — the public, unauthenticated feed endpoint.
//!
//! Security here rests on the secrecy of `token_secret`, optional `bound_ips`, real-time owner
//! permission verification against `vault_group_permissions`, and per-IP rate limiting applied at
//! the entry of every request before database lookups or DNS resolution.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::bound_ips;
use crate::config::resolve_client_ip;
use crate::entities::{endpoint, prelude::Endpoint};
use crate::error::AppError;
use crate::ipfilter::filter_and_aggregate;
use crate::state::AppState;

/// `GET /feed/v1/{token_secret}/list.txt`.
///
/// # Errors
/// Returns [`AppError`] if the token is unknown, client IP/permissions are forbidden, or database lookups fail.
pub async fn serve_feed(
    State(state): State<AppState>,
    Path(token_secret): Path<String>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // See `middleware::auth_middleware`'s identical call for why this is awaited per request
    // rather than resolved once at startup.
    let trusted_proxies = state.config.trusted_proxies.resolved().await;
    let client_ip = resolve_client_ip(addr.ip(), &headers, &trusted_proxies);

    if let Err(remaining) = state.rate_limiter.check_and_record(client_ip) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", remaining.as_secs().to_string())],
            "Rate limit exceeded: at most one request per source IP every 2 minutes\n",
        )
            .into_response());
    }

    let ep = Endpoint::find()
        .filter(endpoint::Column::TokenSecret.eq(token_secret))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(raw) = ep.bound_ips.as_deref().filter(|s| !s.trim().is_empty()) {
        let entries = bound_ips::parse_bound_ips(raw).map_err(|_| {
            tracing::error!(
                "Invalid bound_ips in database for endpoint {}: {:?}",
                ep.id,
                ep.bound_ips
            );
            AppError::Internal
        })?;
        if !bound_ips::is_allowed(&entries, client_ip, &state.dns_resolver).await {
            return Err(AppError::Forbidden(
                "Client IP not allowed for this endpoint".to_owned(),
            ));
        }
    }

    match crate::groups::verify_endpoint_group_permissions(&state, &ep).await? {
        crate::groups::EndpointGroupAuth::AllAuthorized(_) => {}
        crate::groups::EndpointGroupAuth::PartiallyAuthorized(_)
        | crate::groups::EndpointGroupAuth::Denied => {
            return Err(AppError::Forbidden(
                "Endpoint owner lacks permission for configured Vault groups".to_owned(),
            ));
        }
    }

    // The endpoint's retention window is applied here, at feed generation, rather than during sync:
    // the cutoff is relative to *now*, and an operator editing `max_age_seconds` expects the next
    // fetch to reflect it rather than the next sync (up to 24h away). `0` means unlimited. See
    // `cache::IpCache::snapshot_within` for the full rationale.
    let raw = state
        .ip_cache
        .snapshot_within(ep.id, ep.max_age_seconds, chrono::Utc::now().naive_utc())
        .await;
    let aggregated = filter_and_aggregate(
        &raw,
        ep.filter_rfc1918,
        ep.filter_bogons,
        ep.filter_loopback,
    );

    let mut lines: Vec<String> = aggregated.iter().map(ToString::to_string).collect();
    lines.sort();
    let body = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };

    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let etag = format!("\"{}\"", hex::encode(hasher.finalize()));

    if let Some(inm) = headers.get("If-None-Match").and_then(|h| h.to_str().ok())
        && inm.trim() == etag
    {
        return Ok((StatusCode::NOT_MODIFIED, [("ETag", etag)]).into_response());
    }

    Ok((
        StatusCode::OK,
        [
            ("Content-Type", "text/plain; charset=utf-8".to_owned()),
            ("ETag", etag),
        ],
        body,
    )
        .into_response())
}
