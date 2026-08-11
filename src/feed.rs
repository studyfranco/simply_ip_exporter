//! `GET /feed/v1/<token_secret>/list.txt` — the public, unauthenticated feed endpoint.
//!
//! Security here rests entirely on the secrecy of `token_secret`, not on HTTP headers.
//!
//! The rate limiter gates the expensive path — serving a full `200` body — rather than every
//! request indiscriminately. A conditional request whose `If-None-Match` matches the current
//! ETag is answered `304` for free, with no rate-limit consumption at all: the caller has already
//! proven it holds an up-to-date copy, computing the ETag is a cheap in-memory operation, and
//! throttling that exchange would defeat the entire point of supporting ETags — a well-behaved
//! poller (pfBlockerNG et al.) that dutifully revalidates would get needlessly `429`'d instead of
//! the cheap `304` the mechanism exists to provide. Guessing an ETag to farm free responses is not
//! a workable attack: an attacker without the current body cannot produce a matching digest.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::config::resolve_client_ip;
use crate::entities::{endpoint, prelude::Endpoint};
use crate::error::AppError;
use crate::ipfilter::filter_and_aggregate;
use crate::state::AppState;

/// `GET /feed/v1/{token_secret}/list.txt`.
pub async fn serve_feed(
    State(state): State<AppState>,
    Path(token_secret): Path<String>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let client_ip =
        resolve_client_ip(addr.ip(), &headers, state.config.trusted_proxies.networks());

    let ep = Endpoint::find()
        .filter(endpoint::Column::TokenSecret.eq(token_secret))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(bound_ips) = ep.bound_ips.as_deref().filter(|s| !s.trim().is_empty()) {
        let networks: Vec<ipnet::IpNet> = bound_ips
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();
        if !networks.iter().any(|net| net.contains(&client_ip)) {
            return Err(AppError::Forbidden("Client IP not allowed for this endpoint".to_owned()));
        }
    }

    let raw = state.ip_cache.snapshot(ep.id).await;
    let aggregated =
        filter_and_aggregate(&raw, ep.filter_rfc1918, ep.filter_bogons, ep.filter_loopback);

    let mut lines: Vec<String> = aggregated.iter().map(|net| net.to_string()).collect();
    lines.sort();
    let body = if lines.is_empty() { String::new() } else { format!("{}\n", lines.join("\n")) };

    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let etag = format!("\"{}\"", hex::encode(hasher.finalize()));

    if let Some(inm) = headers.get("If-None-Match").and_then(|h| h.to_str().ok())
        && inm.trim() == etag
    {
        return Ok((StatusCode::NOT_MODIFIED, [("ETag", etag)]).into_response());
    }

    if let Err(remaining) = state.rate_limiter.check_and_record(client_ip) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", remaining.as_secs().to_string())],
            "Rate limit exceeded: at most one request per source IP every 2 minutes\n",
        )
            .into_response());
    }

    Ok((
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8".to_owned()), ("ETag", etag)],
        body,
    )
        .into_response())
}
