#![warn(missing_docs)]
//! `simply_ip_exporter`: a DMZ proxy and public feed exporter that periodically syncs IP records
//! from `simply_ip_vault` and exposes aggregated, filtered `text/plain` lists for pfSense
//! (`pfBlockerNG`) and other firewall alias importers.
//!
//! IP data is held strictly in memory (`Arc<RwLock<...>>` via [`cache::IpCache`]) and is never
//! written to SQLite or disk; SQLite persists configuration only (`api_keys`, `endpoints`), per
//! `SCHEMA.MD`.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

/// Hard ceiling on the size of any request body this service will buffer, in bytes (3 MiB). The
/// single source of truth for both the router's `DefaultBodyLimit` and
/// `middleware::MAX_SIGNED_BODY_BYTES`.
pub const MAX_REQUEST_BODY_BYTES: usize = 3 * 1024 * 1024;

pub mod api;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod db;
pub mod entities;
pub mod error;
pub mod feed;
pub mod ipfilter;
pub mod master;
pub mod middleware;
pub mod migration;
pub mod ratelimit;
pub mod replay;
pub mod state;
pub mod sync;
pub mod vault_client;

use state::AppState;

/// Creates the complete Axum router for the application.
pub fn create_app(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/auth/me", get(api::get_me))
        .route("/keys", post(api::create_api_key))
        .route("/keys", get(api::list_api_keys))
        .route("/keys/{id}", put(api::update_api_key))
        .route("/keys/{id}", delete(api::delete_api_key))
        .route("/keys/{id}/rotate", post(api::rotate_api_key))
        .route("/endpoints", post(api::create_endpoint))
        .route("/endpoints", get(api::list_endpoints))
        .route("/endpoints/{id}", put(api::update_endpoint))
        .route("/endpoints/{id}", delete(api::delete_endpoint))
        .route("/endpoints/{id}/owner", put(api::reassign_endpoint_owner))
        .route("/audit-logs", get(api::list_audit_logs))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));

    Router::new()
        .fallback_service(ServeDir::new("static"))
        // Probes sit outside `auth_middleware`, which cannot be satisfied by a caller with no
        // credentials (Docker's HEALTHCHECK, a Kubernetes probe, a load balancer).
        .route("/health", get(api::health_check))
        .route("/healthz", get(api::health_check))
        .route("/ready", get(api::readiness_check))
        .route("/readyz", get(api::readiness_check))
        // Also outside auth: the whole point of the public feed is a URL-embedded secret token
        // instead of a header-based credential.
        .route("/feed/v1/{token_secret}/list.txt", get(feed::serve_feed))
        .nest("/api", api_routes)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
