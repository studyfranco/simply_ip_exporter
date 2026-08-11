//! Liveness and readiness probes. Neither requires authentication: the callers are container
//! orchestrators and load balancers, none of which can compute an HMAC over a rolling timestamp.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::json;

use crate::state::AppState;

/// `GET /health` / `/healthz` — liveness. Always `200`, and never touches the database.
pub async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "simply_ip_exporter" }))
}

/// `GET /ready` / `/readyz` — readiness. `200` only when the database answers and the Master
/// identity is pinned; `503` otherwise.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = state
        .db
        .execute_raw(Statement::from_string(DatabaseBackend::Sqlite, "SELECT 1"))
        .await
        .is_ok();
    let master_pinned = state.master_pin.get().is_some();

    if db_ok && master_pinned {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "database": db_ok, "master_pinned": master_pinned })),
        )
    }
}
