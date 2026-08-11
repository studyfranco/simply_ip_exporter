//! Liveness and readiness probes. Neither requires authentication: the callers are container
//! orchestrators and load balancers, none of which can compute an HMAC over a rolling timestamp.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use sea_orm::{EntityTrait, PaginatorTrait};
use serde_json::json;

use crate::entities::prelude::ApiKey;
use crate::state::AppState;

/// `GET /health` / `/healthz` — liveness. Always `200`, and never touches the database.
pub async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "simply_ip_exporter" }))
}

/// `GET /ready` / `/readyz` — readiness. `200` only when the database answers and the Master
/// identity is pinned; `503` otherwise.
///
/// The database check is an ordinary SeaORM query (`AGENT.MD` forbids raw SQL outside `src/db.rs`
/// and migrations) — `count()` against `api_keys` rather than a raw `SELECT 1`, which proves the
/// connection and the schema are both usable without depending on the table holding any rows.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = ApiKey::find().count(&state.db).await.is_ok();
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
