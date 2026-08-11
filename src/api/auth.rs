//! `GET /api/auth/me` — reports the caller's own identity and RBAC flags, so the SPA can gate its
//! UI without guessing.

use axum::{Extension, Json, response::IntoResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::entities::api_key;

/// The caller's identity, as seen by the server.
#[derive(Serialize)]
pub struct MeResponse {
    id: Uuid,
    name: String,
    prefix: String,
    is_master: bool,
    can_manage_keys: bool,
    bound_ips: Option<String>,
}

/// Handles `GET /api/auth/me`.
pub async fn get_me(Extension(key): Extension<api_key::Model>) -> impl IntoResponse {
    Json(MeResponse {
        id: key.id,
        name: key.name,
        prefix: key.prefix,
        is_master: key.is_master,
        can_manage_keys: key.can_manage_keys,
        bound_ips: key.bound_ips,
    })
}
