//! System settings & introspection endpoint (`GET /api/settings`).
//! Master-only: reports effective runtime configuration and entity counts.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use sea_orm::{EntityTrait, PaginatorTrait};
use serde::Serialize;

use crate::entities::{api_key, audit_log, endpoint};
use crate::error::AppError;
use crate::state::AppState;

/// Runtime system configuration and entity counts shown on the System Settings tab.
#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    /// Peers whose forwarding headers are believed.
    pub trusted_proxies: Vec<String>,
    /// Whether secrets-at-rest encryption is active.
    pub encryption_enabled: bool,
    /// Configured Vault base URL, if any.
    pub vault_base_url: Option<String>,
    /// How far a signature timestamp may drift, in seconds.
    pub signature_max_age_seconds: i64,
    /// Total public feed endpoints defined.
    pub endpoint_count: u64,
    /// Total active API keys.
    pub api_key_count: u64,
    /// Total audit log records retained.
    pub audit_log_count: u64,
}

/// Handles `GET /api/settings`. Master-only.
pub async fn get_settings(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden(
            "System settings are visible to the Master key only".to_owned(),
        ));
    }

    let endpoint_count = endpoint::Entity::find().count(&state.db).await?;
    let api_key_count = api_key::Entity::find().count(&state.db).await?;
    let audit_log_count = audit_log::Entity::find().count(&state.db).await?;

    Ok(Json(SettingsResponse {
        trusted_proxies: state
            .config
            .trusted_proxies
            .matchers()
            .iter()
            .map(ToString::to_string)
            .collect(),
        encryption_enabled: state.cipher.is_encrypting(),
        vault_base_url: state.config.vault_base_url.clone(),
        signature_max_age_seconds: state.config.signature_max_age_seconds,
        endpoint_count,
        api_key_count,
        audit_log_count,
    }))
}
