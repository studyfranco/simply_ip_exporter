//! Read access to `simply_ip_vault` groups: listing what Vault currently has, and managing which
//! local API keys may reference which group in their own endpoints' `vault_groups`.
//!
//! Ported at the user's request from the M:N per-group permission model `example/simply_ip_vault`
//! implements for itself (`RBAC_MODEL.md`) — narrower here on purpose: this crate only ever needs
//! *read* access to a group (it aggregates and republishes, it never writes back to Vault), so
//! there is exactly one right to grant, not vault's own read/write/delete/manage set. A grant's
//! existence in `vault_group_permissions` **is** the right — no separate boolean column.

use axum::{Extension, Json, extract::State, response::IntoResponse};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::api::guards::require_master;
use crate::api::support::{create_audit_log, describe_resource};
use crate::entities::{api_key, prelude::ApiKey, prelude::VaultGroupPermission, vault_group_permission};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;
use crate::vault_client::VaultGroup as VaultClientGroup;

/// `GET /api/vault-groups` — Master-only: lists every group Vault currently has (Vault-side
/// restricted to what this crate's own configured Vault key can read), for the "grant a local key
/// read access to a group" UI to pick from.
pub async fn list_vault_groups(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let client = state.vault_client.as_ref().ok_or(AppError::VaultNotConfigured)?;
    let groups = client.list_groups().await.map_err(|e| {
        tracing::warn!("Could not list Vault groups: {e}");
        AppError::VaultUnreachable
    })?;

    Ok(Json(groups.into_iter().map(VaultGroupResponse::from).collect::<Vec<_>>()))
}

#[derive(Serialize)]
struct VaultGroupResponse {
    id: Uuid,
    name: String,
}

impl From<VaultClientGroup> for VaultGroupResponse {
    fn from(g: VaultClientGroup) -> Self {
        Self { id: g.id, name: g.name }
    }
}

/// A single (key, group) grant as returned to clients.
#[derive(Serialize)]
pub struct GroupGrantResponse {
    id: Uuid,
    api_key_id: Uuid,
    vault_group_id: Uuid,
    vault_group_name: String,
    created_at: chrono::NaiveDateTime,
}

impl From<vault_group_permission::Model> for GroupGrantResponse {
    fn from(m: vault_group_permission::Model) -> Self {
        Self {
            id: m.id,
            api_key_id: m.api_key_id,
            vault_group_id: m.vault_group_id,
            vault_group_name: m.vault_group_name,
            created_at: m.created_at,
        }
    }
}

/// `GET /api/keys/{id}/groups` — lists a key's Vault-group read grants. Master may inspect any
/// key; a Daughter may inspect only its own — the same self-or-Master shape `endpoints::may_manage`
/// uses, needed here so a Daughter's own endpoint-creation form can show what it's allowed to use
/// without requiring `can_manage_keys`.
pub async fn list_key_groups(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    StrictPath(id): StrictPath,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master && caller.id != id {
        return Err(AppError::Forbidden("You may only view your own group grants".to_owned()));
    }

    let grants = VaultGroupPermission::find()
        .filter(vault_group_permission::Column::ApiKeyId.eq(id))
        .all(&state.db)
        .await?;
    Ok(Json(grants.into_iter().map(GroupGrantResponse::from).collect::<Vec<_>>()))
}

/// Payload for granting a key read access to a Vault group. Only the group's id is accepted —
/// its name is resolved from a fresh call to Vault, not trusted from the client, so a grant can
/// never record a name that doesn't actually match the id (and a nonexistent id is refused
/// outright, catching a typo'd UUID at grant time rather than silently storing it).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantGroupPayload {
    vault_group_id: Uuid,
}

/// `POST /api/keys/{id}/groups` — Master-only: grants the named local key read access to a Vault
/// group. Idempotent: granting a group the key already has access to changes nothing and returns
/// the existing grant, rather than a conflict — a repeat grant is not an error condition.
pub async fn grant_key_group(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
    StrictJson(payload): StrictJson<GrantGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    let client = state.vault_client.as_ref().ok_or(AppError::VaultNotConfigured)?;
    let groups = client.list_groups().await.map_err(|e| {
        tracing::warn!("Could not list Vault groups while granting access: {e}");
        AppError::VaultUnreachable
    })?;
    let group = groups
        .into_iter()
        .find(|g| g.id == payload.vault_group_id)
        .ok_or_else(|| AppError::InvalidInput("No such Vault group".to_owned()))?;

    if let Some(existing) = VaultGroupPermission::find()
        .filter(vault_group_permission::Column::ApiKeyId.eq(id))
        .filter(vault_group_permission::Column::VaultGroupId.eq(group.id))
        .one(&state.db)
        .await?
    {
        return Ok(Json(GroupGrantResponse::from(existing)));
    }

    let now = Utc::now().naive_utc();
    let model = vault_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(id),
        vault_group_id: Set(group.id),
        vault_group_name: Set(group.name.clone()),
        created_at: Set(now),
    };
    let created = model.insert(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "KEY_GROUP_GRANT",
        Some(describe_resource("api_key", target.id, &target.name)),
        Some(format!("granted read on Vault group {} ({})", group.name, group.id)),
    )
    .await?;

    Ok(Json(GroupGrantResponse::from(created)))
}

/// `DELETE /api/keys/{id}/groups/{permission_id}` — Master-only: revokes a previously granted
/// Vault-group read right.
///
/// Takes axum's own `Path<(Uuid, Uuid)>` rather than [`StrictPath`]: that extractor only ever
/// wraps a single-segment `Path<Uuid>`, and this is the one route in this crate with two path
/// segments. The rejection is mapped to [`AppError::InvalidInput`] by hand here, the same
/// normalization `StrictPath` itself does internally.
pub async fn revoke_key_group(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    path: Result<axum::extract::Path<(Uuid, Uuid)>, axum::extract::rejection::PathRejection>,
) -> Result<impl IntoResponse, AppError> {
    let axum::extract::Path((id, permission_id)) =
        path.map_err(|rejection| AppError::InvalidInput(rejection.body_text()))?;

    require_master(&caller)?;

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let grant = VaultGroupPermission::find_by_id(permission_id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if grant.api_key_id != id {
        return Err(AppError::NotFound);
    }

    let group_name = grant.vault_group_name.clone();
    let group_id = grant.vault_group_id;
    VaultGroupPermission::delete_by_id(permission_id).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "KEY_GROUP_REVOKE",
        Some(describe_resource("api_key", target.id, &target.name)),
        Some(format!("revoked read on Vault group {group_name} ({group_id})")),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// The set of Vault group names `api_key_id` currently holds a read grant for — the set
/// `endpoints::validate_group_access` checks a Daughter's `vault_groups` against. Matches by the
/// grant's snapshotted name (see `entities::vault_group_permission`'s module doc comment for why
/// grants aren't re-validated against a live Vault call on every use).
pub async fn granted_group_names(
    db: &sea_orm::DatabaseConnection,
    api_key_id: Uuid,
) -> Result<HashSet<String>, AppError> {
    let grants = VaultGroupPermission::find()
        .filter(vault_group_permission::Column::ApiKeyId.eq(api_key_id))
        .all(db)
        .await?;
    Ok(grants.into_iter().map(|g| g.vault_group_name).collect())
}
