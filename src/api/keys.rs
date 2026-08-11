//! CRUD handlers for `api_keys`. Every route here is Master-only, per `AGENT.MD`'s two-tier RBAC:
//! only the Master key may create, list, update, delete, or rotate local API keys.

use axum::{
    Extension, Json,
    extract::{Path, State},
    response::IntoResponse,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::support::{create_audit_log, describe_resource, generate_random_key, hash_key, validate_bound_ips};
use crate::crypto::generate_signing_secret;
use crate::entities::{api_key, prelude::ApiKey};
use crate::error::AppError;
use crate::middleware::ClientIp;
use crate::state::AppState;

fn require_master(key: &api_key::Model) -> Result<(), AppError> {
    if key.is_master {
        Ok(())
    } else {
        Err(AppError::Forbidden("Only the Master key can manage API keys".to_owned()))
    }
}

/// A key as returned to clients. Never carries `key_hash` or `signing_secret`.
#[derive(Serialize)]
pub struct KeyResponse {
    id: Uuid,
    name: String,
    prefix: String,
    bound_ips: Option<String>,
    is_master: bool,
    can_manage_keys: bool,
    parent_key_id: Option<Uuid>,
    owner_key_id: Option<Uuid>,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

impl From<api_key::Model> for KeyResponse {
    fn from(m: api_key::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            prefix: m.prefix,
            bound_ips: m.bound_ips,
            is_master: m.is_master,
            can_manage_keys: m.can_manage_keys,
            parent_key_id: m.parent_key_id,
            owner_key_id: m.owner_key_id,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// A key response carrying its plaintext secret and signing secret, shown exactly once.
#[derive(Serialize)]
pub struct MintedKeyResponse {
    #[serde(flatten)]
    key: KeyResponse,
    api_key: String,
    signing_secret: String,
}

/// Payload for creating a Daughter key.
#[derive(Deserialize)]
pub struct CreateKeyPayload {
    name: String,
    bound_ips: Option<String>,
    /// Whether the new key may itself manage other keys. `is_master` is deliberately absent from
    /// this type: it is never settable through the API.
    #[serde(default)]
    can_manage_keys: bool,
}

/// `POST /api/keys` — mints a new Daughter key, owned and parented by the caller.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<CreateKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    if payload.name.trim().is_empty() {
        return Err(AppError::InvalidInput("name must not be empty".to_owned()));
    }
    let bound_ips = payload.bound_ips.filter(|s| !s.trim().is_empty());
    if let Some(raw) = &bound_ips {
        validate_bound_ips(raw).map_err(AppError::InvalidInput)?;
    }

    let plaintext_key = generate_random_key();
    let signing_secret = generate_signing_secret();
    let now = Utc::now().naive_utc();
    let id = Uuid::new_v4();

    let model = api_key::ActiveModel {
        id: Set(id),
        name: Set(payload.name),
        prefix: Set(plaintext_key.chars().take(8).collect()),
        key_hash: Set(hash_key(&plaintext_key)),
        signing_secret: Set(Some(state.cipher.seal(&signing_secret).map_err(|e| {
            tracing::error!("Failed to seal signing secret: {e}");
            AppError::Internal
        })?)),
        bound_ips: Set(bound_ips),
        is_master: Set(false),
        can_manage_keys: Set(payload.can_manage_keys),
        parent_key_id: Set(Some(caller.id)),
        owner_key_id: Set(Some(caller.id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let created = model.insert(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "KEY_CREATE",
        Some(describe_resource("api_key", created.id, &created.name)),
        Some(format!("can_manage_keys={}", created.can_manage_keys)),
    )
    .await?;

    Ok(Json(MintedKeyResponse {
        key: created.into(),
        api_key: plaintext_key,
        signing_secret,
    }))
}

/// `GET /api/keys` — lists every local API key.
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;
    let keys = ApiKey::find().all(&state.db).await?;
    Ok(Json(keys.into_iter().map(KeyResponse::from).collect::<Vec<_>>()))
}

/// Payload for updating a key. `is_master` cannot appear here by construction.
#[derive(Deserialize, Default)]
pub struct UpdateKeyPayload {
    name: Option<String>,
    bound_ips: Option<String>,
    can_manage_keys: Option<bool>,
}

/// `PUT /api/keys/{id}` — updates a key's name, `bound_ips`, or `can_manage_keys`.
pub async fn update_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let mut active: api_key::ActiveModel = existing.into();
    let mut changed: Vec<&str> = Vec::new();

    if let Some(name) = payload.name {
        if name.trim().is_empty() {
            return Err(AppError::InvalidInput("name must not be empty".to_owned()));
        }
        active.name = Set(name);
        changed.push("name");
    }
    if let Some(bound_ips) = payload.bound_ips {
        let trimmed = bound_ips.trim();
        if !trimmed.is_empty() {
            validate_bound_ips(trimmed).map_err(AppError::InvalidInput)?;
        }
        active.bound_ips = Set(if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) });
        changed.push("bound_ips");
    }
    if let Some(can_manage_keys) = payload.can_manage_keys {
        active.can_manage_keys = Set(can_manage_keys);
        changed.push("can_manage_keys");
    }
    active.updated_at = Set(Utc::now().naive_utc());

    let updated = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "KEY_UPDATE",
        Some(describe_resource("api_key", updated.id, &updated.name)),
        Some(format!("changed: {}", if changed.is_empty() { "(none)".to_owned() } else { changed.join(", ") })),
    )
    .await?;

    Ok(Json(KeyResponse::from(updated)))
}

/// `DELETE /api/keys/{id}` — removes a key. The Master key cannot be deleted through the API.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if existing.is_master {
        return Err(AppError::Forbidden("The Master key cannot be deleted through the API".to_owned()));
    }

    // Captured before the row is gone, since the audit entry must describe what was deleted.
    let target_resource = describe_resource("api_key", existing.id, &existing.name);

    ApiKey::delete_by_id(id).exec(&state.db).await?;

    create_audit_log(&state.db, &caller, client_ip.0, "KEY_DELETE", Some(target_resource), None).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/keys/{id}/rotate` — mints a fresh secret and signing secret for a key.
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if existing.is_master {
        return Err(AppError::Forbidden(
            "The Master key cannot be rotated through the API; regenerate it in the database"
                .to_owned(),
        ));
    }

    let plaintext_key = generate_random_key();
    let signing_secret = generate_signing_secret();

    let mut active: api_key::ActiveModel = existing.into();
    active.key_hash = Set(hash_key(&plaintext_key));
    active.prefix = Set(plaintext_key.chars().take(8).collect());
    active.signing_secret = Set(Some(state.cipher.seal(&signing_secret).map_err(|e| {
        tracing::error!("Failed to seal signing secret: {e}");
        AppError::Internal
    })?));
    active.updated_at = Set(Utc::now().naive_utc());
    let updated = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "KEY_ROTATE",
        Some(describe_resource("api_key", updated.id, &updated.name)),
        Some("credentials rotated".to_owned()),
    )
    .await?;

    Ok(Json(MintedKeyResponse { key: updated.into(), api_key: plaintext_key, signing_secret }))
}
