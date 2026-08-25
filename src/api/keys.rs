//! CRUD handlers for `api_keys`. Every route here is Master-only, per `AGENT.MD`'s two-tier RBAC:
//! only the Master key may create, list, update, delete, or rotate local API keys.

use axum::{Extension, Json, extract::State, response::IntoResponse};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::api::guards::{guard_master_delete_or_rotate, guard_master_update, require_master};
use crate::api::support::{create_audit_log, describe_resource, generate_random_key, hash_key, validate_bound_ips};
use crate::crypto::generate_signing_secret;
use crate::entities::{api_key, endpoint, prelude::ApiKey, prelude::Endpoint};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::AppState;

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
///
/// `is_master` is deliberately absent from this type (never settable through the API) *and* the
/// struct denies unknown fields — the field's absence alone only means a stray `"is_master": true`
/// is silently ignored; `deny_unknown_fields` is what makes it refused, with an error naming the
/// field, instead. See `simply_ip_vault`'s `src/extract.rs` module doc comment for the fuller
/// rationale this mirrors.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    StrictJson(payload): StrictJson<CreateKeyPayload>,
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

/// Payload for updating a key. `is_master` cannot appear here by construction, and an unknown
/// field is refused rather than silently dropped (see `CreateKeyPayload`'s doc comment).
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
    StrictPath(id): StrictPath,
    StrictJson(payload): StrictJson<UpdateKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_master_update(&existing, payload.name.is_some(), payload.can_manage_keys.is_some())?;

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

/// Query parameters for `DELETE /api/keys/{id}`.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeleteKeyQuery {
    /// If the target key owns any endpoints, they are reassigned to this key — in the same
    /// transaction as the delete — instead of being refused. Omit when the target owns nothing.
    #[serde(default)]
    pub reassign_to: Option<Uuid>,
}

/// `DELETE /api/keys/{id}` — removes a key. The Master key cannot be deleted through the API.
///
/// If the key owns any endpoints and no `?reassign_to=<key id>` is given, refuses with `409
/// Conflict` and a structured inventory of what it owns, so the caller knows what's blocking the
/// delete without a second round-trip to discover it. With `reassign_to`, the reassignment and the
/// delete happen inside one database transaction, isolated from concurrent readers/writers and
/// expressed entirely through SeaORM's query builder (`Entity::update_many().col_expr(...)`) —
/// portable across SQLite, PostgreSQL, and MariaDB with no vendor-specific SQL.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
    StrictQuery(query): StrictQuery<DeleteKeyQuery>,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_master_delete_or_rotate(&existing, "deleted")?;

    if query.reassign_to == Some(id) {
        return Err(AppError::InvalidInput("reassign_to cannot name the key being deleted".to_owned()));
    }

    // Captured before the row is gone, since the audit entry must describe what was deleted.
    let target_resource = describe_resource("api_key", existing.id, &existing.name);
    let now = Utc::now().naive_utc();

    // Explicit `begin()`/`commit()` (rather than the `db.transaction(|txn| ...)` closure helper)
    // for control over the early-return branches below: a `409` on the no-`reassign_to` path and a
    // `404` on the concurrent-delete race both need to leave the transaction uncommitted, which a
    // plain `return Err(...)` here does automatically — `DatabaseTransaction` rolls back on drop
    // when it was never committed, the same guarantee sqlx's own `Transaction` gives.
    let txn = state.db.begin().await?;

    let owned_endpoints = Endpoint::find().filter(endpoint::Column::OwnerKeyId.eq(id)).all(&txn).await?;

    let reassign_target = match query.reassign_to {
        Some(target_id) => Some(
            ApiKey::find_by_id(target_id)
                .one(&txn)
                .await?
                .ok_or_else(|| AppError::InvalidInput("reassign_to does not name an existing key".to_owned()))?,
        ),
        None => {
            if !owned_endpoints.is_empty() {
                let inventory: Vec<_> =
                    owned_endpoints.iter().map(|e| json!({ "id": e.id, "name": e.name })).collect();
                return Err(AppError::ConflictWithDetails {
                    message: format!(
                        "this key still owns {} endpoint(s); reassign or delete them first, or retry with \
                         ?reassign_to=<key id>",
                        owned_endpoints.len()
                    ),
                    details: json!({ "owned_endpoints": inventory }),
                });
            }
            None
        }
    };

    if let Some(target) = &reassign_target {
        Endpoint::update_many()
            .filter(endpoint::Column::OwnerKeyId.eq(id))
            .col_expr(endpoint::Column::OwnerKeyId, sea_orm::sea_query::Expr::value(target.id))
            .col_expr(endpoint::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
            .exec(&txn)
            .await?;
    }

    // See the identical race in `api::endpoints::delete_endpoint` for why `rows_affected` (not
    // just "did the query error?") is what a second, concurrent delete of the same key must be
    // judged on: a `404`, and no second `KEY_DELETE` audit entry for a deletion this request did
    // not actually perform. Reached after the reassignment above, so a losing concurrent request
    // rolls back its reassignment too, rather than leaving endpoints reassigned out from under a
    // key delete that itself never took effect.
    let result = ApiKey::delete_by_id(id).exec(&txn).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    let details = reassign_target.as_ref().map(|target| {
        format!(
            "reassigned {} endpoint(s) to {} ({}); key deleted",
            owned_endpoints.len(),
            target.name,
            target.id
        )
    });
    create_audit_log(&txn, &caller, client_ip.0, "KEY_DELETE", Some(target_resource), details).await?;

    txn.commit().await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/keys/{id}/rotate` — mints a fresh secret and signing secret for a key.
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_master_delete_or_rotate(&existing, "rotated")?;

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

/// Response after rotating only an API key's HMAC signing secret. Deliberately narrower than
/// [`MintedKeyResponse`]: no `api_key`, since this operation never changes it.
#[derive(Serialize)]
pub struct RotateSigningSecretResponse {
    /// Key ID — unchanged by this operation.
    id: Uuid,
    /// Key name — unchanged by this operation, echoed back so the caller can confirm which key it
    /// just re-keyed without a second lookup.
    name: String,
    /// The new signing secret, in plaintext. Returned only here: the stored copy is encrypted at
    /// rest when `EXPORTER_ENCRYPTION_KEY` is set, and no read endpoint ever echoes it.
    signing_secret: String,
}

/// `POST /api/keys/{id}/rotate-secret` — replaces a key's HMAC signing secret in place, leaving
/// its `X-API-Key`, name, `bound_ips`, and `can_manage_keys` untouched.
///
/// Distinct from [`rotate_api_key`] (`POST /api/keys/{id}/rotate`), which replaces *both*
/// credential halves and therefore invalidates the API key too. This narrower operation exists
/// because the two secrets have different blast radii: rotating `X-API-Key` forces every client to
/// be reconfigured with a new identity, whereas rotating only the signing secret re-keys the HMAC
/// while the key's id, name, `bound_ips`, and `can_manage_keys` stay exactly as they were — the
/// right tool for routine credential hygiene. Ported from `simply_ip_vault`'s identical
/// `rotate_signing_secret` handler and its own `RotateSigningSecretResponse`.
///
/// The previous signing secret stops working the instant this returns — the column is
/// overwritten, not versioned — so callers must be updated in lockstep.
pub async fn rotate_signing_secret(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
) -> Result<impl IntoResponse, AppError> {
    require_master(&caller)?;

    let existing = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_master_delete_or_rotate(&existing, "rotated")?;

    let signing_secret = generate_signing_secret();
    let name = existing.name.clone();

    // Only `signing_secret` (and the bookkeeping `updated_at`) is touched: `key_hash`, `prefix`,
    // `name`, `bound_ips`, and `can_manage_keys` are left untouched by construction.
    let mut active: api_key::ActiveModel = existing.into();
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
        "KEY_SECRET_ROTATE",
        Some(describe_resource("api_key", updated.id, &updated.name)),
        Some("signing secret rotated".to_owned()),
    )
    .await?;

    Ok(Json(RotateSigningSecretResponse { id: updated.id, name, signing_secret }))
}
