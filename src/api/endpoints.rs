//! CRUD handlers for `endpoints`. Any authenticated key may create an endpoint (which it then
//! owns); managing an existing endpoint requires being its owner or the Master key, per
//! `AGENT.MD`'s Master/Daughter RBAC.

use axum::{Extension, Json, extract::State, response::IntoResponse};
use chrono::Utc;
use rand::RngExt;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::support::{create_audit_log, describe_resource};
use crate::bound_ips::validate_bound_ips;
use crate::entities::{api_key, endpoint, prelude::Endpoint};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;

fn generate_token_secret() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    hex::encode(bytes)
}

fn may_manage(caller: &api_key::Model, ep: &endpoint::Model) -> bool {
    caller.is_master || ep.owner_key_id == Some(caller.id)
}

/// An endpoint as returned to a caller authorized to see it in full (owner or Master).
#[derive(Serialize)]
pub struct EndpointResponse {
    id: Uuid,
    owner_key_id: Option<Uuid>,
    name: String,
    description: Option<String>,
    token_secret: String,
    feed_path: String,
    vault_groups: String,
    ttl_seconds: i32,
    bound_ips: Option<String>,
    filter_rfc1918: bool,
    filter_bogons: bool,
    filter_loopback: bool,
    last_synced_at: Option<chrono::NaiveDateTime>,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

impl From<endpoint::Model> for EndpointResponse {
    fn from(m: endpoint::Model) -> Self {
        Self {
            feed_path: format!("/feed/v1/{}/list.txt", m.token_secret),
            id: m.id,
            owner_key_id: m.owner_key_id,
            name: m.name,
            description: m.description,
            token_secret: m.token_secret,
            vault_groups: m.vault_groups,
            ttl_seconds: m.ttl_seconds,
            bound_ips: m.bound_ips,
            filter_rfc1918: m.filter_rfc1918,
            filter_bogons: m.filter_bogons,
            filter_loopback: m.filter_loopback,
            last_synced_at: m.last_synced_at,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// Payload for creating an endpoint. Denies unknown fields — a stray/mistyped field is refused with
/// an error naming it, rather than silently ignored (matches `simply_ip_vault`'s convention).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEndpointPayload {
    name: String,
    description: Option<String>,
    vault_groups: String,
    ttl_seconds: Option<i32>,
    bound_ips: Option<String>,
    #[serde(default)]
    filter_rfc1918: bool,
    #[serde(default)]
    filter_bogons: bool,
    #[serde(default)]
    filter_loopback: bool,
}

fn validate_groups(raw: &str) -> Result<(), AppError> {
    if raw.split(',').map(str::trim).all(str::is_empty) {
        return Err(AppError::InvalidInput("vault_groups must name at least one group".to_owned()));
    }
    Ok(())
}

/// Refuses a non-Master caller's `vault_groups` if it names any group the caller hasn't been
/// granted read access to (`vault_group_permissions`, see `api::groups`). A no-op for Master —
/// "master can see all groups" — so both call sites below can call this unconditionally rather
/// than branching on `caller.is_master` themselves.
async fn validate_group_access(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    vault_groups: &str,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }
    let granted = crate::api::groups::granted_group_names(db, caller.id).await?;
    let ungranted: Vec<&str> = vault_groups
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .filter(|g| !granted.contains(*g))
        .collect();
    if !ungranted.is_empty() {
        return Err(AppError::Forbidden(format!(
            "You do not have read access to Vault group(s): {} — ask the Master to grant it via \
             POST /api/keys/{{id}}/groups",
            ungranted.join(", ")
        )));
    }
    Ok(())
}

/// `POST /api/endpoints` — creates a new public feed endpoint, owned by the caller.
pub async fn create_endpoint(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateEndpointPayload>,
) -> Result<impl IntoResponse, AppError> {
    if payload.name.trim().is_empty() {
        return Err(AppError::InvalidInput("name must not be empty".to_owned()));
    }
    validate_groups(&payload.vault_groups)?;
    validate_group_access(&state.db, &caller, &payload.vault_groups).await?;
    let bound_ips = payload.bound_ips.filter(|s| !s.trim().is_empty());
    if let Some(raw) = &bound_ips {
        validate_bound_ips(raw).map_err(AppError::InvalidInput)?;
    }
    let ttl_seconds = payload.ttl_seconds.unwrap_or(3600);
    if ttl_seconds <= 0 {
        return Err(AppError::InvalidInput("ttl_seconds must be positive".to_owned()));
    }

    let now = Utc::now().naive_utc();
    let model = endpoint::ActiveModel {
        id: Set(Uuid::new_v4()),
        owner_key_id: Set(Some(caller.id)),
        name: Set(payload.name),
        description: Set(payload.description),
        token_secret: Set(generate_token_secret()),
        vault_groups: Set(payload.vault_groups),
        ttl_seconds: Set(ttl_seconds),
        bound_ips: Set(bound_ips),
        filter_rfc1918: Set(payload.filter_rfc1918),
        filter_bogons: Set(payload.filter_bogons),
        filter_loopback: Set(payload.filter_loopback),
        last_synced_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let created = model.insert(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "ENDPOINT_CREATE",
        Some(describe_resource("endpoint", created.id, &created.name)),
        Some(format!("vault_groups={}", created.vault_groups)),
    )
    .await?;

    Ok(Json(EndpointResponse::from(created)))
}

/// `GET /api/endpoints` — lists endpoints. Master sees every endpoint; a Daughter key sees only
/// the ones it owns.
pub async fn list_endpoints(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let rows = if caller.is_master {
        Endpoint::find().all(&state.db).await?
    } else {
        Endpoint::find()
            .filter(endpoint::Column::OwnerKeyId.eq(caller.id))
            .all(&state.db)
            .await?
    };
    Ok(Json(rows.into_iter().map(EndpointResponse::from).collect::<Vec<_>>()))
}

/// Payload for updating an endpoint. Ownership (`owner_key_id`) is reassignable by Master only,
/// via a separate route, and never through this general update — enforced structurally (the field
/// is absent here) and denies any other unknown field too, rather than silently ignoring it.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpointPayload {
    name: Option<String>,
    description: Option<String>,
    vault_groups: Option<String>,
    ttl_seconds: Option<i32>,
    bound_ips: Option<String>,
    filter_rfc1918: Option<bool>,
    filter_bogons: Option<bool>,
    filter_loopback: Option<bool>,
}

/// `PUT /api/endpoints/{id}` — updates an endpoint's configuration.
pub async fn update_endpoint(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
    StrictJson(payload): StrictJson<UpdateEndpointPayload>,
) -> Result<impl IntoResponse, AppError> {
    let existing = Endpoint::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !may_manage(&caller, &existing) {
        return Err(AppError::Forbidden(
            "You do not have management rights over this endpoint".to_owned(),
        ));
    }

    let mut active: endpoint::ActiveModel = existing.into();
    let mut changed: Vec<&str> = Vec::new();

    if let Some(name) = payload.name {
        if name.trim().is_empty() {
            return Err(AppError::InvalidInput("name must not be empty".to_owned()));
        }
        active.name = Set(name);
        changed.push("name");
    }
    if let Some(description) = payload.description {
        active.description = Set(if description.trim().is_empty() { None } else { Some(description) });
        changed.push("description");
    }
    if let Some(vault_groups) = payload.vault_groups {
        validate_groups(&vault_groups)?;
        validate_group_access(&state.db, &caller, &vault_groups).await?;
        active.vault_groups = Set(vault_groups);
        changed.push("vault_groups");
    }
    if let Some(ttl_seconds) = payload.ttl_seconds {
        if ttl_seconds <= 0 {
            return Err(AppError::InvalidInput("ttl_seconds must be positive".to_owned()));
        }
        active.ttl_seconds = Set(ttl_seconds);
        changed.push("ttl_seconds");
    }
    if let Some(bound_ips) = payload.bound_ips {
        let trimmed = bound_ips.trim();
        if !trimmed.is_empty() {
            validate_bound_ips(trimmed).map_err(AppError::InvalidInput)?;
        }
        active.bound_ips = Set(if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) });
        changed.push("bound_ips");
    }
    if let Some(v) = payload.filter_rfc1918 {
        active.filter_rfc1918 = Set(v);
        changed.push("filter_rfc1918");
    }
    if let Some(v) = payload.filter_bogons {
        active.filter_bogons = Set(v);
        changed.push("filter_bogons");
    }
    if let Some(v) = payload.filter_loopback {
        active.filter_loopback = Set(v);
        changed.push("filter_loopback");
    }
    active.updated_at = Set(Utc::now().naive_utc());

    let updated = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "ENDPOINT_UPDATE",
        Some(describe_resource("endpoint", updated.id, &updated.name)),
        Some(format!("changed: {}", if changed.is_empty() { "(none)".to_owned() } else { changed.join(", ") })),
    )
    .await?;

    Ok(Json(EndpointResponse::from(updated)))
}

/// `DELETE /api/endpoints/{id}` — removes an endpoint and evicts its in-memory cache.
pub async fn delete_endpoint(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
) -> Result<impl IntoResponse, AppError> {
    let existing = Endpoint::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !may_manage(&caller, &existing) {
        return Err(AppError::Forbidden(
            "You do not have management rights over this endpoint".to_owned(),
        ));
    }

    // Captured before the row is gone, since the audit entry must describe what was deleted.
    let target_resource = describe_resource("endpoint", existing.id, &existing.name);

    // `rows_affected` — not just "did the query error?" — is what closes the race between two
    // concurrent deletes of the same endpoint: both requests can pass the `find_by_id` check above
    // before either's `DELETE` runs (the check and the delete are two separate round-trips, not one
    // atomic statement), so without this only the *first* to reach here should report success. A
    // second `DELETE` for a row already gone is a `404`, not a second `204` — and, just as
    // importantly, must not write a second `ENDPOINT_DELETE` audit entry claiming a deletion that
    // this request did not actually perform.
    let result = Endpoint::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    state.ip_cache.evict(id).await;

    create_audit_log(&state.db, &caller, client_ip.0, "ENDPOINT_DELETE", Some(target_resource), None)
        .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `PUT /api/endpoints/{id}/owner` — reassigns ownership. Master only.
pub async fn reassign_endpoint_owner(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath,
    StrictJson(payload): StrictJson<ReassignOwnerPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden("Only the Master key can reassign endpoint ownership".to_owned()));
    }
    let existing = Endpoint::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    if let Some(new_owner) = payload.owner_key_id {
        crate::entities::prelude::ApiKey::find_by_id(new_owner)
            .one(&state.db)
            .await?
            .ok_or(AppError::InvalidInput("owner_key_id does not name an existing key".to_owned()))?;
    }

    let new_owner_id = payload.owner_key_id;
    let mut active: endpoint::ActiveModel = existing.into();
    active.owner_key_id = Set(new_owner_id);
    active.updated_at = Set(Utc::now().naive_utc());
    let updated = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "ENDPOINT_OWNER_REASSIGN",
        Some(describe_resource("endpoint", updated.id, &updated.name)),
        Some(format!("owner_key_id -> {}", new_owner_id.map_or_else(|| "(none)".to_owned(), |id| id.to_string()))),
    )
    .await?;

    Ok(Json(EndpointResponse::from(updated)))
}

/// Payload for [`reassign_endpoint_owner`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReassignOwnerPayload {
    owner_key_id: Option<Uuid>,
}
