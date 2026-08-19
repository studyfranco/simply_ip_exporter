//! `GET /api/audit-logs` — the audit trail read surface. Master-only: audit entries span every
//! key and endpoint in the system, so a scoped Daughter key seeing them would be an RBAC leak
//! regardless of what it owns.

use axum::{Extension, Json, extract::State, response::IntoResponse};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;

use crate::entities::{api_key, audit_log, prelude::AuditLog};
use crate::error::AppError;
use crate::extract::StrictQuery;
use crate::state::AppState;

/// Query parameters for `GET /api/audit-logs`. Denies unknown fields — a stray/mistyped parameter
/// is refused with a `400` naming it, rather than silently ignored (matches every mutating JSON
/// payload's convention; see `api::keys::CreateKeyPayload`'s doc comment for the fuller rationale).
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    /// Filter by exact action type (e.g. `KEY_CREATE`).
    pub action: Option<String>,
    /// Pagination limit. Defaults to 50.
    pub limit: Option<u64>,
    /// Pagination offset. Defaults to 0.
    pub offset: Option<u64>,
}

/// `GET /api/audit-logs` — lists audit trail entries, most recent first.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<AuditLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden("Only the Master key can view audit logs".to_owned()));
    }

    let mut q = AuditLog::find().order_by_desc(audit_log::Column::Timestamp);
    if let Some(action) = &query.action
        && !action.is_empty()
    {
        q = q.filter(audit_log::Column::Action.eq(action));
    }

    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);
    let logs = q.limit(limit).offset(offset).all(&state.db).await?;

    Ok(Json(logs))
}
