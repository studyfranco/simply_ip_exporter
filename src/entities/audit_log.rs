//! The `audit_logs` table: the audit trail for mutating operations against `api_keys` and
//! `endpoints`.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single audit trail entry for a mutating administrative action.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// Unique audit log entry ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The API key that performed the action, if any. `None` when the acting key was later
    /// deleted (`ON DELETE SET NULL`) — the row survives, only the live link is severed.
    pub api_key_id: Option<Uuid>,
    /// The acting key's name, denormalized at write time so the audit trail stays legible even
    /// after that key is deleted. A point-in-time snapshot, not a live join.
    pub api_key_name: String,
    /// The acting key's prefix, denormalized for the same reason as `api_key_name`.
    pub api_key_prefix: String,
    /// The caller's resolved client IP (see `middleware::ClientIp`).
    pub client_ip: String,
    /// Operation type, e.g. `KEY_CREATE`, `KEY_UPDATE`, `KEY_DELETE`, `KEY_ROTATE`,
    /// `ENDPOINT_CREATE`, `ENDPOINT_UPDATE`, `ENDPOINT_DELETE`, `ENDPOINT_OWNER_REASSIGN`.
    pub action: String,
    /// The resource the action targeted, e.g. `api_key:<id> (<name>)` or `endpoint:<id> (<name>)`.
    pub target_resource: Option<String>,
    /// Additional context: which fields changed, or other short human-readable detail.
    pub details: Option<String>,
    /// Log entry creation timestamp (UTC).
    pub timestamp: DateTime,
}

/// Relations from `audit_logs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The API key that performed the audited action.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
