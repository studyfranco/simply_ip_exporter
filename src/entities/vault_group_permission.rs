//! The `vault_group_permissions` table: which local API keys may reference which
//! `simply_ip_vault` groups in their own endpoints' `vault_groups`.
//!
//! Unlike `api_keys`/`endpoints`, the other half of this relationship (the Vault group) does not
//! live in this crate's own database — Vault is a separate service, reached only over HTTP, so
//! `vault_group_id` cannot be a real foreign key the way `example/simply_ip_vault`'s own
//! `api_key_group_permissions.group_id` is to its local `ip_groups` table. `vault_group_name` is a
//! snapshot taken at grant time, kept so a grant stays displayable and enforceable by name even
//! after the group is renamed or deleted in Vault — this crate does not reach out to Vault to
//! re-validate a grant on every use. See `groups::spawn_group_permission_cleanup_worker` for the
//! only place stale grants (referencing a group Vault no longer has) are ever removed, and why
//! that removal is deliberately conservative.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single (local API key, Vault group) read-access grant.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "vault_group_permissions")]
pub struct Model {
    /// Unique identifier for the grant.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The local API key this grant applies to.
    pub api_key_id: Uuid,
    /// The Vault group's own id, exactly as Vault assigned it — not a local foreign key (see the
    /// module doc comment).
    pub vault_group_id: Uuid,
    /// The group's name as observed at grant time (or the cleanup worker's last successful
    /// refresh), used for both display and endpoint `vault_groups` enforcement without a live
    /// Vault call on every use.
    pub vault_group_name: String,
    /// Grant timestamp.
    pub created_at: DateTime,
}

/// Relations from `vault_group_permissions` to the entities it references.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The local API key holding this grant. Cascades: deleting the key deletes its grants.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
