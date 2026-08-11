//! The `api_keys` table: local admin authentication tokens, Master/Daughter RBAC flags, and CIDR
//! network bindings. See `SCHEMA.MD` §1 and `RBAC_MODEL.md`.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single local admin API key.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Unique identifier for the API key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable label (e.g. `"pfSense DMZ Exporter Admin"`).
    pub name: String,
    /// Public identifier prefix (e.g. `sie_exp1`) for display/logs.
    pub prefix: String,
    /// SHA-256 hash of the plaintext secret key. The plaintext is never stored.
    #[sea_orm(unique)]
    pub key_hash: String,
    /// HMAC-SHA256 signing secret, encrypted at rest with `EXPORTER_ENCRYPTION_KEY` when set (see
    /// [`crate::crypto::SecretCipher`]). Never returned by any read endpoint.
    #[sea_orm(column_type = "Text", nullable)]
    pub signing_secret: Option<String>,
    /// Comma-separated CIDR ranges permitted to use this key. Empty/`None` means unrestricted.
    #[sea_orm(column_type = "Text", nullable)]
    pub bound_ips: Option<String>,
    /// Bypasses all local RBAC checks. Bootstrap-only; never settable through request payloads.
    pub is_master: bool,
    /// Global right to manage **other** local API keys. Master-granted only.
    pub can_manage_keys: bool,
    /// The key that created this one. Lineage only — never authority (`RBAC_MODEL.md` R3).
    pub parent_key_id: Option<Uuid>,
    /// The key answerable for this key record.
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp (UTC).
    pub created_at: DateTime,
    /// Last modification timestamp (UTC).
    pub updated_at: DateTime,
}

/// Relations from `api_keys` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Endpoints owned by this key.
    #[sea_orm(has_many = "super::endpoint::Entity")]
    Endpoint,
}

impl Related<super::endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Endpoint.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
