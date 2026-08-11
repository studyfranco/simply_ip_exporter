//! The `endpoints` table: public feed routes exposed at `/feed/v1/<token_secret>/list.txt`. See
//! `SCHEMA.MD` §2.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single public feed endpoint configuration.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "endpoints")]
pub struct Model {
    /// Unique identifier for the endpoint route.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The key holding lifecycle authority over this endpoint route.
    pub owner_key_id: Option<Uuid>,
    /// Human-readable name (e.g. `pfBlockerNG_Blacklist_DMZ`).
    pub name: String,
    /// Detailed summary of the endpoint purpose.
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    /// Unique random secret token used in the public URL path.
    #[sea_orm(unique)]
    pub token_secret: String,
    /// Comma-separated list of target group names/UUIDs fetched from `simply_ip_vault`.
    #[sea_orm(column_type = "Text")]
    pub vault_groups: String,
    /// In-memory cache retention duration and refresh interval, in seconds.
    pub ttl_seconds: i32,
    /// Comma-separated allowed CIDR networks for client queries against this public feed.
    #[sea_orm(column_type = "Text", nullable)]
    pub bound_ips: Option<String>,
    /// Strip private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) from output.
    pub filter_rfc1918: bool,
    /// Strip invalid, unallocated, or reserved (bogon) IP ranges.
    pub filter_bogons: bool,
    /// Strip loopback blocks (`127.0.0.0/8`, `::1`).
    pub filter_loopback: bool,
    /// Timestamp of the last successful synchronization with `simply_ip_vault`.
    pub last_synced_at: Option<DateTime>,
    /// Endpoint creation timestamp (UTC).
    pub created_at: DateTime,
    /// Last modification timestamp (UTC).
    pub updated_at: DateTime,
}

/// Relations from `endpoints` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The key owning this endpoint.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::OwnerKeyId",
        to = "super::api_key::Column::Id",
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
