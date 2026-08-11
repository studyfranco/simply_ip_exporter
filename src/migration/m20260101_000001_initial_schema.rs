//! Initial schema: `api_keys` and `endpoints`, per `SCHEMA.MD`.
//!
//! `api_keys.master_marker` is added as a database-engine-derived `GENERATED ALWAYS AS (...)`
//! column under a unique index, per `RBAC_MODEL.md` §5 and `SCHEMA.MD` §1 — never an
//! application-maintained column, and never present on [`crate::entities::api_key::Model`], since
//! every supported engine rejects a write that targets a generated column.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

/// The derived master-uniqueness marker column.
const MARKER_COLUMN: &str = "master_marker";
/// The unique index enforcing at most one Master key.
const MARKER_INDEX: &str = "idx_api_keys_master_marker";

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
    Name,
    Prefix,
    KeyHash,
    SigningSecret,
    BoundIps,
    IsMaster,
    CanManageKeys,
    ParentKeyId,
    OwnerKeyId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Endpoints {
    Table,
    Id,
    OwnerKeyId,
    Name,
    Description,
    TokenSecret,
    VaultGroups,
    TtlSeconds,
    BoundIps,
    FilterRfc1918,
    FilterBogons,
    FilterLoopback,
    LastSyncedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

impl Migration {
    /// The `ALTER TABLE` that adds the derived marker, in this backend's dialect. SQLite (the only
    /// backend this crate ships) accepts only `VIRTUAL` for a generated column added via `ALTER
    /// TABLE`; `STORED`/`VIRTUAL` are kept dialect-aware anyway so the statement stays correct if
    /// this project ever widens beyond SQLite, matching the reference implementations' convention.
    fn add_marker_column(backend: DatabaseBackend) -> String {
        let expression = "CASE WHEN is_master THEN 1 ELSE NULL END";
        let storage = match backend {
            DatabaseBackend::Postgres => "STORED",
            _ => "VIRTUAL",
        };
        format!(
            "ALTER TABLE api_keys ADD COLUMN {MARKER_COLUMN} INTEGER \
             GENERATED ALWAYS AS ({expression}) {storage}"
        )
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKeys::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(ApiKeys::Name).string().not_null())
                    .col(ColumnDef::new(ApiKeys::Prefix).string().not_null())
                    .col(ColumnDef::new(ApiKeys::KeyHash).string().not_null().unique_key())
                    .col(ColumnDef::new(ApiKeys::SigningSecret).text().null())
                    .col(ColumnDef::new(ApiKeys::BoundIps).text().null())
                    .col(ColumnDef::new(ApiKeys::IsMaster).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CanManageKeys).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::ParentKeyId).uuid().null())
                    .col(ColumnDef::new(ApiKeys::OwnerKeyId).uuid().null())
                    .col(ColumnDef::new(ApiKeys::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(ApiKeys::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_prefix")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Prefix)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_parent_key_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::ParentKeyId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_owner_key_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let backend = db.get_database_backend();
        db.execute_raw(Statement::from_string(backend, Migration::add_marker_column(backend)))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .col(Alias::new(MARKER_COLUMN))
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Endpoints::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Endpoints::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Endpoints::OwnerKeyId).uuid().null())
                    .col(ColumnDef::new(Endpoints::Name).string().not_null())
                    .col(ColumnDef::new(Endpoints::Description).text().null())
                    .col(ColumnDef::new(Endpoints::TokenSecret).string().not_null().unique_key())
                    .col(ColumnDef::new(Endpoints::VaultGroups).text().not_null())
                    .col(ColumnDef::new(Endpoints::TtlSeconds).integer().not_null().default(3600))
                    .col(ColumnDef::new(Endpoints::BoundIps).text().null())
                    .col(
                        ColumnDef::new(Endpoints::FilterRfc1918).boolean().not_null().default(false),
                    )
                    .col(ColumnDef::new(Endpoints::FilterBogons).boolean().not_null().default(false))
                    .col(
                        ColumnDef::new(Endpoints::FilterLoopback).boolean().not_null().default(false),
                    )
                    .col(ColumnDef::new(Endpoints::LastSyncedAt).date_time().null())
                    .col(ColumnDef::new(Endpoints::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Endpoints::UpdatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoints_owner_key_id")
                            .from(Endpoints::Table, Endpoints::OwnerKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_endpoints_owner_key_id")
                    .table(Endpoints::Table)
                    .col(Endpoints::OwnerKeyId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_endpoints_token_secret")
                    .table(Endpoints::Table)
                    .col(Endpoints::TokenSecret)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Endpoints::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(ApiKeys::Table).to_owned()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_generated_column_uses_virtual_storage() {
        assert!(Migration::add_marker_column(DatabaseBackend::Sqlite).ends_with("VIRTUAL"));
    }

    #[test]
    fn the_marker_is_generated_from_is_master() {
        let ddl = Migration::add_marker_column(DatabaseBackend::Sqlite);
        assert!(ddl.contains("GENERATED ALWAYS AS") && ddl.contains("is_master"));
        assert!(ddl.contains("ELSE NULL"));
    }
}
