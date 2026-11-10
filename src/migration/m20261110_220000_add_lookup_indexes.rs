//! Adds lookup indexes for vault group permissions, API key master lookups, and endpoint creation dates.
//!
//! Hot paths optimized:
//! - Vault group permissions: lookups by `vault_group_id` (`group_id`) to avoid sequential scans.
//! - API keys: fast lookup of Master key by `is_master` during startup / authentication.
//! - Endpoints & API keys: fast newest-first ordering by `created_at DESC`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum VaultGroupPermissions {
    Table,
    VaultGroupId,
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    IsMaster,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Endpoints {
    Table,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Vault group permissions: lookups by group ID
        manager
            .create_index(
                Index::create()
                    .name("idx_vault_group_permissions_vault_group_id")
                    .table(VaultGroupPermissions::Table)
                    .col(VaultGroupPermissions::VaultGroupId)
                    .to_owned(),
            )
            .await?;

        // API keys: filter by master status
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_is_master")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::IsMaster)
                    .to_owned(),
            )
            .await?;

        // Endpoints: newest-first ordering across all endpoints
        manager
            .create_index(
                Index::create()
                    .name("idx_endpoints_created_at_desc")
                    .table(Endpoints::Table)
                    .col((Endpoints::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // API keys: newest-first ordering
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_created_at_desc")
                    .table(ApiKeys::Table)
                    .col((ApiKeys::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_keys_created_at_desc")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_endpoints_created_at_desc")
                    .table(Endpoints::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_keys_is_master")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_vault_group_permissions_vault_group_id")
                    .table(VaultGroupPermissions::Table)
                    .to_owned(),
            )
            .await
    }
}
