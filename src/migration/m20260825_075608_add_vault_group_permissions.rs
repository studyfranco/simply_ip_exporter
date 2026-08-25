//! Adds `vault_group_permissions`: which local API keys may reference which `simply_ip_vault`
//! groups in their own endpoints' `vault_groups`.
//!
//! `vault_group_id` is deliberately not a foreign key to anything in this database — the Vault
//! group it names lives in a separate service's database, reachable only over HTTP. A grant
//! survives that group being renamed or deleted in Vault (see `entities::vault_group_permission`'s
//! module doc comment and `groups::spawn_group_permission_cleanup_worker`, the only place a stale
//! grant is ever removed, and only conservatively).

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum VaultGroupPermissions {
    Table,
    Id,
    ApiKeyId,
    VaultGroupId,
    VaultGroupName,
    CreatedAt,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VaultGroupPermissions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(VaultGroupPermissions::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(VaultGroupPermissions::ApiKeyId).uuid().not_null())
                    .col(ColumnDef::new(VaultGroupPermissions::VaultGroupId).uuid().not_null())
                    .col(ColumnDef::new(VaultGroupPermissions::VaultGroupName).string().not_null())
                    .col(ColumnDef::new(VaultGroupPermissions::CreatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_vault_group_permissions_api_key_id")
                            .from(VaultGroupPermissions::Table, VaultGroupPermissions::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // One grant per (key, group) — a repeat grant is a no-op, not a duplicate row.
        manager
            .create_index(
                Index::create()
                    .name("idx_vault_group_permissions_key_group")
                    .table(VaultGroupPermissions::Table)
                    .col(VaultGroupPermissions::ApiKeyId)
                    .col(VaultGroupPermissions::VaultGroupId)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(VaultGroupPermissions::Table).to_owned()).await
    }
}
