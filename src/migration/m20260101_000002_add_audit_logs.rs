//! Adds `audit_logs`: the audit trail for mutating `/api/keys/*` and `/api/endpoints/*` actions.
//!
//! `api_key_id` is `ON DELETE SET NULL` rather than `CASCADE` — deleting the acting key must never
//! delete the history of what it did. `api_key_name`/`api_key_prefix` are `NOT NULL` denormalized
//! snapshots for the same reason: they are the only attribution that survives the key being
//! deleted, so unlike `api_key_id` they are never nulled out by the cascade.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    Id,
    ApiKeyId,
    ApiKeyName,
    ApiKeyPrefix,
    ClientIp,
    Action,
    TargetResource,
    Details,
    Timestamp,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuditLogs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuditLogs::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(AuditLogs::ApiKeyId).uuid().null())
                    .col(ColumnDef::new(AuditLogs::ApiKeyName).string().not_null())
                    .col(ColumnDef::new(AuditLogs::ApiKeyPrefix).string().not_null())
                    .col(ColumnDef::new(AuditLogs::ClientIp).string().not_null())
                    .col(ColumnDef::new(AuditLogs::Action).string().not_null())
                    .col(ColumnDef::new(AuditLogs::TargetResource).string().null())
                    .col(ColumnDef::new(AuditLogs::Details).text().null())
                    .col(ColumnDef::new(AuditLogs::Timestamp).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_audit_logs_api_key_id")
                            .from(AuditLogs::Table, AuditLogs::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_action")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Timestamp)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_api_key_id")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(AuditLogs::Table).to_owned()).await
    }
}
