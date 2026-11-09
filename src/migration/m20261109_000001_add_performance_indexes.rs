//! Adds performance indexes for audit log queries and endpoint lookups.
//!
//! Hot paths in `simply_ip_exporter`:
//! - Audit log listings: `ORDER BY timestamp DESC`, optionally filtered by `action` or `api_key_id`.
//! - Endpoints listing: Daughter keys query `WHERE owner_key_id = ? ORDER BY created_at DESC`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    ApiKeyId,
    Action,
    Timestamp,
}

#[derive(DeriveIden)]
enum Endpoints {
    Table,
    OwnerKeyId,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Audit logs: default search newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_timestamp_desc")
                    .table(AuditLogs::Table)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Audit logs: filter by action newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_action_timestamp_desc")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Audit logs: filter by API key newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_api_key_id_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Endpoints: filter by owner key newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_endpoints_owner_created")
                    .table(Endpoints::Table)
                    .col(Endpoints::OwnerKeyId)
                    .col((Endpoints::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_endpoints_owner_created")
                    .table(Endpoints::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_api_key_id_timestamp")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_action_timestamp_desc")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_timestamp_desc")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await
    }
}
