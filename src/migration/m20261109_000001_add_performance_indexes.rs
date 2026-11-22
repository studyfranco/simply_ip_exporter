//! Adds performance indexes for audit log queries and endpoint lookups.
//!
//! Hot paths in `simply_ip_exporter`:
//! - Audit log listings: `ORDER BY timestamp DESC`, optionally filtered by `action` or `api_key_id`.
//! - Endpoints listing: Daughter keys query `WHERE owner_key_id = ? ORDER BY created_at DESC`.

use sea_orm::{
    ConnectionTrait, DbErr, DeriveIden,
    sea_query::{Index, IndexOrder},
};

use super::runner::{Migration as MigrationStep, SchemaManager};

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
impl<C: ConnectionTrait> MigrationStep<C> for Migration {
    async fn up(&self, manager: &SchemaManager<'_, C>) -> Result<(), DbErr> {
        // Audit logs: default search newest-first
        manager
            .create_index(
                "audit_logs",
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
                "audit_logs",
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
                "audit_logs",
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
                "endpoints",
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
}
