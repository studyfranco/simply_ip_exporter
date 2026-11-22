//! Forward migrations and schema inspection using `SeaORM` and `sea-schema`.

use std::collections::HashSet;

use sea_orm::sea_query::{IndexCreateStatement, SelectStatement};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, EntityTrait, Schema, Set,
    SqliteTransactionMode, StatementBuilder, TransactionOptions, TransactionTrait,
};
use sea_schema::probe::{Has, SchemaProbe};
use time::OffsetDateTime;

use super::migrations;

mod history {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "seaql_migrations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub version: String,
        pub applied_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) struct SchemaManager<'a, C>(&'a C);

impl<'a, C: ConnectionTrait> SchemaManager<'a, C> {
    pub(super) fn new(db: &'a C) -> Self {
        Self(db)
    }

    pub(super) fn get_database_backend(&self) -> DbBackend {
        self.0.get_database_backend()
    }

    pub(super) async fn execute(&self, statement: impl StatementBuilder) -> Result<(), DbErr> {
        self.0.execute(&statement).await.map(|_| ())
    }

    pub(super) async fn create_index(
        &self,
        table: &str,
        statement: IndexCreateStatement,
    ) -> Result<(), DbErr> {
        let name = statement
            .get_index_spec()
            .get_name()
            .ok_or_else(|| DbErr::Custom("Migration index must have a name".to_owned()))?;
        if !self.has_index(table, name).await? {
            self.execute(statement).await?;
        }
        Ok(())
    }

    async fn probe(
        &self,
        check: impl FnOnce(DbBackend) -> Result<SelectStatement, DbErr>,
        column: Has,
    ) -> Result<bool, DbErr> {
        let statement = check(self.get_database_backend())?;
        self.0
            .query_one(&statement)
            .await?
            .ok_or_else(|| DbErr::Custom("Schema probe returned no result".to_owned()))?
            .try_get("", sea_orm::Iden::unquoted(&column))
    }

    pub(super) async fn has_table(&self, table: &str) -> Result<bool, DbErr> {
        self.probe(
            |backend| match backend {
                DbBackend::Sqlite => Ok(sea_schema::sqlite::Sqlite.has_table(table)),
                DbBackend::Postgres => Ok(sea_schema::postgres::Postgres.has_table(table)),
                DbBackend::MySql => Ok(sea_schema::mysql::MySql.has_table(table)),
                other => Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "has_table",
                }),
            },
            Has::Table,
        )
        .await
    }

    pub(super) async fn has_column(&self, table: &str, column: &str) -> Result<bool, DbErr> {
        self.probe(
            |backend| match backend {
                DbBackend::Sqlite => Ok(sea_schema::sqlite::Sqlite.has_column(table, column)),
                DbBackend::Postgres => Ok(sea_schema::postgres::Postgres.has_column(table, column)),
                DbBackend::MySql => Ok(sea_schema::mysql::MySql.has_column(table, column)),
                other => Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "has_column",
                }),
            },
            Has::Column,
        )
        .await
    }

    pub(super) async fn has_index(&self, table: &str, index: &str) -> Result<bool, DbErr> {
        self.probe(
            |backend| match backend {
                DbBackend::Sqlite => Ok(sea_schema::sqlite::Sqlite.has_index(table, index)),
                DbBackend::Postgres => Ok(sea_schema::postgres::Postgres.has_index(table, index)),
                DbBackend::MySql => Ok(sea_schema::mysql::MySql.has_index(table, index)),
                other => Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "has_index",
                }),
            },
            Has::Index,
        )
        .await
    }
}

#[async_trait::async_trait]
pub(super) trait Migration<C: ConnectionTrait>: Sync {
    async fn up(&self, manager: &SchemaManager<'_, C>) -> Result<(), DbErr>;
}

async fn apply<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    let manager = SchemaManager::new(db);
    if !manager.has_table("seaql_migrations").await? {
        let mut table =
            Schema::new(db.get_database_backend()).create_table_from_entity(history::Entity);
        manager.execute(table.if_not_exists().take()).await?;
    }

    let applied: HashSet<_> = history::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.version)
        .collect();
    let migrations = migrations::<C>();
    if let Some(version) = applied.iter().find(|version| {
        !migrations
            .iter()
            .any(|(known, _)| *known == version.as_str())
    }) {
        return Err(DbErr::Custom(format!(
            "Unknown applied migration: {version}"
        )));
    }

    for (version, migration) in migrations {
        if applied.contains(version) {
            continue;
        }
        tracing::info!(version, "Applying migration");
        migration.up(&manager).await?;
        history::Entity::insert(history::ActiveModel {
            version: Set(version.to_owned()),
            applied_at: Set(OffsetDateTime::now_utc().unix_timestamp()),
        })
        .exec(db)
        .await?;
    }
    Ok(())
}

pub(super) async fn run(db: &DatabaseConnection) -> Result<(), DbErr> {
    // MySQL commits DDL implicitly. Each migration checks for already-created objects
    // so an interrupted startup can resume before its history row was recorded.
    if db.get_database_backend() == DbBackend::MySql {
        return apply(db).await;
    }
    let transaction = db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    apply(&transaction).await?;
    transaction.commit().await
}

pub(crate) async fn has_index(
    db: &DatabaseConnection,
    table: &str,
    index: &str,
) -> Result<bool, DbErr> {
    SchemaManager::new(db).has_index(table, index).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::sea_query::{ColumnDef, Table};

    #[tokio::test]
    async fn resumes_from_legacy_history_without_rewriting_applied_rows() {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        let manager = SchemaManager::new(&db);
        manager
            .execute(
                Table::create()
                    .table("seaql_migrations")
                    .col(ColumnDef::new("version").string().not_null().primary_key())
                    .col(ColumnDef::new("applied_at").big_integer().not_null())
                    .take(),
            )
            .await
            .unwrap();

        let original = history::Model {
            version: "m20260811_115204_initial_schema".to_owned(),
            applied_at: 1_786_448_004,
        };
        super::super::m20260811_115204_initial_schema::Migration
            .up(&manager)
            .await
            .unwrap();
        history::Entity::insert(history::ActiveModel {
            version: Set(original.version.clone()),
            applied_at: Set(original.applied_at),
        })
        .exec(&db)
        .await
        .unwrap();

        run(&db).await.unwrap();
        let mut applied = history::Entity::find().all(&db).await.unwrap();
        applied.sort_by(|a, b| a.version.cmp(&b.version));
        assert_eq!(applied[0], original);
        assert!(applied[1..].iter().all(|row| row.applied_at > 0));
        assert_eq!(
            applied
                .iter()
                .map(|row| row.version.as_str())
                .collect::<Vec<_>>(),
            [
                "m20260811_115204_initial_schema",
                "m20260811_152352_add_audit_logs",
                "m20260825_075608_add_vault_group_permissions",
                "m20260826_231500_add_endpoint_max_age_seconds",
                "m20261109_000001_add_performance_indexes",
                "m20261110_220000_add_lookup_indexes",
            ]
        );

        run(&db).await.unwrap();
        let mut rerun = history::Entity::find().all(&db).await.unwrap();
        rerun.sort_by(|a, b| a.version.cmp(&b.version));
        assert_eq!(rerun, applied);
    }
}
