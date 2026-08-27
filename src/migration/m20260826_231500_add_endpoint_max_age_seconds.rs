//! Adds `endpoints.max_age_seconds`: an optional per-endpoint retention window bounding how
//! recently a Vault record must have been updated to appear in that endpoint's feed.
//!
//! `0` means **unlimited** (no age cutoff) and is the default, so every endpoint that existed
//! before this migration keeps publishing exactly what it published before. That is why the column
//! is `NOT NULL DEFAULT 0` rather than nullable: "unlimited" is a real, expressible value here, not
//! an absence, and a `NULL` would force every read site to re-decide what missing means.
//!
//! Written with SeaORM's vendor-agnostic builder (`ColumnDef::big_integer`), not raw SQL, so the
//! same migration applies on SQLite, PostgreSQL and MariaDB alike — `AGENT.MD`'s multi-database
//! rule. `big_integer` (i64) rather than `integer` so a window can exceed the ~68-year i32 second
//! ceiling without overflow arithmetic, and so it lines up with `chrono::Duration::seconds`, which
//! takes an `i64` — the value is handed straight to it at feed time.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum Endpoints {
    Table,
    MaxAgeSeconds,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Endpoints::Table)
                    .add_column(
                        ColumnDef::new(Endpoints::MaxAgeSeconds)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter().table(Endpoints::Table).drop_column(Endpoints::MaxAgeSeconds).to_owned(),
            )
            .await
    }
}
