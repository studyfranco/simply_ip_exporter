//! Database migration registry for `simply_ip_exporter`. Migrations run automatically on startup.
pub use sea_orm_migration::prelude::*;

mod m20260101_000001_initial_schema;

/// The ordered set of all schema migrations for `simply_ip_exporter`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20260101_000001_initial_schema::Migration)]
    }
}
