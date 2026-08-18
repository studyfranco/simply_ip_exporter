//! Database migration registry for `simply_ip_exporter`. Migrations run automatically on startup.
pub use sea_orm_migration::prelude::*;

mod m20260811_115204_initial_schema;
mod m20260811_152352_add_audit_logs;

/// The ordered set of all schema migrations for `simply_ip_exporter`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260811_115204_initial_schema::Migration),
            Box::new(m20260811_152352_add_audit_logs::Migration),
        ]
    }
}
