//! Database migration registry for `simply_ip_exporter`. Migrations run automatically on startup.
pub use sea_orm_migration::prelude::*;

mod m20260811_115204_initial_schema;
mod m20260811_152352_add_audit_logs;
mod m20260825_075608_add_vault_group_permissions;
mod m20260826_231500_add_endpoint_max_age_seconds;
mod m20261109_000001_add_performance_indexes;
mod m20261110_220000_add_lookup_indexes;

/// The ordered set of all schema migrations for `simply_ip_exporter`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260811_115204_initial_schema::Migration),
            Box::new(m20260811_152352_add_audit_logs::Migration),
            Box::new(m20260825_075608_add_vault_group_permissions::Migration),
            Box::new(m20260826_231500_add_endpoint_max_age_seconds::Migration),
            Box::new(m20261109_000001_add_performance_indexes::Migration),
            Box::new(m20261110_220000_add_lookup_indexes::Migration),
        ]
    }
}
