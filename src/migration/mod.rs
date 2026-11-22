//! Ordered database migrations, applied automatically at startup.

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr};

mod m20260811_115204_initial_schema;
mod m20260811_152352_add_audit_logs;
mod m20260825_075608_add_vault_group_permissions;
mod m20260826_231500_add_endpoint_max_age_seconds;
mod m20261109_000001_add_performance_indexes;
mod m20261110_220000_add_lookup_indexes;
mod runner;

use runner::Migration;

fn migrations<C: ConnectionTrait>() -> [(&'static str, Box<dyn Migration<C>>); 6] {
    [
        (
            "m20260811_115204_initial_schema",
            Box::new(m20260811_115204_initial_schema::Migration),
        ),
        (
            "m20260811_152352_add_audit_logs",
            Box::new(m20260811_152352_add_audit_logs::Migration),
        ),
        (
            "m20260825_075608_add_vault_group_permissions",
            Box::new(m20260825_075608_add_vault_group_permissions::Migration),
        ),
        (
            "m20260826_231500_add_endpoint_max_age_seconds",
            Box::new(m20260826_231500_add_endpoint_max_age_seconds::Migration),
        ),
        (
            "m20261109_000001_add_performance_indexes",
            Box::new(m20261109_000001_add_performance_indexes::Migration),
        ),
        (
            "m20261110_220000_add_lookup_indexes",
            Box::new(m20261110_220000_add_lookup_indexes::Migration),
        ),
    ]
}

/// Applies every pending migration.
///
/// # Errors
/// Returns a database error if schema inspection, migration, or history recording fails.
pub async fn run(db: &DatabaseConnection) -> Result<(), DbErr> {
    runner::run(db).await
}

pub(crate) use runner::has_index;
