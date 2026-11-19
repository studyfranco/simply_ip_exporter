//! Database connection setup: pool construction, SQLite session pragmas, and migrations.
//!
//! SQLite permits a single concurrent writer, so `SQLITE_MAX_CONNECTIONS = 1` is enforced
//! explicitly on the connection pool, per `SCHEMA.MD`.

use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbErr, SqlxSqliteConnector};
use sea_orm_migration::{MigratorTrait, SchemaManager};

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 10_000;

/// Connections in the SQLite pool. Fixed at one, per `SCHEMA.MD`.
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Opens the database pool, declaring SQLite's session pragmas and close-time `PRAGMA optimize`
/// declaratively via [`SqliteConnectOptions`](sea_orm::sqlx::sqlite::SqliteConnectOptions) (zero
/// raw `PRAGMA` SQL statements).
///
/// # Errors
/// Returns [`DbErr`] if parsing the database URL or opening the pool fails.
pub async fn connect(db_url: &str) -> Result<DatabaseConnection, DbErr> {
    use sea_orm::sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };
    use std::str::FromStr;

    let mut opt = ConnectOptions::new(db_url.to_owned());
    opt.sqlx_logging_level(log::LevelFilter::Debug);

    if !db_url.starts_with("sqlite:") {
        return Database::connect(opt).await;
    }

    let connect_options = SqliteConnectOptions::from_str(db_url)
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_millis(u64::from(
            SQLITE_BUSY_TIMEOUT_MS,
        )))
        .pragma("temp_store", "MEMORY")
        .pragma("mmap_size", "268435456")
        .pragma("cache_size", "-64000")
        .analysis_limit(1000)
        .optimize_on_close(true, Some(1000));

    let pool = SqlitePoolOptions::new()
        .max_connections(SQLITE_MAX_CONNECTIONS)
        .connect_with(connect_options)
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// Runs every pending migration.
///
/// # Errors
/// Returns [`DbErr`] if applying migrations fails.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    tracing::info!("Running database migrations...");
    crate::migration::Migrator::up(db, None).await
}

/// Whether an index named `index` exists on `table`, inspected via `SeaORM`'s
/// [`SchemaManager::has_index`] (zero raw SQL).
///
/// # Errors
/// Returns [`DbErr`] if the backend is unsupported or the schema inspection fails.
pub async fn has_index(db: &DatabaseConnection, table: &str, index: &str) -> Result<bool, DbErr> {
    SchemaManager::new(db).has_index(table, index).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDb(std::path::PathBuf);
    impl TempDb {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("sie_db_{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir is creatable");
            Self(dir)
        }
        fn url(&self) -> String {
            format!("sqlite://{}", self.0.join("sie.db").display())
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn pragma<T>(db: &DatabaseConnection, sql: &'static str) -> T
    where
        T: Send
            + Unpin
            + for<'r> sea_orm::sqlx::Decode<'r, sea_orm::sqlx::Sqlite>
            + sea_orm::sqlx::Type<sea_orm::sqlx::Sqlite>,
    {
        sea_orm::sqlx::query_scalar::<_, T>(sql)
            .fetch_one(db.get_sqlite_connection_pool())
            .await
            .expect("pragma query succeeds")
    }

    #[tokio::test]
    async fn connect_applies_pragmas_and_pins_pool_to_one_connection() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool()
                .options()
                .get_max_connections(),
            1
        );
        assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;").await, "wal");
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;").await, 1);
        assert_eq!(pragma::<i32>(&db, "PRAGMA temp_store;").await, 2);
        assert_eq!(pragma::<i32>(&db, "PRAGMA cache_size;").await, -64000);
        assert_eq!(pragma::<i32>(&db, "PRAGMA analysis_limit;").await, 1000);
    }

    #[tokio::test]
    async fn migrations_apply_and_are_idempotent() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        run_migrations(&db).await.expect("migrations apply");
        run_migrations(&db).await.expect("re-running is a no-op");
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let db = connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite opens");
        run_migrations(&db).await.expect("migrations apply");

        let orphan = crate::entities::endpoint::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            owner_key_id: Set(Some(uuid::Uuid::new_v4())),
            name: Set("orphan".to_owned()),
            description: Set(None),
            token_secret: Set("tok".to_owned()),
            vault_groups: Set("g1".to_owned()),
            max_age_seconds: Set(0),
            ttl_seconds: Set(3600),
            bound_ips: Set(None),
            filter_rfc1918: Set(false),
            filter_bogons: Set(false),
            filter_loopback: Set(false),
            last_synced_at: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        };
        assert!(
            crate::entities::prelude::Endpoint::insert(orphan)
                .exec(&db)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_database_that_cannot_use_wal_still_starts() {
        let db = connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite opens");
        run_migrations(&db).await.expect("migrations still run");
    }

    #[tokio::test]
    async fn has_index_finds_a_real_index_and_correctly_reports_absence() {
        let db = connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite opens");
        run_migrations(&db).await.expect("migrations apply");
        assert!(
            has_index(&db, "api_keys", "idx_api_keys_master_marker")
                .await
                .expect("query succeeds"),
            "the generated master_marker index must be found"
        );
        assert!(
            !has_index(&db, "api_keys", "no_such_index")
                .await
                .expect("query succeeds"),
            "a nonexistent index must report false, not error"
        );
    }
}
