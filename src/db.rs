//! Database connection setup: pool construction, SQLite session pragmas, and migrations.
//!
//! SQLite permits a single concurrent writer, so `SQLITE_MAX_CONNECTIONS = 1` is enforced
//! explicitly on the connection pool, per `SCHEMA.MD`.

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    SqlxSqliteConnector, Statement,
};
use sea_orm_migration::MigratorTrait;

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 5_000;

/// Connections in the SQLite pool. Fixed at one, per `SCHEMA.MD`.
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Opens the database pool, declaring SQLite's session pragmas on every connection.
pub async fn connect(db_url: &str) -> Result<DatabaseConnection, DbErr> {
    let mut opt = ConnectOptions::new(db_url.to_owned());
    opt.sqlx_logging_level(log::LevelFilter::Debug);

    if !db_url.starts_with("sqlite:") {
        return Database::connect(opt).await;
    }

    use sea_orm::sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };
    use std::str::FromStr;

    let connect_options = SqliteConnectOptions::from_str(db_url)
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_millis(u64::from(SQLITE_BUSY_TIMEOUT_MS)));

    let pool = SqlitePoolOptions::new()
        .max_connections(SQLITE_MAX_CONNECTIONS)
        .connect_with(connect_options)
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// Runs every pending migration.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    tracing::info!("Running database migrations...");
    crate::migration::Migrator::up(db, None).await
}

/// Whether an index named `index` exists on `table`, queried directly against the backend's own
/// catalog rather than through `sea_orm_migration::SchemaManager::has_index`.
///
/// Ported from `example/simply_ip_vault`'s `db::has_index` (2026-08-18 harmonization pass — see
/// `AGENT_NOTES.MD`): `SchemaManager::has_index` gates its catalog query behind cargo features this
/// crate does not enable for PostgreSQL, so it answers `BackendNotSupported` there rather than
/// correctly reporting whether the index exists — a database whose index is present and correct
/// would still fail `master::MasterPin::pin_at_boot`'s check. This crate is documented as SQLite-only
/// today, so the defect is latent rather than live, but the fix costs nothing and removes the trap
/// for good rather than leaving it for whoever changes that later.
///
/// Returns `Ok(false)` when the index is absent — an absent index is an answer, not an error. Only a
/// failure to *ask* (an unrecognized backend, or a query error) is an error.
pub async fn has_index(db: &DatabaseConnection, table: &str, index: &str) -> Result<bool, DbErr> {
    let backend = db.get_database_backend();
    let sql = index_catalog_query(backend)?;

    let row = db
        .query_one_raw(Statement::from_sql_and_values(backend, sql, [index.into(), table.into()]))
        .await?
        .ok_or_else(|| {
            DbErr::Custom(format!("catalog query for index '{index}' on '{table}' returned no row"))
        })?;

    // `COUNT(*)` is `i64` on PostgreSQL and SQLite and narrower on some MySQL drivers, so the
    // smaller type is tried second rather than assumed.
    let hits: i64 = match row.try_get::<i64>("", "hits") {
        Ok(n) => n,
        Err(_) => i64::from(row.try_get::<i32>("", "hits")?),
    };
    Ok(hits > 0)
}

/// The catalog query for one backend, taking the index name first and the table name second.
///
/// Split out from [`has_index`] so it is unit-testable without a live database — the defect this
/// replaces is PostgreSQL-only, and no suite in this crate starts a PostgreSQL server, so a test
/// requiring a live connection could not have caught it and cannot guard against its return.
fn index_catalog_query(backend: DatabaseBackend) -> Result<&'static str, DbErr> {
    Ok(match backend {
        DatabaseBackend::Sqlite => {
            "SELECT COUNT(*) AS hits FROM sqlite_master \
             WHERE type = 'index' AND name = ? AND tbl_name = ?"
        }
        DatabaseBackend::Postgres => {
            "SELECT COUNT(*) AS hits FROM pg_indexes WHERE indexname = $1 AND tablename = $2"
        }
        DatabaseBackend::MySql => {
            "SELECT COUNT(*) AS hits FROM information_schema.statistics \
             WHERE index_name = ? AND table_name = ? AND table_schema = DATABASE()"
        }
        // `DatabaseBackend` is `#[non_exhaustive]`: a future SeaORM release can add a variant this
        // build has never heard of. Refusing is the only safe answer — inventing `true` for a
        // backend whose catalog cannot be read would report the constraint as present without
        // having looked.
        other => {
            return Err(DbErr::Custom(format!(
                "no catalog query is known for backend {other:?}; refusing to assume an index exists"
            )));
        }
    })
}

/// Applies SQLite's session pragmas to the current connection, logging what actually took effect.
///
/// A pragma that cannot be applied (e.g. `journal_mode=WAL` against `sqlite::memory:`) is logged
/// and swallowed rather than aborting startup: these are performance settings, not correctness
/// ones.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    match db
        .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA journal_mode=WAL;"))
        .await
    {
        Ok(Some(row)) => match row.try_get::<String>("", "journal_mode") {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
                tracing::info!("SQLite journal mode: WAL.");
            }
            Ok(mode) => tracing::info!(
                "SQLite journal mode is '{mode}' rather than WAL; normal for in-memory databases."
            ),
            Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}"),
        },
        Ok(None) => tracing::warn!("PRAGMA journal_mode returned no row; leaving the default."),
        Err(e) => tracing::warn!("Could not enable SQLite WAL mode: {e}. Continuing without it."),
    }

    for (label, statement) in [
        ("foreign key enforcement", "PRAGMA foreign_keys=ON;".to_owned()),
        ("synchronous mode", "PRAGMA synchronous=NORMAL;".to_owned()),
        ("busy timeout", format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")),
    ] {
        if let Err(e) =
            db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, statement)).await
        {
            tracing::warn!("Could not set the SQLite {label}: {e}. Continuing with the default.");
        }
    }

    Ok(())
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

    #[tokio::test]
    async fn connect_applies_pragmas_and_pins_pool_to_one_connection() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        assert_eq!(db.get_sqlite_connection_pool().options().get_max_connections(), 1);

        async fn pragma<T: sea_orm::TryGetable>(db: &DatabaseConnection, sql: &str, col: &str) -> T {
            db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql.to_owned()))
                .await
                .expect("pragma query succeeds")
                .expect("a row is returned")
                .try_get("", col)
                .expect("expected type")
        }
        assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;", "foreign_keys").await, 1);
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
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        apply_sqlite_pragmas(&db).await.expect("pragmas apply");
        run_migrations(&db).await.expect("migrations apply");

        use sea_orm::{ActiveValue::Set, EntityTrait};
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
        assert!(crate::entities::prelude::Endpoint::insert(orphan).exec(&db).await.is_err());
    }

    #[tokio::test]
    async fn a_database_that_cannot_use_wal_still_starts() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
        run_migrations(&db).await.expect("migrations still run");
    }

    #[tokio::test]
    async fn has_index_finds_a_real_index_and_correctly_reports_absence() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        run_migrations(&db).await.expect("migrations apply");
        assert!(
            has_index(&db, "api_keys", "idx_api_keys_master_marker").await.expect("query succeeds"),
            "the generated master_marker index must be found"
        );
        assert!(
            !has_index(&db, "api_keys", "no_such_index").await.expect("query succeeds"),
            "a nonexistent index must report false, not error"
        );
    }

    /// Every backend `DatabaseBackend` currently defines gets a real catalog query. `DatabaseBackend`
    /// is `#[non_exhaustive]`, so there is no way to construct a fourth variant from this crate to
    /// exercise the `other => Err(...)` arm directly — its guarantee is that a *future* backend this
    /// build has never heard of is refused rather than silently assumed present, which is enforced by
    /// the `match` itself having no wildcard `Ok` arm, not by a test that could run today.
    #[test]
    fn index_catalog_query_covers_every_known_backend() {
        for backend in [DatabaseBackend::Sqlite, DatabaseBackend::Postgres, DatabaseBackend::MySql] {
            assert!(index_catalog_query(backend).is_ok(), "{backend:?} must have a catalog query");
        }
    }
}
