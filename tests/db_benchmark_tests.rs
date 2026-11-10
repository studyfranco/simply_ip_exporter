//! Database query performance benchmarks and index verification tests.
//!
//! Measures and quantifies query execution times before and after indexing for hot paths:
//! 1. `vault_group_permissions` lookups by `vault_group_id` (`group_id`).
//! 2. `api_keys` lookups by `is_master`.
//! 3. `endpoints` ordering by `created_at DESC`.

use std::time::Instant;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, Database, DatabaseBackend,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Statement,
};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

use simply_ip_exporter::db::has_index;
use simply_ip_exporter::entities::{api_key, endpoint, prelude::*, vault_group_permission};
use simply_ip_exporter::migration::Migrator;

#[tokio::test]
async fn verify_all_performance_indexes_are_applied() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("in-memory database opens");
    Migrator::up(&db, None).await.expect("migrations apply cleanly");

    let required_indexes = [
        ("vault_group_permissions", "idx_vault_group_permissions_vault_group_id"),
        ("vault_group_permissions", "idx_vault_group_permissions_key_group"),
        ("api_keys", "idx_api_keys_is_master"),
        ("api_keys", "idx_api_keys_created_at_desc"),
        ("api_keys", "idx_api_keys_prefix"),
        ("endpoints", "idx_endpoints_created_at_desc"),
        ("endpoints", "idx_endpoints_owner_created"),
        ("endpoints", "idx_endpoints_token_secret"),
        ("audit_logs", "idx_audit_logs_action_timestamp_desc"),
        ("audit_logs", "idx_audit_logs_timestamp_desc"),
        ("audit_logs", "idx_audit_logs_api_key_id_timestamp"),
    ];

    for (table, index) in required_indexes {
        assert!(
            has_index(&db, table, index).await.expect("index check succeeds"),
            "Expected index '{index}' on table '{table}' to exist after migrations"
        );
    }
}

#[tokio::test]
async fn benchmark_vault_group_id_lookup_performance() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("in-memory database opens");
    Migrator::up(&db, None).await.expect("migrations apply cleanly");

    // Seed 1 master key + 200 daughter keys
    let master_id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    api_key::ActiveModel {
        id: Set(master_id),
        name: Set("Master Key".to_owned()),
        prefix: Set("mstr1234".to_owned()),
        key_hash: Set("hash_master".to_owned()),
        signing_secret: Set(None),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .expect("master insert");

    let group_ids: Vec<Uuid> = (0..50).map(|_| Uuid::new_v4()).collect();

    // Insert 2,000 permissions
    for i in 0..2000 {
        let key_id = Uuid::new_v4();
        api_key::ActiveModel {
            id: Set(key_id),
            name: Set(format!("Key {i}")),
            prefix: Set(format!("k{:07}", i)),
            key_hash: Set(format!("hash_{i}")),
            signing_secret: Set(None),
            bound_ips: Set(None),
            is_master: Set(false),
            can_manage_keys: Set(false),
            parent_key_id: Set(Some(master_id)),
            owner_key_id: Set(Some(master_id)),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&db)
        .await
        .expect("key insert");

        let gid = group_ids[i % group_ids.len()];
        vault_group_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key_id),
            vault_group_id: Set(gid),
            vault_group_name: Set(format!("group_{}", i % group_ids.len())),
            created_at: Set(now),
        }
        .insert(&db)
        .await
        .expect("grant insert");
    }

    let target_group = group_ids[25];

    // 1. Measure with index
    let start_indexed = Instant::now();
    for _ in 0..200 {
        let _ = VaultGroupPermission::find()
            .filter(vault_group_permission::Column::VaultGroupId.eq(target_group))
            .all(&db)
            .await
            .expect("query succeeds");
    }
    let duration_indexed = start_indexed.elapsed();

    // 2. Drop index and measure without index (simulating sequential table scan)
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        "DROP INDEX idx_vault_group_permissions_vault_group_id;".to_owned(),
    ))
    .await
    .expect("drop index succeeds");

    let start_unindexed = Instant::now();
    for _ in 0..200 {
        let _ = VaultGroupPermission::find()
            .filter(vault_group_permission::Column::VaultGroupId.eq(target_group))
            .all(&db)
            .await
            .expect("query succeeds");
    }
    let duration_unindexed = start_unindexed.elapsed();

    eprintln!(
        "\n[BENCHMARK] vault_group_id lookup (200 iterations over 2,000 rows):\n  Without Index: {:?}\n  With Index:    {:?}\n  Speedup:       {:.2}x faster",
        duration_unindexed,
        duration_indexed,
        duration_unindexed.as_secs_f64() / duration_indexed.as_secs_f64()
    );

    assert!(
        duration_indexed <= duration_unindexed,
        "Indexed query ({:?}) should be at least as fast as unindexed ({:?})",
        duration_indexed,
        duration_unindexed
    );
}

#[tokio::test]
async fn benchmark_api_keys_is_master_lookup_performance() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("in-memory database opens");
    Migrator::up(&db, None).await.expect("migrations apply cleanly");

    let now = chrono::Utc::now().naive_utc();

    // Insert 1,500 non-master keys
    for i in 0..1500 {
        api_key::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(format!("Daughter Key {i}")),
            prefix: Set(format!("d{:07}", i)),
            key_hash: Set(format!("hash_d_{i}")),
            signing_secret: Set(None),
            bound_ips: Set(None),
            is_master: Set(false),
            can_manage_keys: Set(false),
            parent_key_id: Set(None),
            owner_key_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&db)
        .await
        .expect("insert succeeds");
    }

    // Insert 1 master key at the end
    api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set("System Master".to_owned()),
        prefix: Set("mstr9999".to_owned()),
        key_hash: Set("hash_master_final".to_owned()),
        signing_secret: Set(None),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .expect("master insert");

    // 1. Measure with index
    let start_indexed = Instant::now();
    for _ in 0..300 {
        let master = ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .one(&db)
            .await
            .expect("query succeeds");
        assert!(master.is_some());
    }
    let duration_indexed = start_indexed.elapsed();

    // 2. Drop index and measure without index
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        "DROP INDEX idx_api_keys_is_master;".to_owned(),
    ))
    .await
    .expect("drop index succeeds");

    let start_unindexed = Instant::now();
    for _ in 0..300 {
        let master = ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .one(&db)
            .await
            .expect("query succeeds");
        assert!(master.is_some());
    }
    let duration_unindexed = start_unindexed.elapsed();

    eprintln!(
        "\n[BENCHMARK] api_keys is_master lookup (300 iterations over 1,501 rows):\n  Without Index: {:?}\n  With Index:    {:?}\n  Speedup:       {:.2}x faster",
        duration_unindexed,
        duration_indexed,
        duration_unindexed.as_secs_f64() / duration_indexed.as_secs_f64()
    );

    assert!(
        duration_indexed <= duration_unindexed,
        "Indexed query ({:?}) should be at least as fast as unindexed ({:?})",
        duration_indexed,
        duration_unindexed
    );
}

#[tokio::test]
async fn benchmark_endpoints_created_at_ordering_performance() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("in-memory database opens");
    Migrator::up(&db, None).await.expect("migrations apply cleanly");

    let base_time = chrono::Utc::now().naive_utc();

    // Insert 1,500 endpoints with varying timestamps
    for i in 0..1500 {
        endpoint::ActiveModel {
            id: Set(Uuid::new_v4()),
            owner_key_id: Set(None),
            name: Set(format!("Endpoint {i}")),
            description: Set(None),
            token_secret: Set(format!("tok_{i:016}")),
            vault_groups: Set("group1".to_owned()),
            ttl_seconds: Set(3600),
            max_age_seconds: Set(0),
            bound_ips: Set(None),
            filter_rfc1918: Set(false),
            filter_bogons: Set(false),
            filter_loopback: Set(false),
            last_synced_at: Set(None),
            created_at: Set(base_time - chrono::Duration::seconds(i as i64 * 10)),
            updated_at: Set(base_time),
        }
        .insert(&db)
        .await
        .expect("endpoint insert");
    }

    // 1. Measure with index
    let start_indexed = Instant::now();
    for _ in 0..100 {
        let rows = Endpoint::find()
            .order_by_desc(endpoint::Column::CreatedAt)
            .limit(50)
            .all(&db)
            .await
            .expect("query succeeds");
        assert_eq!(rows.len(), 50);
    }
    let duration_indexed = start_indexed.elapsed();

    // 2. Drop index and measure without index (forces sorting in memory/filesort)
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        "DROP INDEX idx_endpoints_created_at_desc;".to_owned(),
    ))
    .await
    .expect("drop index succeeds");

    let start_unindexed = Instant::now();
    for _ in 0..100 {
        let rows = Endpoint::find()
            .order_by_desc(endpoint::Column::CreatedAt)
            .limit(50)
            .all(&db)
            .await
            .expect("query succeeds");
        assert_eq!(rows.len(), 50);
    }
    let duration_unindexed = start_unindexed.elapsed();

    eprintln!(
        "\n[BENCHMARK] endpoints created_at DESC with LIMIT 50 (100 iterations over 1,500 rows):\n  Without Index: {:?}\n  With Index:    {:?}\n  Speedup:       {:.2}x faster",
        duration_unindexed,
        duration_indexed,
        duration_unindexed.as_secs_f64() / duration_indexed.as_secs_f64()
    );

    assert!(
        duration_indexed <= duration_unindexed,
        "Indexed query ({:?}) should be at least as fast as unindexed ({:?})",
        duration_indexed,
        duration_unindexed
    );
}
