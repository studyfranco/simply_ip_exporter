//! Background sync worker implementing the hybrid refresh protocol: differential sync on TTL
//! expiration, and a full unconstrained resync every 24 hours to clear orphaned records.

use std::time::Duration;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};

use crate::cache::VaultRecord;
use crate::entities::{endpoint, prelude::Endpoint};
use crate::state::AppState;
use crate::vault_client::VaultApiRecord;

/// How often every endpoint gets a full, unconstrained resync, per `AGENT.MD`.
pub const FULL_SYNC_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// How often the worker wakes to check whether any endpoint is due for a sync.
const TICK_INTERVAL: Duration = Duration::from_secs(15);

/// Wall-clock ceiling on the boot sync ([`run_boot_sync`]) before startup proceeds regardless.
///
/// The boot pass is sequential and each endpoint's fetch can take up to `vault_client`'s own 15s
/// request timeout, so an unreachable Vault plus a handful of endpoints would otherwise hold the
/// HTTP listener closed for minutes. To an orchestrator that is indistinguishable from a failed
/// start: Docker's `HEALTHCHECK` and Kubernetes' probes cannot even open a connection while the
/// listener is unbound, so they escalate to a restart, and the next boot stalls identically — the
/// crash loop `AGENT.MD` requires this daemon never to enter. Capping the wait converts that into a
/// bounded delay after which the service starts serving (initially from an empty or partial cache)
/// while the background worker keeps retrying.
const BOOT_SYNC_BUDGET: Duration = Duration::from_secs(30);

fn map_records(records: Vec<VaultApiRecord>) -> Vec<VaultRecord> {
    records
        .into_iter()
        .map(|r| VaultRecord {
            target_address: r.target_address,
            updated_at: r.updated_at,
            is_deleted: r.is_deleted,
        })
        .collect()
}

/// Runs one full synchronization pass over every endpoint **before** the HTTP listener opens, so
/// the first caller to fetch a feed is served real data rather than an empty cache.
///
/// # Why this exists when the worker already syncs immediately
///
/// [`spawn_sync_worker`] does not sleep before its first pass — it syncs, *then* waits a tick. But
/// it does that on a **spawned task**, concurrently with `axum::serve`, so the listener starts
/// accepting traffic while that first pass is still in flight. Any feed fetched inside that window
/// is answered from a cache that has not been populated yet: a `200` with an empty body, which a
/// consumer like pfBlockerNG cannot distinguish from "the list is legitimately empty" and will
/// happily install as an empty alias. Awaiting one pass here closes that window; the worker is
/// spawned afterwards and its own immediate pass finds nothing due (this pass just set
/// `last_full_sync_at` and `last_synced_at`), so nothing is fetched twice.
///
/// # Never fatal, always bounded
///
/// Every failure inside the pass is already logged-and-swallowed per endpoint by [`sync_endpoint`],
/// so an unreachable Vault costs warnings rather than a failed boot. The whole pass is additionally
/// capped at [`BOOT_SYNC_BUDGET`]: without that ceiling a Vault that accepts connections but never
/// answers would keep the listener closed for `endpoints × 15s`, which an orchestrator reads as a
/// failed start and restarts — a boot loop, which is strictly worse than serving a cold cache while
/// the background worker catches up.
pub async fn run_boot_sync(state: &AppState) {
    if state.vault_client.is_none() {
        tracing::info!(
            "Skipping the startup sync: simply_ip_vault is not configured. Feeds will be empty \
             until VAULT_BASE_URL/VAULT_API_KEY/VAULT_SIGNING_SECRET are set."
        );
        return;
    }

    tracing::info!("Running the startup sync before opening the HTTP listener...");
    let started = std::time::Instant::now();

    match tokio::time::timeout(BOOT_SYNC_BUDGET, sync_all_endpoints(state)).await {
        Ok(()) => tracing::info!(
            "Startup sync finished in {:?}; the cache is populated before the first request.",
            started.elapsed()
        ),
        Err(_) => tracing::warn!(
            "Startup sync did not finish within {}s. Starting anyway and serving whatever is \
             already cached — the background sync worker continues from here, so no restart is \
             needed. Check that simply_ip_vault is reachable.",
            BOOT_SYNC_BUDGET.as_secs()
        ),
    }
}

/// Spawns the background sync loop, returning its join handle for graceful shutdown.
///
/// The loop syncs first and sleeps second, so an endpoint created while the process is running is
/// picked up on the next tick rather than a tick plus a full interval later.
pub fn spawn_sync_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            sync_all_endpoints(&state).await;
            tokio::time::sleep(TICK_INTERVAL).await;
        }
    })
}

async fn sync_all_endpoints(state: &AppState) {
    let Some(client) = state.vault_client.clone() else {
        return;
    };

    let endpoints = match Endpoint::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("Could not list endpoints for sync: {e}");
            return;
        }
    };

    for ep in endpoints {
        sync_endpoint(state, &client, ep).await;
    }
}

async fn sync_endpoint(state: &AppState, client: &crate::vault_client::VaultClient, ep: endpoint::Model) {
    let full_due = state.ip_cache.full_sync_due(ep.id, FULL_SYNC_INTERVAL).await;

    if full_due {
        match client.fetch_ips(&ep.vault_groups, None).await {
            Ok(records) => {
                let id = ep.id;
                state.ip_cache.apply_full(id, &map_records(records)).await;
                mark_synced(state, ep).await;
                tracing::info!(endpoint = %id, "Full sync completed");
            }
            Err(e) => {
                tracing::warn!(
                    endpoint = %ep.id,
                    "Full sync against simply_ip_vault failed: {e}. Continuing to serve the \
                     existing in-memory cache."
                );
            }
        }
        return;
    }

    let due = match ep.last_synced_at {
        None => true,
        Some(last) => {
            Utc::now().naive_utc() - last >= chrono::Duration::seconds(ep.ttl_seconds.max(1) as i64)
        }
    };
    if !due {
        return;
    }

    match client.fetch_ips(&ep.vault_groups, ep.last_synced_at).await {
        Ok(records) => {
            state.ip_cache.apply_diff(ep.id, &map_records(records)).await;
            mark_synced(state, ep).await;
        }
        Err(e) => {
            tracing::warn!(
                endpoint = %ep.id,
                "Differential sync against simply_ip_vault failed: {e}. Continuing to serve the \
                 existing in-memory cache."
            );
        }
    }
}

async fn mark_synced(state: &AppState, ep: endpoint::Model) {
    let id = ep.id;
    let mut active: endpoint::ActiveModel = ep.into();
    active.last_synced_at = Set(Some(Utc::now().naive_utc()));
    if let Err(e) = active.update(&state.db).await {
        tracing::warn!(endpoint = %id, "Could not persist last_synced_at: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_records_preserves_deletion_state() {
        let raw = vec![VaultApiRecord {
            target_address: "10.0.0.1/32".to_owned(),
            updated_at: Utc::now().naive_utc(),
            is_deleted: true,
        }];
        let mapped = map_records(raw);
        assert!(mapped[0].is_deleted);
    }

    // ── Resilience across the Vault error spectrum ──────────────────────────
    //
    // AGENT.MD: "If simply_ip_vault is offline, log a warning and keep serving the current
    // in-memory cache to public callers." These tests exercise `sync_endpoint` directly (it is
    // private, but this module's own test suite can see it) against a real mock Vault server for
    // every point on that spectrum: authenticated-but-rejected (401/403), server-side failure
    // (500), and total connection failure — asserting each leaves a pre-populated cache exactly as
    // it was, with no panic, and does not falsely advance `last_synced_at`.

    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use uuid::Uuid;

    use crate::config::RuntimeConfig;
    use crate::crypto::SecretCipher;

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite always opens");
        crate::migration::Migrator::up(&db, None).await.expect("migrations apply");
        db
    }

    fn test_state(db: &DatabaseConnection, vault_base_url: String) -> AppState {
        let config = RuntimeConfig {
            vault_base_url: Some(vault_base_url),
            vault_api_key: Some("key".to_owned()),
            vault_signing_secret: Some("secret".to_owned()),
            ..RuntimeConfig::default()
        };
        AppState::new(db.clone(), std::sync::Arc::new(config), std::sync::Arc::new(SecretCipher::Plaintext))
    }

    /// Inserts a real `endpoints` row (so `mark_synced`'s `UPDATE` has something to affect) and
    /// returns the model `sync_endpoint` expects.
    async fn insert_test_endpoint(db: &DatabaseConnection, last_synced_at: Option<chrono::NaiveDateTime>) -> endpoint::Model {
        let now = Utc::now().naive_utc();
        let model = endpoint::ActiveModel {
            id: Set(Uuid::new_v4()),
            owner_key_id: Set(None),
            name: Set("Resilience Test".to_owned()),
            description: Set(None),
            token_secret: Set(Uuid::new_v4().simple().to_string()),
            vault_groups: Set("g1".to_owned()),
            max_age_seconds: Set(0),
        ttl_seconds: Set(1),
            bound_ips: Set(None),
            filter_rfc1918: Set(false),
            filter_bogons: Set(false),
            filter_loopback: Set(false),
            last_synced_at: Set(last_synced_at),
            created_at: Set(now),
            updated_at: Set(now),
        };
        model.insert(db).await.expect("insert succeeds")
    }

    async fn spawn_mock_vault(
        status: axum::http::StatusCode,
        body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{Router, routing::get};

        let app = Router::new().route(
            "/api/ips",
            get(move || {
                let body = body.clone();
                async move { (status, axum::Json(body)) }
            }),
        );
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), handle)
    }

    fn seed_record(addr: &str) -> crate::cache::VaultRecord {
        crate::cache::VaultRecord {
            target_address: addr.to_owned(),
            updated_at: Utc::now().naive_utc(),
            is_deleted: false,
        }
    }

    // ── Startup sync ────────────────────────────────────────────────────────

    /// The property the boot sync exists for: an endpoint already in the database is synced during
    /// startup, so the cache holds real records *before* `axum::serve` is ever reached — not one
    /// tick later, and not racing the listener from a spawned task.
    #[tokio::test]
    async fn the_boot_sync_populates_the_cache_for_endpoints_already_in_the_database() {
        let (url, _server) = spawn_mock_vault(
            axum::http::StatusCode::OK,
            serde_json::json!([
                {"target_address": "203.0.113.7/32", "updated_at": "2026-08-11T10:00:00", "is_deleted": false},
                {"target_address": "198.51.100.9/32", "updated_at": "2026-08-11T10:00:00", "is_deleted": false}
            ]),
        )
        .await;
        let db = test_db().await;
        let state = test_state(&db, url);
        let ep = insert_test_endpoint(&db, None).await;

        assert!(
            state.ip_cache.snapshot(ep.id).await.is_empty(),
            "precondition: nothing is cached before the boot sync runs"
        );

        run_boot_sync(&state).await;

        let cached = state.ip_cache.snapshot(ep.id).await;
        assert_eq!(cached.len(), 2, "the boot sync must have fetched and cached both records");
    }

    /// The resilience contract at boot: Vault being unreachable must leave the process able to
    /// continue starting. `run_boot_sync` returns normally (there is no error to propagate and
    /// nothing to panic on), leaving the cache empty for the worker to fill in later.
    #[tokio::test]
    async fn the_boot_sync_returns_normally_when_vault_is_unreachable() {
        // Bind then immediately drop, so the port is genuinely closed — a deterministic
        // ECONNREFUSED without depending on a specific port staying free.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        drop(listener);

        let db = test_db().await;
        let state = test_state(&db, format!("http://{addr}"));
        let ep = insert_test_endpoint(&db, None).await;

        run_boot_sync(&state).await;

        assert!(
            state.ip_cache.snapshot(ep.id).await.is_empty(),
            "an unreachable Vault leaves the cache empty rather than failing the boot"
        );
    }

    /// With no Vault configured the boot sync is a no-op that must not stall startup — the
    /// zero-configuration path a first run takes before any Vault credentials are set.
    #[tokio::test]
    async fn the_boot_sync_is_a_no_op_without_a_configured_vault() {
        let db = test_db().await;
        let config = RuntimeConfig::default();
        let state = AppState::new(
            db.clone(),
            std::sync::Arc::new(config),
            std::sync::Arc::new(SecretCipher::Plaintext),
        );
        let ep = insert_test_endpoint(&db, None).await;

        // Also asserts it returns promptly: `BOOT_SYNC_BUDGET` is 30s, so a no-op that somehow
        // waited on the timeout would blow this margin by orders of magnitude.
        let started = std::time::Instant::now();
        run_boot_sync(&state).await;
        assert!(started.elapsed() < Duration::from_secs(5), "the unconfigured path must return at once");
        assert!(state.ip_cache.snapshot(ep.id).await.is_empty());
    }

    /// The boot sync must not re-fetch what it just fetched: after it runs, the background worker's
    /// own immediate first pass finds nothing due (`last_full_sync_at` and `last_synced_at` were
    /// both just set) and issues no further requests. Counted at the mock, since a duplicate full
    /// sync would be invisible in the cache contents.
    #[tokio::test]
    async fn the_worker_does_not_repeat_the_work_the_boot_sync_just_did() {
        use axum::{Router, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_for_handler = std::sync::Arc::clone(&hits);
        let app = Router::new().route(
            "/api/ips",
            get(move || {
                let hits = std::sync::Arc::clone(&hits_for_handler);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!([
                        {"target_address": "203.0.113.7/32", "updated_at": "2026-08-11T10:00:00", "is_deleted": false}
                    ]))
                }
            }),
        );
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        let _server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let db = test_db().await;
        let state = test_state(&db, format!("http://{addr}"));
        // ttl_seconds is 1 in the fixture, so this endpoint would become due again a second later;
        // the assertion below runs well inside that, isolating "the worker's first pass" from
        // "a legitimately due later sync".
        let _ep = insert_test_endpoint(&db, None).await;

        run_boot_sync(&state).await;
        let after_boot = hits.load(Ordering::SeqCst);
        assert_eq!(after_boot, 1, "the boot sync fetches each endpoint exactly once");

        // Exactly what `spawn_sync_worker` does before its first sleep.
        sync_all_endpoints(&state).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            after_boot,
            "the worker's immediate first pass must find nothing due and re-fetch nothing"
        );
    }

    /// A full sync (never-synced endpoint) against an unauthorized Vault must not panic and must
    /// leave the cache empty rather than in some partially-applied state.
    #[tokio::test]
    async fn full_sync_against_401_does_not_panic_and_leaves_an_empty_cache_empty() {
        let (url, _server) =
            spawn_mock_vault(axum::http::StatusCode::UNAUTHORIZED, serde_json::json!({"error": "bad key"}))
                .await;
        let db = test_db().await;
        let state = test_state(&db, url);
        let client = state.vault_client.clone().expect("configured");
        let ep = insert_test_endpoint(&db, None).await;

        sync_endpoint(&state, &client, ep.clone()).await;

        assert!(state.ip_cache.snapshot(ep.id).await.is_empty());
    }

    /// The core resilience property: a cache already holding data from a prior successful sync
    /// must survive a subsequent 401/403/500/connection-failure untouched, byte for byte.
    async fn assert_differential_sync_failure_preserves_the_cache(
        status: Option<axum::http::StatusCode>,
    ) {
        let (url, _server) = match status {
            Some(status) => {
                let (url, server) =
                    spawn_mock_vault(status, serde_json::json!({"error": "rejected"})).await;
                (url, Some(server))
            }
            // `None` selects the connection-failure case: bind to grab a free port, then drop the
            // listener so nothing answers there.
            None => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("loopback bind always succeeds");
                let addr = listener.local_addr().expect("bound listener has an address");
                drop(listener);
                (format!("http://{addr}"), None)
            }
        };

        let db = test_db().await;
        let state = test_state(&db, url);
        let client = state.vault_client.clone().expect("configured");

        // A prior successful full sync populated the cache and marked `last_full_sync_at`, so this
        // call takes the differential branch below rather than attempting another full sync.
        let ep = insert_test_endpoint(&db, Some(Utc::now().naive_utc() - chrono::Duration::hours(1)))
            .await;
        state.ip_cache.apply_full(ep.id, &[seed_record("8.8.8.8/32"), seed_record("1.1.1.1/32")]).await;
        let before = state.ip_cache.snapshot(ep.id).await;
        assert_eq!(before.len(), 2, "the fixture pre-populates two cached records");

        sync_endpoint(&state, &client, ep.clone()).await;

        let after = state.ip_cache.snapshot(ep.id).await;
        assert_eq!(after.len(), before.len(), "the cache must be unchanged after a failed sync");
        let after_set: std::collections::HashSet<_> = after.into_iter().collect();
        let before_set: std::collections::HashSet<_> = before.into_iter().collect();
        assert_eq!(after_set, before_set);

        // `last_synced_at` in the database must not have been falsely advanced by a failed sync —
        // a later differential fetch should still use the true last-successful timestamp as `since`.
        let reloaded = Endpoint::find_by_id(ep.id).one(&state.db).await.expect("query succeeds").expect("row exists");
        assert_eq!(reloaded.last_synced_at, ep.last_synced_at);
    }

    #[tokio::test]
    async fn differential_sync_against_401_preserves_the_cache() {
        assert_differential_sync_failure_preserves_the_cache(Some(axum::http::StatusCode::UNAUTHORIZED)).await;
    }

    #[tokio::test]
    async fn differential_sync_against_403_preserves_the_cache() {
        assert_differential_sync_failure_preserves_the_cache(Some(axum::http::StatusCode::FORBIDDEN)).await;
    }

    #[tokio::test]
    async fn differential_sync_against_500_preserves_the_cache() {
        assert_differential_sync_failure_preserves_the_cache(Some(axum::http::StatusCode::INTERNAL_SERVER_ERROR))
            .await;
    }

    #[tokio::test]
    async fn differential_sync_against_a_total_connection_failure_preserves_the_cache() {
        assert_differential_sync_failure_preserves_the_cache(None).await;
    }

    /// The positive control: without this, the four tests above could all be passing vacuously
    /// (e.g. if `sync_endpoint` silently did nothing at all, ever). A successful differential sync
    /// must actually merge new records in and advance `last_synced_at`.
    #[tokio::test]
    async fn differential_sync_against_a_healthy_vault_actually_updates_the_cache() {
        let (url, _server) = spawn_mock_vault(
            axum::http::StatusCode::OK,
            serde_json::json!([
                {"target_address": "9.9.9.9/32", "updated_at": "2026-08-11T10:00:00", "is_deleted": false}
            ]),
        )
        .await;
        let db = test_db().await;
        let state = test_state(&db, url);
        let client = state.vault_client.clone().expect("configured");

        let ep = insert_test_endpoint(&db, Some(Utc::now().naive_utc() - chrono::Duration::hours(1)))
            .await;
        state.ip_cache.apply_full(ep.id, &[seed_record("8.8.8.8/32")]).await;

        sync_endpoint(&state, &client, ep.clone()).await;

        let after = state.ip_cache.snapshot(ep.id).await;
        assert_eq!(after.len(), 2, "the new record was merged in alongside the pre-existing one");

        let reloaded = Endpoint::find_by_id(ep.id).one(&state.db).await.expect("query succeeds").expect("row exists");
        assert!(reloaded.last_synced_at > ep.last_synced_at, "a successful sync must advance last_synced_at");
    }
}
