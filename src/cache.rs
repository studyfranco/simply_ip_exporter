//! Thread-safe in-memory IP cache. Per `AGENT.MD`, IP records and aggregated CIDR sets are held
//! strictly in RAM (`Arc<RwLock<...>>`) and are never written to SQLite or disk.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::NaiveDateTime;
use ipnet::IpNet;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Parses a Vault `target_address` (`"192.168.1.50"` or `"192.168.1.50/32"`) into a network.
pub fn parse_target_address(raw: &str) -> Option<IpNet> {
    if let Ok(net) = raw.parse::<IpNet>() {
        return Some(net);
    }
    raw.parse::<std::net::IpAddr>().ok().map(IpNet::from)
}

/// One record's cached state, keyed by its normalized `target_address` string.
#[derive(Clone, Debug)]
struct CachedRecord {
    network: IpNet,
    /// Vault's `updated_at` for this record — retained (2026-08-26) so an endpoint's
    /// `max_age_seconds` retention window can be evaluated at feed-generation time. See
    /// [`IpCache::snapshot_within`] for why the age cutoff is applied there rather than at sync.
    updated_at: NaiveDateTime,
}

/// The in-memory state for a single endpoint's feed.
#[derive(Clone, Debug, Default)]
struct EndpointCache {
    records: HashMap<String, CachedRecord>,
    /// The most recent `updated_at` seen from Vault, used as the next differential sync's `since`.
    last_synced_at: Option<NaiveDateTime>,
    /// When the last full (unconstrained) sync completed, in-process monotonic time.
    last_full_sync_at: Option<tokio::time::Instant>,
}

/// A single record as received from `simply_ip_vault`'s `GET /api/ips` contract.
#[derive(Clone, Debug)]
pub struct VaultRecord {
    /// The raw `target_address` as Vault stored it.
    pub target_address: String,
    /// Last activity timestamp, UTC naive.
    pub updated_at: NaiveDateTime,
    /// Whether this record is a soft-deleted tombstone.
    pub is_deleted: bool,
}

/// Thread-safe, per-endpoint in-memory IP cache.
#[derive(Clone, Default)]
pub struct IpCache {
    inner: Arc<RwLock<HashMap<Uuid, EndpointCache>>>,
}

impl IpCache {
    /// Builds an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the entire record set for an endpoint (a full 24h sync), dropping orphans that no
    /// longer appear in Vault's response.
    pub async fn apply_full(&self, endpoint_id: Uuid, records: &[VaultRecord]) {
        let mut guard = self.inner.write().await;
        let entry = guard.entry(endpoint_id).or_default();
        entry.records.clear();
        let mut max_updated = entry.last_synced_at;
        for record in records {
            if record.is_deleted {
                continue;
            }
            let Some(network) = parse_target_address(&record.target_address) else { continue };
            max_updated = Some(max_updated.map_or(record.updated_at, |m| m.max(record.updated_at)));
            entry.records.insert(
                record.target_address.clone(),
                CachedRecord { network, updated_at: record.updated_at },
            );
        }
        entry.last_synced_at = max_updated;
        entry.last_full_sync_at = Some(tokio::time::Instant::now());
    }

    /// Merges a differential batch: upserts live records, removes soft-deleted ones.
    pub async fn apply_diff(&self, endpoint_id: Uuid, records: &[VaultRecord]) {
        let mut guard = self.inner.write().await;
        let entry = guard.entry(endpoint_id).or_default();
        let mut max_updated = entry.last_synced_at;
        for record in records {
            max_updated = Some(max_updated.map_or(record.updated_at, |m| m.max(record.updated_at)));
            if record.is_deleted {
                entry.records.remove(&record.target_address);
                continue;
            }
            let Some(network) = parse_target_address(&record.target_address) else { continue };
            entry.records.insert(
                record.target_address.clone(),
                CachedRecord { network, updated_at: record.updated_at },
            );
        }
        entry.last_synced_at = max_updated;
    }

    /// The networks currently cached for an endpoint, unaggregated and unfiltered.
    pub async fn snapshot(&self, endpoint_id: Uuid) -> Vec<IpNet> {
        self.snapshot_within(endpoint_id, 0, chrono::Utc::now().naive_utc()).await
    }

    /// As [`snapshot`](Self::snapshot), but dropping records older than an endpoint's
    /// `max_age_seconds` retention window.
    ///
    /// `max_age_seconds == 0` means **unlimited** — no cutoff is computed and every cached record
    /// is returned, which is the default and the pre-2026-08-26 behaviour exactly. A negative value
    /// is treated the same way (the column is validated `>= 0` at the API boundary; this is
    /// belt-and-braces so a hand-edited database row cannot make a feed mysteriously empty).
    /// Otherwise a record survives when `updated_at >= now - max_age_seconds`.
    ///
    /// # Why the cutoff is applied here and not during sync
    ///
    /// Filtering at sync time would be simpler but wrong in three ways, all of which an operator
    /// would experience as the feature not working:
    ///
    /// 1. **Config changes wouldn't take effect.** Lowering `max_age_seconds` would leave already-
    ///    cached stale records published until the next sync — up to `ttl_seconds`, or 24h for a
    ///    full sync. Applied here, an edit takes effect on the very next feed fetch.
    /// 2. **It would be destructive and irreversible.** Records dropped at sync time are gone from
    ///    the cache, so *raising* the window back up could not restore them without waiting for a
    ///    full re-sync. Here the cache stays complete and the window is a pure view over it.
    /// 3. **The window would drift.** The cutoff is relative to *now*; a record fresh at sync time
    ///    goes stale minutes later and would keep being served until the next sync happened to
    ///    re-evaluate it. Evaluating per request keeps the window continuously accurate.
    ///
    /// `now` is passed in rather than read here so tests can pin it.
    pub async fn snapshot_within(
        &self,
        endpoint_id: Uuid,
        max_age_seconds: i64,
        now: NaiveDateTime,
    ) -> Vec<IpNet> {
        let guard = self.inner.read().await;
        let Some(entry) = guard.get(&endpoint_id) else { return Vec::new() };

        if max_age_seconds <= 0 {
            return entry.records.values().map(|r| r.network).collect();
        }

        let cutoff = now - chrono::Duration::seconds(max_age_seconds);
        entry
            .records
            .values()
            .filter(|r| r.updated_at >= cutoff)
            .map(|r| r.network)
            .collect()
    }

    /// The `since` cursor for the next differential sync.
    pub async fn last_synced_at(&self, endpoint_id: Uuid) -> Option<NaiveDateTime> {
        self.inner.read().await.get(&endpoint_id).and_then(|e| e.last_synced_at)
    }

    /// Whether a full sync has never run, or ran more than `interval` ago.
    pub async fn full_sync_due(&self, endpoint_id: Uuid, interval: std::time::Duration) -> bool {
        let guard = self.inner.read().await;
        match guard.get(&endpoint_id).and_then(|e| e.last_full_sync_at) {
            Some(at) => at.elapsed() >= interval,
            None => true,
        }
    }

    /// Drops an endpoint's cached state entirely (used when the endpoint itself is deleted).
    pub async fn evict(&self, endpoint_id: Uuid) {
        self.inner.write().await.remove(&endpoint_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(addr: &str, deleted: bool) -> VaultRecord {
        VaultRecord {
            target_address: addr.to_owned(),
            updated_at: NaiveDateTime::parse_from_str("2026-08-11T10:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
            is_deleted: deleted,
        }
    }

    #[tokio::test]
    async fn full_sync_replaces_state_and_drops_orphans() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        cache.apply_full(id, &[record("10.1.2.3/32", false)]).await;
        assert_eq!(cache.snapshot(id).await.len(), 1);

        cache.apply_full(id, &[record("10.1.2.4/32", false)]).await;
        let snap = cache.snapshot(id).await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].to_string(), "10.1.2.4/32");
    }

    #[tokio::test]
    async fn diff_sync_upserts_and_removes_soft_deletes() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        cache.apply_diff(id, &[record("10.1.2.3/32", false), record("10.1.2.4/32", false)]).await;
        assert_eq!(cache.snapshot(id).await.len(), 2);

        cache.apply_diff(id, &[record("10.1.2.3/32", true)]).await;
        let snap = cache.snapshot(id).await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].to_string(), "10.1.2.4/32");
    }

    #[tokio::test]
    async fn last_synced_at_tracks_the_max_updated_at_seen() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        cache.apply_diff(id, &[record("10.1.2.3/32", false)]).await;
        assert!(cache.last_synced_at(id).await.is_some());
    }

    #[tokio::test]
    async fn full_sync_due_is_true_until_a_full_sync_has_run() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        assert!(cache.full_sync_due(id, std::time::Duration::from_secs(86_400)).await);
        cache.apply_full(id, &[]).await;
        assert!(!cache.full_sync_due(id, std::time::Duration::from_secs(86_400)).await);
    }

    // ── max_age_seconds retention window ──────────────────────────────────────

    /// A record with an explicit `updated_at`, so a test can place it precisely relative to a
    /// pinned "now" rather than depending on wall-clock timing.
    fn record_at(addr: &str, updated_at: NaiveDateTime) -> VaultRecord {
        VaultRecord { target_address: addr.to_owned(), updated_at, is_deleted: false }
    }

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").expect("a valid fixture timestamp")
    }

    /// `0` is the documented spelling of "unlimited", and the default every pre-existing endpoint
    /// carries — it must return everything, including a record old enough that any finite window
    /// would drop it.
    #[tokio::test]
    async fn a_max_age_of_zero_means_unlimited_and_filters_nothing() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        let now = at("2026-08-26T12:00:00");
        cache
            .apply_full(
                id,
                &[
                    record_at("10.1.2.3/32", at("2026-08-26T11:59:00")), // 60s old
                    record_at("10.1.2.4/32", at("2020-01-01T00:00:00")), // years old
                ],
            )
            .await;

        assert_eq!(cache.snapshot_within(id, 0, now).await.len(), 2);
    }

    /// The core behaviour: a finite window keeps what is inside it and drops what is outside.
    #[tokio::test]
    async fn a_positive_max_age_drops_only_records_older_than_the_cutoff() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        let now = at("2026-08-26T12:00:00");
        cache
            .apply_full(
                id,
                &[
                    record_at("10.0.0.1/32", at("2026-08-26T11:59:30")), // 30s old — inside 60s
                    record_at("10.0.0.2/32", at("2026-08-26T11:58:00")), // 120s old — outside
                ],
            )
            .await;

        let kept = cache.snapshot_within(id, 60, now).await;
        assert_eq!(kept.len(), 1, "only the record inside the window survives");
        assert_eq!(kept[0].to_string(), "10.0.0.1/32");
    }

    /// The boundary is inclusive (`updated_at >= cutoff`), so a record exactly at the edge is kept.
    /// Worth pinning: an exclusive comparison would silently drop a record every window-length tick
    /// in a system where records are refreshed on a fixed interval equal to the window.
    #[tokio::test]
    async fn a_record_exactly_at_the_cutoff_is_kept() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        let now = at("2026-08-26T12:00:00");
        cache.apply_full(id, &[record_at("10.0.0.1/32", at("2026-08-26T11:59:00"))]).await;

        assert_eq!(cache.snapshot_within(id, 60, now).await.len(), 1, "exactly 60s old, window 60s");
        assert!(
            cache.snapshot_within(id, 59, now).await.is_empty(),
            "one second past the window, it goes"
        );
    }

    /// The window is a *view*, not a mutation: narrowing it then widening it again must restore the
    /// record without a re-sync. This is the property that makes feed-time filtering non-destructive
    /// and is the main reason the cutoff is not applied during sync.
    #[tokio::test]
    async fn narrowing_then_widening_the_window_restores_records_without_a_resync() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        let now = at("2026-08-26T12:00:00");
        cache.apply_full(id, &[record_at("10.0.0.9/32", at("2026-08-26T11:00:00"))]).await;

        assert!(cache.snapshot_within(id, 60, now).await.is_empty(), "an hour old, 60s window");
        assert_eq!(
            cache.snapshot_within(id, 7_200, now).await.len(),
            1,
            "widened to 2h — the record was never evicted, so it comes straight back"
        );
    }

    /// Defensive: the API validates `max_age_seconds >= 0`, but a hand-edited database row must not
    /// be able to turn a feed silently empty. A negative window is treated as unlimited.
    #[tokio::test]
    async fn a_negative_max_age_is_treated_as_unlimited_rather_than_emptying_the_feed() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        let now = at("2026-08-26T12:00:00");
        cache.apply_full(id, &[record_at("10.0.0.1/32", at("2020-01-01T00:00:00"))]).await;

        assert_eq!(cache.snapshot_within(id, -1, now).await.len(), 1);
    }

    /// A differential sync must carry `updated_at` through too, not just a full one — otherwise a
    /// record refreshed by a delta would keep its original age and age out while Vault considers it
    /// current.
    #[tokio::test]
    async fn a_differential_upsert_refreshes_a_records_age() {
        let cache = IpCache::new();
        let id = Uuid::new_v4();
        let now = at("2026-08-26T12:00:00");
        cache.apply_full(id, &[record_at("10.0.0.1/32", at("2026-08-26T10:00:00"))]).await;
        assert!(cache.snapshot_within(id, 60, now).await.is_empty(), "2h old, outside a 60s window");

        cache.apply_diff(id, &[record_at("10.0.0.1/32", at("2026-08-26T11:59:45"))]).await;
        assert_eq!(
            cache.snapshot_within(id, 60, now).await.len(),
            1,
            "the delta re-registered it, so it is inside the window again"
        );
    }

    #[test]
    fn parses_bare_addresses_and_cidrs() {
        assert_eq!(parse_target_address("192.168.1.1").unwrap().to_string(), "192.168.1.1/32");
        assert_eq!(parse_target_address("192.168.1.0/24").unwrap().to_string(), "192.168.1.0/24");
        assert!(parse_target_address("not-an-ip").is_none());
    }

    // ── Concurrent access ────────────────────────────────────────────────────
    //
    // `IpCache` is shared, via `Arc<RwLock<...>>`, between every public feed request and the
    // background sync worker — exactly the shape where a deadlock or a torn read would be a
    // production incident rather than a test failure. `tokio::sync::RwLock` behind a clean async
    // API (no method holds a guard across a call back into `self`) makes a *self*-deadlock
    // essentially impossible by construction; what these tests actually exercise is that heavy,
    // real *parallelism* (`flavor = "multi_thread"`, so tasks genuinely run on different OS
    // threads, not just interleaved cooperatively on one) neither hangs nor corrupts state, and
    // that the `tokio::time::timeout` wrapper would catch it if a future change broke that.

    fn record_with_updated_at(addr: &str, minute: u32) -> VaultRecord {
        VaultRecord {
            target_address: addr.to_owned(),
            updated_at: NaiveDateTime::parse_from_str("2026-08-11T10:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                + chrono::Duration::minutes(minute as i64),
            is_deleted: false,
        }
    }

    /// Many writer tasks (full syncs, differential syncs, evictions) and many more reader tasks
    /// (snapshot, `full_sync_due`, `last_synced_at`) all hammer a small, shared set of endpoint ids
    /// concurrently across real OS threads. Bounded by an explicit timeout so a regression that
    /// reintroduced a deadlock fails fast and loudly rather than hanging the test suite forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn high_concurrency_mixed_read_write_does_not_deadlock_or_panic() {
        let cache = IpCache::new();
        let endpoint_ids: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();

        let mut tasks = tokio::task::JoinSet::new();

        for w in 0..20u32 {
            let cache = cache.clone();
            let ids = endpoint_ids.clone();
            tasks.spawn(async move {
                for i in 0..200u32 {
                    let id = ids[((w * 200 + i) as usize) % ids.len()];
                    match i % 10 {
                        0 => cache.evict(id).await,
                        n if n % 2 == 0 => {
                            cache.apply_full(id, &[record_with_updated_at("10.0.0.1/32", i)]).await
                        }
                        _ => cache.apply_diff(id, &[record_with_updated_at("10.0.0.2/32", i)]).await,
                    }
                }
            });
        }

        for r in 0..50u32 {
            let cache = cache.clone();
            let ids = endpoint_ids.clone();
            tasks.spawn(async move {
                for i in 0..200u32 {
                    let id = ids[((r * 200 + i) as usize) % ids.len()];
                    let _ = cache.snapshot(id).await;
                    let _ = cache.full_sync_due(id, std::time::Duration::from_secs(1)).await;
                    let _ = cache.last_synced_at(id).await;
                }
            });
        }

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while let Some(result) = tasks.join_next().await {
                result.expect("no writer or reader task panicked");
            }
        })
        .await;
        assert!(outcome.is_ok(), "concurrent cache access deadlocked: did not finish within 30s");

        // The cache must still be fully usable afterward — a poisoned or corrupted lock would
        // hang or panic here too.
        for id in &endpoint_ids {
            let snap = cache.snapshot(*id).await;
            assert!(snap.len() <= 2, "each endpoint only ever received two distinct addresses");
        }
    }

    /// Complementary to the mixed stress test above: confirms writes to one endpoint never leak
    /// into another's snapshot even under heavy concurrent pressure — a `HashMap<Uuid,
    /// EndpointCache>` behind one shared lock makes cross-contamination structurally impossible,
    /// but "impossible by construction" is exactly the kind of claim worth actually running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_writes_to_distinct_endpoints_never_cross_contaminate() {
        let cache = IpCache::new();
        let endpoint_ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();

        let mut tasks = tokio::task::JoinSet::new();
        for (i, id) in endpoint_ids.iter().copied().enumerate() {
            let cache = cache.clone();
            let addr = format!("10.{}.{}.1/32", i / 256, i % 256);
            tasks.spawn(async move {
                for _ in 0..50 {
                    cache.apply_full(id, &[VaultRecord {
                        target_address: addr.clone(),
                        updated_at: chrono::Utc::now().naive_utc(),
                        is_deleted: false,
                    }]).await;
                }
                (id, addr)
            });
        }

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut expected = std::collections::HashMap::new();
            while let Some(result) = tasks.join_next().await {
                let (id, addr) = result.expect("no task panicked");
                expected.insert(id, addr);
            }
            expected
        })
        .await
        .expect("concurrent per-endpoint writes deadlocked: did not finish within 30s");

        for (id, addr) in outcome {
            let snap = cache.snapshot(id).await;
            assert_eq!(snap.len(), 1, "endpoint {id} must hold exactly its own one address");
            assert_eq!(snap[0].to_string(), addr, "endpoint {id} must not see another endpoint's write");
        }
    }
}
