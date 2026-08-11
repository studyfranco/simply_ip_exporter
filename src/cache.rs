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
            entry.records.insert(record.target_address.clone(), CachedRecord { network });
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
            entry.records.insert(record.target_address.clone(), CachedRecord { network });
        }
        entry.last_synced_at = max_updated;
    }

    /// The networks currently cached for an endpoint, unaggregated and unfiltered.
    pub async fn snapshot(&self, endpoint_id: Uuid) -> Vec<IpNet> {
        let guard = self.inner.read().await;
        guard
            .get(&endpoint_id)
            .map(|e| e.records.values().map(|r| r.network).collect())
            .unwrap_or_default()
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

    #[test]
    fn parses_bare_addresses_and_cidrs() {
        assert_eq!(parse_target_address("192.168.1.1").unwrap().to_string(), "192.168.1.1/32");
        assert_eq!(parse_target_address("192.168.1.0/24").unwrap().to_string(), "192.168.1.0/24");
        assert!(parse_target_address("not-an-ip").is_none());
    }
}
