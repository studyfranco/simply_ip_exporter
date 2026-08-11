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

/// Spawns the background sync loop, returning its join handle for graceful shutdown.
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
}
