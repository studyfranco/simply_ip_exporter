//! Background hygiene for `vault_group_permissions`: periodically drops grants that reference a
//! Vault group Vault no longer has.
//!
//! A grant is deliberately *not* re-validated on every use (see
//! `entities::vault_group_permission`'s module doc comment) — this worker is the only place a
//! stale grant is ever removed, and it does so conservatively: a failed or unreachable Vault call
//! skips the cycle entirely rather than treating "couldn't ask" as "doesn't exist" and deleting
//! everything.

use std::collections::HashSet;
use std::time::Duration;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::entities::{prelude::VaultGroupPermission, vault_group_permission};
use crate::state::AppState;

/// Once a month. Named per the user's own framing of how often this needs to run — Vault-side
/// group deletions are rare and the consequence of a stale grant lingering a while longer is
/// nothing worse than an operator being able to name an already-gone group in `vault_groups` (the
/// endpoint sync itself would then just see that group return nothing from Vault, same as any
/// other empty/unreadable group), not a security issue that needs faster cleanup.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Spawns the background cleanup loop, returning its join handle for graceful shutdown. Runs once
/// immediately (so a long-lived instance doesn't wait a full month for its first pass) and then
/// every [`CLEANUP_INTERVAL`] thereafter.
pub fn spawn_group_permission_cleanup_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            cleanup_stale_group_permissions(&state).await;
            tokio::time::sleep(CLEANUP_INTERVAL).await;
        }
    })
}

/// One cleanup pass: lists Vault's current groups and removes every local grant whose
/// `vault_group_id` isn't among them. Skips entirely — touching nothing — when Vault sync isn't
/// configured or a live call to Vault fails for any reason (network error, timeout, non-2xx);
/// only a *successful* listing is trusted enough to say a group is really gone.
async fn cleanup_stale_group_permissions(state: &AppState) {
    let Some(client) = state.vault_client.as_ref() else {
        return;
    };

    let live_groups = match client.list_groups().await {
        Ok(groups) => groups,
        Err(crate::vault_client::VaultError::Status(s)) if s == reqwest::StatusCode::FORBIDDEN => {
            tracing::info!(
                "Skipping this cycle's Vault-group permission cleanup: Vault API key lacks group listing permissions (HTTP 403 Forbidden). Existing grants are left untouched."
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                "Skipping this cycle's Vault-group permission cleanup: could not list Vault's \
                 groups ({e}). Existing grants are left untouched."
            );
            return;
        }
    };
    let live_ids: HashSet<Uuid> = live_groups.into_iter().map(|g| g.id).collect();

    let all_grants = match VaultGroupPermission::find().all(&state.db).await {
        Ok(grants) => grants,
        Err(e) => {
            tracing::warn!("Skipping this cycle's Vault-group permission cleanup: {e}");
            return;
        }
    };
    let stale_ids: Vec<Uuid> =
        all_grants.iter().filter(|g| !live_ids.contains(&g.vault_group_id)).map(|g| g.id).collect();
    if stale_ids.is_empty() {
        return;
    }

    let count = stale_ids.len();
    match VaultGroupPermission::delete_many()
        .filter(vault_group_permission::Column::Id.is_in(stale_ids))
        .exec(&state.db)
        .await
    {
        Ok(_) => {
            tracing::info!(
                "Removed {count} stale Vault-group permission grant(s) referencing a group Vault \
                 no longer has."
            );
        }
        Err(e) => tracing::warn!("Failed to remove stale Vault-group permission grant(s): {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite always opens");
        crate::migration::Migrator::up(&db, None).await.expect("migrations apply");
        db
    }

    fn test_state(db: &DatabaseConnection, vault_base_url: Option<String>) -> AppState {
        let config = crate::config::RuntimeConfig {
            vault_base_url,
            vault_api_key: Some("key".to_owned()),
            vault_signing_secret: Some("secret".to_owned()),
            ..crate::config::RuntimeConfig::default()
        };
        AppState::new(db.clone(), std::sync::Arc::new(config), std::sync::Arc::new(crate::crypto::SecretCipher::Plaintext))
    }

    async fn insert_grant(db: &DatabaseConnection, vault_group_id: Uuid, name: &str) {
        let model = vault_group_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(insert_key(db).await),
            vault_group_id: Set(vault_group_id),
            vault_group_name: Set(name.to_owned()),
            created_at: Set(Utc::now().naive_utc()),
        };
        model.insert(db).await.expect("insert succeeds");
    }

    /// A grant's `api_key_id` is a real foreign key (`ON DELETE CASCADE`), so it needs a real
    /// `api_keys` row to point at.
    async fn insert_key(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        let model = crate::entities::api_key::ActiveModel {
            id: Set(id),
            name: Set("Cleanup Test Key".to_owned()),
            prefix: Set("clnup123".to_owned()),
            key_hash: Set(Uuid::new_v4().simple().to_string()),
            signing_secret: Set(None),
            bound_ips: Set(None),
            is_master: Set(false),
            can_manage_keys: Set(false),
            parent_key_id: Set(None),
            owner_key_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        model.insert(db).await.expect("insert succeeds");
        id
    }

    async fn spawn_mock_vault_groups(groups: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{Router, routing::get};

        let app = Router::new().route(
            "/api/groups",
            get(move || {
                let groups = groups.clone();
                async move { axum::Json(groups) }
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

    async fn spawn_mock_vault_error(status: axum::http::StatusCode) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{Router, routing::get};

        let app = Router::new().route("/api/groups", get(move || async move { status }));
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn without_a_configured_vault_client_nothing_is_touched() {
        let db = test_db().await;
        let group_id = Uuid::new_v4();
        insert_grant(&db, group_id, "some_group").await;
        let state = test_state(&db, None);

        cleanup_stale_group_permissions(&state).await;

        let remaining = VaultGroupPermission::find().all(&db).await.expect("query succeeds");
        assert_eq!(remaining.len(), 1, "no Vault client configured means no cleanup at all, not a wipe");
    }

    #[tokio::test]
    async fn an_unreachable_vault_leaves_every_grant_untouched() {
        let db = test_db().await;
        let group_id = Uuid::new_v4();
        insert_grant(&db, group_id, "some_group").await;
        let (url, _server) = spawn_mock_vault_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let state = test_state(&db, Some(url));

        cleanup_stale_group_permissions(&state).await;

        let remaining = VaultGroupPermission::find().all(&db).await.expect("query succeeds");
        assert_eq!(remaining.len(), 1, "a failed Vault call must not be treated as \"the group is gone\"");
    }

    #[tokio::test]
    async fn a_403_forbidden_from_vault_leaves_every_grant_untouched() {
        let db = test_db().await;
        let group_id = Uuid::new_v4();
        insert_grant(&db, group_id, "some_group").await;
        let (url, _server) = spawn_mock_vault_error(axum::http::StatusCode::FORBIDDEN).await;
        let state = test_state(&db, Some(url));

        cleanup_stale_group_permissions(&state).await;

        let remaining = VaultGroupPermission::find().all(&db).await.expect("query succeeds");
        assert_eq!(remaining.len(), 1, "a 403 Forbidden response must leave grants untouched");
    }

    #[tokio::test]
    async fn a_grant_for_a_group_vault_still_has_survives() {
        let db = test_db().await;
        let group_id = Uuid::new_v4();
        insert_grant(&db, group_id, "still_here").await;
        let (url, _server) = spawn_mock_vault_groups(serde_json::json!([
            {"id": group_id, "name": "still_here"}
        ]))
        .await;
        let state = test_state(&db, Some(url));

        cleanup_stale_group_permissions(&state).await;

        let remaining = VaultGroupPermission::find().all(&db).await.expect("query succeeds");
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn a_grant_for_a_group_vault_no_longer_has_is_removed() {
        let db = test_db().await;
        let gone_group_id = Uuid::new_v4();
        let live_group_id = Uuid::new_v4();
        insert_grant(&db, gone_group_id, "deleted_in_vault").await;
        insert_grant(&db, live_group_id, "still_here").await;
        let (url, _server) = spawn_mock_vault_groups(serde_json::json!([
            {"id": live_group_id, "name": "still_here"}
        ]))
        .await;
        let state = test_state(&db, Some(url));

        cleanup_stale_group_permissions(&state).await;

        let remaining = VaultGroupPermission::find().all(&db).await.expect("query succeeds");
        assert_eq!(remaining.len(), 1, "only the grant for the still-existing group must survive");
        assert_eq!(remaining[0].vault_group_id, live_group_id);
    }
}
