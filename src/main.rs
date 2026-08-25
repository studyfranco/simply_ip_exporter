//! `simply_ip_exporter` entry point: database bootstrap, master key provisioning, HTTP server,
//! and graceful shutdown.

use std::net::SocketAddr;

use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use simply_ip_exporter::{
    api, config, config::RuntimeConfig, create_app, crypto, db, entities, groups, state::AppState, sync,
};
use tokio::net::TcpListener;
use uuid::Uuid;

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Received shutdown signal.");
}

/// Mints the bootstrap Master API key if the table holds none, per `AGENT.MD`.
async fn bootstrap_master_key(
    db: &DatabaseConnection,
    cipher: &crypto::SecretCipher,
    initial_master_key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use entities::{api_key, prelude::ApiKey};

    if ApiKey::find().filter(api_key::Column::IsMaster.eq(true)).one(db).await?.is_some() {
        return Ok(());
    }

    let plaintext_key = match initial_master_key {
        Some(fixed) => {
            tracing::warn!(
                "INITIAL_MASTER_KEY is set: using the provided value instead of generating one. \
                 Intended for deterministic test/CI bootstrap only."
            );
            fixed.to_owned()
        }
        None => api::support::generate_random_key(),
    };
    let key_hash = api::support::hash_key(&plaintext_key);
    let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0,::/0".to_owned());
    let prefix: String = plaintext_key.chars().take(8).collect();
    let now = chrono::Utc::now().naive_utc();

    // As with INITIAL_MASTER_KEY above: deterministic test/CI bootstrap only, so a script never
    // has to scrape the signing secret back out of stdout.
    let signing_secret = match std::env::var("INITIAL_MASTER_SIGNING_SECRET") {
        Ok(fixed) if !fixed.is_empty() => {
            tracing::warn!(
                "INITIAL_MASTER_SIGNING_SECRET is set: using the provided value instead of \
                 generating one. Intended for deterministic test/CI bootstrap only."
            );
            fixed
        }
        _ => crypto::generate_signing_secret(),
    };

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set("System Master".to_owned()),
        prefix: Set(prefix),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(cipher.seal(&signing_secret)?)),
        bound_ips: Set(Some(bound_ip.clone())),
        is_master: Set(true),
        can_manage_keys: Set(true),
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(db).await?;

    tracing::info!(
        "\n╔══════════════════════════════════════════════════════════════╗\n\
         ║  BOOTSTRAP: Master API Key Generated                            \n\
         ║  X-API-Key:        {}  \n\
         ║  Signing Secret:   {}  \n\
         ║  Bound IPs:        {}  \n\
         ║  Shown once. Store the key and signing secret securely!         \n\
         ╚══════════════════════════════════════════════════════════════╝",
        plaintext_key,
        signing_secret,
        bound_ip
    );

    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    Ok(())
}

/// Why [`verify_encryption_key`] refused to let the process start.
#[derive(Debug)]
struct EncryptionKeyMismatch(crypto::CryptoError);

impl std::fmt::Display for EncryptionKeyMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EXPORTER_ENCRYPTION_KEY does not match the key this database's secrets were sealed \
             with ({}). Refusing to start: continuing would leave every stored signing secret \
             unreadable and silently break authentication for every API key. Restore the correct \
             EXPORTER_ENCRYPTION_KEY, or if rotating it intentionally, re-seal every key's \
             signing_secret with the new key first.",
            self.0
        )
    }
}

impl std::error::Error for EncryptionKeyMismatch {}

/// Verifies `EXPORTER_ENCRYPTION_KEY` can actually decrypt what is already on disk, using the
/// Master key's sealed `signing_secret` as a canary.
///
/// [`crypto::SecretCipher::from_env`] only validates that the configured key is 64 hex characters
/// — a syntactically valid key that simply doesn't match the one secrets on disk were sealed with
/// passes it fine. Left unchecked, that mismatch stays invisible at boot and only surfaces later,
/// request by request, as every caller's signature verification quietly fails with an opaque `401`
/// (`recover_signing_secret` in `middleware.rs`). Run once at boot, right after the Master row is
/// guaranteed to exist (bootstrapped fresh, in which case this trivially passes since it was just
/// sealed with this same cipher; or pre-existing, in which case a mismatch here means every other
/// stored secret is equally unreadable).
async fn verify_encryption_key(
    db: &DatabaseConnection,
    cipher: &crypto::SecretCipher,
) -> Result<(), Box<dyn std::error::Error>> {
    use entities::{api_key, prelude::ApiKey};

    let Some(master) = ApiKey::find().filter(api_key::Column::IsMaster.eq(true)).one(db).await?
    else {
        // bootstrap_master_key runs before this and always leaves exactly one master row behind;
        // absence here means that invariant broke, which pin_at_boot will report properly next.
        return Ok(());
    };
    let Some(stored) = master.signing_secret.as_deref() else { return Ok(()) };

    cipher.open(stored).map_err(EncryptionKeyMismatch)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    let config = match RuntimeConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    let initial_master_key =
        match config::validate_initial_master_key(std::env::var("INITIAL_MASTER_KEY").ok().as_deref()) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!("{e}");
                std::process::exit(1);
            }
        };

    let db_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://simply_ip_exporter.db?mode=rwc".to_owned());

    tracing::info!("Connecting to database...");
    let db: DatabaseConnection = db::connect(&db_url).await?;

    if let Err(e) = db::apply_sqlite_pragmas(&db).await {
        tracing::warn!("Could not apply the SQLite concurrency pragmas: {e}. Starting anyway.");
    }

    db::run_migrations(&db).await?;

    let cipher = crypto::SecretCipher::from_env()?;
    if cipher.is_encrypting() {
        tracing::info!("Secrets are encrypted at rest (EXPORTER_ENCRYPTION_KEY is configured).");
    } else {
        tracing::warn!(
            "EXPORTER_ENCRYPTION_KEY is not set: API key signing secrets are stored unencrypted. \
             Generate one with `openssl rand -hex 32`."
        );
    }

    bootstrap_master_key(&db, &cipher, initial_master_key.as_deref()).await?;
    if let Err(e) = verify_encryption_key(&db, &cipher).await {
        tracing::error!("{e}");
        std::process::exit(1);
    }

    let state = AppState::new(db, std::sync::Arc::new(config), std::sync::Arc::new(cipher));

    state.master_pin.pin_at_boot(&state.db).await?;

    // Resolve every configured TRUSTED_PROXIES hostname once, now, so a typo is reported at boot
    // rather than discovered as an unexplained 403 later. Detached and non-blocking: an
    // unresolvable entry is retried after a grace period and disabled meanwhile, never a reason to
    // refuse to start — see `config::TrustedProxies::prime_with_grace`.
    state.config.trusted_proxies.prime_with_grace();

    if state.vault_client.is_some() {
        tracing::info!("simply_ip_vault sync is configured; starting the background sync worker.");
    } else {
        tracing::warn!(
            "VAULT_BASE_URL/VAULT_API_KEY/VAULT_SIGNING_SECRET are not fully set: the sync worker \
             is idle and feeds will stay empty until Vault sync is configured."
        );
    }
    let sync_handle = sync::spawn_sync_worker(state.clone());
    // Same Vault-configured-or-not gate as the sync worker above: with no Vault client, every
    // cleanup pass is a no-op anyway (see `groups::cleanup_stale_group_permissions`), so the
    // worker is still spawned (cheap: it just sleeps) rather than conditionally started, matching
    // this crate's existing preference for one code path over a start/don't-start branch.
    let group_cleanup_handle = groups::spawn_group_permission_cleanup_worker(state.clone());

    let app = create_app(state);

    let addr = config::resolve_bind_addr();
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr().unwrap_or(addr);
    tracing::info!("simply_ip_exporter listening on http://{}", bound);

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    sync_handle.abort();
    group_cleanup_handle.abort();
    tracing::info!("Graceful shutdown complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    const KEY_A: &str = "0f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a6978";

    fn key_b() -> String {
        "f".repeat(64)
    }

    async fn fresh_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        db::run_migrations(&db).await.expect("migrations apply");
        db
    }

    #[tokio::test]
    async fn a_freshly_bootstrapped_master_passes_the_canary_check() {
        let db = fresh_db().await;
        let cipher = crypto::SecretCipher::from_hex_key(KEY_A).expect("valid key");
        bootstrap_master_key(&db, &cipher, None).await.expect("bootstrap succeeds");

        assert!(verify_encryption_key(&db, &cipher).await.is_ok());
    }

    #[tokio::test]
    async fn a_mismatched_key_is_refused_after_restart_not_silently_accepted() {
        let db = fresh_db().await;
        let sealing_cipher = crypto::SecretCipher::from_hex_key(KEY_A).expect("valid key");
        bootstrap_master_key(&db, &sealing_cipher, None).await.expect("bootstrap succeeds");

        // Simulates a restart with the wrong EXPORTER_ENCRYPTION_KEY against the same database:
        // bootstrap_master_key sees the existing master row and does nothing, so this canary check
        // is the only thing standing between a key mismatch and silent per-request auth failures.
        let wrong_cipher = crypto::SecretCipher::from_hex_key(&key_b()).expect("valid key");
        let err = verify_encryption_key(&db, &wrong_cipher).await.unwrap_err();
        assert!(err.to_string().contains("EXPORTER_ENCRYPTION_KEY does not match"));
    }

    #[tokio::test]
    async fn plaintext_mode_is_unaffected_by_the_canary_check() {
        let db = fresh_db().await;
        let cipher = crypto::SecretCipher::Plaintext;
        bootstrap_master_key(&db, &cipher, None).await.expect("bootstrap succeeds");

        assert!(verify_encryption_key(&db, &cipher).await.is_ok());
    }

    #[tokio::test]
    async fn no_master_row_is_not_this_checks_problem_to_report() {
        // pin_at_boot (run right after this check in main()) is what reports a missing master row;
        // this check should stay quiet rather than duplicating that diagnosis.
        let db = fresh_db().await;
        let cipher = crypto::SecretCipher::from_hex_key(KEY_A).expect("valid key");
        assert!(verify_encryption_key(&db, &cipher).await.is_ok());
    }
}
