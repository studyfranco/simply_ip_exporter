//! `simply_ip_exporter` entry point: database bootstrap, master key provisioning, HTTP server,
//! and graceful shutdown.

use std::net::SocketAddr;

use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use simply_ip_exporter::{api, config, config::RuntimeConfig, create_app, crypto, db, entities, state::AppState, sync};
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
    let signing_secret = crypto::generate_signing_secret();

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

    let state = AppState::new(db, std::sync::Arc::new(config), std::sync::Arc::new(cipher));

    state.master_pin.pin_at_boot(&state.db).await?;

    if state.vault_client.is_some() {
        tracing::info!("simply_ip_vault sync is configured; starting the background sync worker.");
    } else {
        tracing::warn!(
            "VAULT_BASE_URL/VAULT_API_KEY/VAULT_SIGNING_SECRET are not fully set: the sync worker \
             is idle and feeds will stay empty until Vault sync is configured."
        );
    }
    let sync_handle = sync::spawn_sync_worker(state.clone());

    let app = create_app(state);

    let addr = config::resolve_bind_addr();
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr().unwrap_or(addr);
    tracing::info!("simply_ip_exporter listening on http://{}", bound);

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    sync_handle.abort();
    tracing::info!("Graceful shutdown complete.");
    Ok(())
}
