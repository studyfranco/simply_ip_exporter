//! Application state shared by every handler and background worker.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::cache::IpCache;
use crate::config::RuntimeConfig;
use crate::crypto::SecretCipher;
use crate::master::MasterPin;
use crate::ratelimit::RateLimiter;
use crate::replay::ReplayGuard;
use crate::vault_client::VaultClient;

/// Global application state. Cheap to clone: the database handle is an internally-refcounted
/// pool, and every other field is shared behind [`Arc`].
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool (configuration only — never IP data).
    pub db: DatabaseConnection,
    /// Immutable runtime configuration, read from the environment at startup.
    pub config: Arc<RuntimeConfig>,
    /// Protects `api_keys.signing_secret` at rest.
    pub cipher: Arc<SecretCipher>,
    /// Enforces single use of `CANONICAL_V1` signatures on `/api/*` inside the anti-replay window.
    pub replay_guard: Arc<ReplayGuard>,
    /// The Master key identity, fixed for the life of the process.
    pub master_pin: Arc<MasterPin>,
    /// Strictly in-memory cache of aggregated IP records per endpoint.
    pub ip_cache: IpCache,
    /// Per-source-IP throttle for the public feed endpoint.
    pub rate_limiter: Arc<RateLimiter>,
    /// Signed HTTP client for `simply_ip_vault`, or `None` when sync is not configured.
    pub vault_client: Option<Arc<VaultClient>>,
}

impl AppState {
    /// Builds state around an existing database connection.
    pub fn new(db: DatabaseConnection, config: Arc<RuntimeConfig>, cipher: Arc<SecretCipher>) -> Self {
        let replay_guard = Arc::new(ReplayGuard::new(config.signature_max_age_seconds));
        let vault_client = VaultClient::from_config(&config).map(Arc::new);
        Self {
            db,
            config,
            cipher,
            replay_guard,
            master_pin: Arc::new(MasterPin::new()),
            ip_cache: IpCache::new(),
            rate_limiter: Arc::new(RateLimiter::new()),
            vault_client,
        }
    }

    /// Builds state whose Master identity is fixed without a database lookup. Test-facing.
    pub fn with_pinned_master(mut self, master_key_id: uuid::Uuid) -> Self {
        self.master_pin = Arc::new(MasterPin::pinned_to(master_key_id));
        self
    }
}
