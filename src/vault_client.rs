//! Outbound `simply_ip_vault` API client: `CANONICAL_V1` HMAC-signed `GET /api/ips` requests for
//! the hybrid differential/full sync protocol.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::NaiveDateTime;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::crypto::{canonical_v1_payload, compute_signature};

/// Hard ceiling on how long one sync request may take, covering connect, send, and receive.
///
/// Without this, a Vault that accepts a TCP connection and then never answers (a black-holed
/// route, a misbehaving proxy in front of it) would hang the request forever — `reqwest::Client`
/// has no default timeout. The background sync worker awaits one endpoint's fetch at a time
/// (`sync::sync_all_endpoints`), so an indefinitely hanging request would silently stall every
/// other endpoint's sync ticks behind it rather than surfacing as the fast, logged failure the
/// "keep serving the cache" resilience contract expects.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// One record as returned by Vault's `GET /api/ips` contract.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultApiRecord {
    /// The IP address or CIDR range, exactly as Vault stored it.
    pub target_address: String,
    /// Last activity timestamp, UTC naive ISO-8601.
    pub updated_at: NaiveDateTime,
    /// Whether this is a soft-deleted tombstone (only present with `include_deleted=true`).
    #[serde(default)]
    pub is_deleted: bool,
}

/// One group as returned by Vault's `GET /api/groups` contract. Only the two fields this crate
/// actually uses (grant enforcement matches by name; display shows both) — Vault's own response
/// carries more (`group_type`, `description`, `owner_key_id`, `created_at`), silently ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultGroup {
    /// The group's id, exactly as Vault assigned it.
    pub id: Uuid,
    /// The group's name, used both for display and for matching against a grant's
    /// `vault_group_name` snapshot.
    pub name: String,
}

/// Failure modes for a Vault sync request.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The client is not configured (`VAULT_BASE_URL`/`VAULT_API_KEY`/`VAULT_SIGNING_SECRET`).
    #[error("simply_ip_vault client is not configured")]
    NotConfigured,
    /// The HTTP request itself failed (network error, timeout, connection refused).
    #[error("request to simply_ip_vault failed: {0}")]
    Request(#[from] reqwest::Error),
    /// Vault answered with a non-success status.
    #[error("simply_ip_vault returned HTTP {0}")]
    Status(reqwest::StatusCode),
}

/// A signed HTTP client for `simply_ip_vault`.
#[derive(Clone)]
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    signing_secret: String,
    last_timestamp: Arc<AtomicI64>,
}

impl VaultClient {
    /// Builds a client from the runtime configuration, or `None` if Vault sync is not configured
    /// or the underlying HTTP client cannot be built (a TLS backend failure — not reachable in
    /// practice with the `rustls` feature this crate compiles, but reported rather than unwrapped).
    pub fn from_config(config: &crate::config::RuntimeConfig) -> Option<Self> {
        let (base_url, api_key, signing_secret) = (
            config.vault_base_url.clone()?,
            config.vault_api_key.clone()?,
            config.vault_signing_secret.clone()?,
        );
        let http = reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build().ok()?;
        let last_timestamp = Arc::new(AtomicI64::new(0));
        Some(Self { http, base_url, api_key, signing_secret, last_timestamp })
    }

    /// Fetches IP records for `groups`. When `since` is set, performs a differential query
    /// (`include_deleted=true`); otherwise performs a full, unconstrained query.
    pub async fn fetch_ips(
        &self,
        groups: &str,
        since: Option<NaiveDateTime>,
    ) -> Result<Vec<VaultApiRecord>, VaultError> {
        let mut path_and_query = format!("/api/ips?groups={}", urlencode(groups));
        if let Some(since) = since {
            path_and_query.push_str(&format!(
                "&since={}&include_deleted=true",
                urlencode(&since.and_utc().timestamp().to_string())
            ));
        }
        self.signed_get(&path_and_query).await
    }

    /// Lists every group Vault currently has, restricted (Vault-side) to what this crate's own
    /// Vault key can read. Used both to populate the Master-only "grant a key read access to a
    /// group" UI and by `groups::spawn_group_permission_cleanup_worker` to find grants whose
    /// group Vault no longer has.
    pub async fn list_groups(&self) -> Result<Vec<VaultGroup>, VaultError> {
        self.signed_get("/api/groups").await
    }

    /// Signs and sends one `CANONICAL_V1` `GET` request, deserializing a successful body as `T`.
    /// Shared by every read this client makes — `fetch_ips` and `list_groups` differ only in path
    /// and response shape, not in how a request gets signed or a non-2xx/malformed body is turned
    /// into a [`VaultError`].
    async fn signed_get<T: DeserializeOwned>(&self, path_and_query: &str) -> Result<T, VaultError> {
        let now = chrono::Utc::now().timestamp();
        let mut ts = now;
        let _ = self.last_timestamp.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            let next = if now > last || last.saturating_sub(now) >= 5 {
                now
            } else {
                last + 1
            };
            ts = next;
            Some(next)
        });
        let timestamp = ts.to_string();
        let payload = canonical_v1_payload("GET", path_and_query, &timestamp, b"");
        let signature = compute_signature(&self.signing_secret, &payload)
            .ok_or(VaultError::Status(reqwest::StatusCode::INTERNAL_SERVER_ERROR))?;

        let url = format!("{}{}", self.base_url, path_and_query);
        let response = self
            .http
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("X-Timestamp", &timestamp)
            .header("X-Signature-256", &signature)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultError::Status(response.status()));
        }

        Ok(response.json::<T>().await?)
    }
}

/// Minimal query-string percent-encoding, sufficient for group names/UUIDs and Unix timestamps
/// (comma, alphanumeric, `-`).
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b',' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_passes_through_safe_characters() {
        assert_eq!(urlencode("g1,g2-3_a.b~c"), "g1,g2-3_a.b~c");
    }

    #[test]
    fn urlencode_escapes_unsafe_characters() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a/b"), "a%2Fb");
    }

    #[test]
    fn a_client_with_missing_configuration_is_none() {
        let config = crate::config::RuntimeConfig::default();
        assert!(VaultClient::from_config(&config).is_none());
    }

    #[test]
    fn a_fully_configured_client_is_built() {
        let config = crate::config::RuntimeConfig {
            vault_base_url: Some("http://vault:3000".to_owned()),
            vault_api_key: Some("key".to_owned()),
            vault_signing_secret: Some("secret".to_owned()),
            ..crate::config::RuntimeConfig::default()
        };
        assert!(VaultClient::from_config(&config).is_some());
    }

    // ── The Vault error spectrum: HTTP-status mapping and connection failure ───

    fn client_at(base_url: String) -> VaultClient {
        let config = crate::config::RuntimeConfig {
            vault_base_url: Some(base_url),
            vault_api_key: Some("key".to_owned()),
            vault_signing_secret: Some("secret".to_owned()),
            ..crate::config::RuntimeConfig::default()
        };
        VaultClient::from_config(&config).expect("fully configured")
    }

    /// Boots a throwaway HTTP server on an OS-assigned loopback port that answers `/api/ips` and
    /// `/api/groups` with the same fixed status and JSON body, and returns its base URL alongside
    /// the task handle.
    async fn spawn_mock_vault(
        status: axum::http::StatusCode,
        body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{Router, routing::get};

        let ips_body = body.clone();
        let groups_body = body;
        let app = Router::new()
            .route(
                "/api/ips",
                get(move || {
                    let body = ips_body.clone();
                    async move { (status, axum::Json(body)) }
                }),
            )
            .route(
                "/api/groups",
                get(move || {
                    let body = groups_body.clone();
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

    #[tokio::test]
    async fn a_401_from_vault_is_reported_as_a_status_error_naming_401() {
        let (url, _server) =
            spawn_mock_vault(axum::http::StatusCode::UNAUTHORIZED, serde_json::json!({"error": "bad key"}))
                .await;
        let client = client_at(url);
        let err = client.fetch_ips("g1", None).await.expect_err("401 must not be Ok");
        assert!(matches!(err, VaultError::Status(s) if s == reqwest::StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn a_403_from_vault_is_reported_as_a_status_error_naming_403() {
        let (url, _server) = spawn_mock_vault(
            axum::http::StatusCode::FORBIDDEN,
            serde_json::json!({"error": "client ip not allowed"}),
        )
        .await;
        let client = client_at(url);
        let err = client.fetch_ips("g1", None).await.expect_err("403 must not be Ok");
        assert!(matches!(err, VaultError::Status(s) if s == reqwest::StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn a_500_from_vault_is_reported_as_a_status_error() {
        let (url, _server) = spawn_mock_vault(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "internal"}),
        )
        .await;
        let client = client_at(url);
        let err = client.fetch_ips("g1", None).await.expect_err("500 must not be Ok");
        assert!(matches!(err, VaultError::Status(s) if s == reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[tokio::test]
    async fn a_malformed_json_body_on_an_otherwise_successful_response_is_a_request_error() {
        // Valid 200, but a body shaped nothing like `Vec<VaultApiRecord>` — the deserialization
        // failure surfaces as VaultError::Request via the `#[from] reqwest::Error` conversion.
        let (url, _server) =
            spawn_mock_vault(axum::http::StatusCode::OK, serde_json::json!({"not": "a list"})).await;
        let client = client_at(url);
        let err = client.fetch_ips("g1", None).await.expect_err("malformed body must not be Ok");
        assert!(matches!(err, VaultError::Request(_)));
    }

    #[tokio::test]
    async fn a_successful_response_with_valid_records_is_ok() {
        let (url, _server) = spawn_mock_vault(
            axum::http::StatusCode::OK,
            serde_json::json!([
                {"target_address": "8.8.8.8/32", "updated_at": "2026-08-11T10:00:00", "is_deleted": false}
            ]),
        )
        .await;
        let client = client_at(url);
        let records = client.fetch_ips("g1", None).await.expect("a valid 200 body must parse");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target_address, "8.8.8.8/32");
    }

    #[tokio::test]
    async fn list_groups_parses_a_successful_response() {
        let group_id = Uuid::new_v4();
        let (url, _server) = spawn_mock_vault(
            axum::http::StatusCode::OK,
            serde_json::json!([
                {"id": group_id, "name": "pfBlocker_Blacklist", "group_type": "banlist", "owner_key_id": null, "created_at": "2026-08-11T10:00:00"}
            ]),
        )
        .await;
        let client = client_at(url);
        let groups = client.list_groups().await.expect("a valid 200 body must parse");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);
        assert_eq!(groups[0].name, "pfBlocker_Blacklist");
    }

    /// Total connection failure — nothing listening at all — is the other end of the spectrum
    /// from an authenticated-but-rejected response, and must be distinguished as such: a `401`/
    /// `403` means "the key is bad", a connection failure means "the network/host is unreachable".
    /// Both keep the exporter serving its cache (see `sync::tests`), but they are different facts
    /// an operator reading logs needs told apart.
    #[tokio::test]
    async fn a_refused_connection_is_a_request_error_not_a_status_error() {
        // Bind to grab a genuinely free loopback port, then drop the listener immediately so nothing
        // is listening on it by the time the client connects — a fast, deterministic way to
        // reproduce ECONNREFUSED without depending on any specific unused port staying unused.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        drop(listener);

        let client = client_at(format!("http://{addr}"));
        let err = client.fetch_ips("g1", None).await.expect_err("a refused connection must not be Ok");
        assert!(matches!(err, VaultError::Request(_)), "expected a request-level error, got {err:?}");
    }
}
