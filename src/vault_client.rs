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

/// How many records to request per `GET /api/ips` page.
///
/// Vault imposes no ceiling on `limit`, so this is chosen for two properties rather than to satisfy
/// a cap: it keeps a single response comfortably small, and it puts the overwhelming majority of
/// deployments in **one** page — which means zero page boundaries, and so no exposure at all to the
/// ordering caveat documented on [`VaultClient::fetch_ips`].
const PAGE_SIZE: u64 = 1_000;

/// Hard ceiling on pages walked in one [`VaultClient::fetch_ips`] call — a runaway guard, not a
/// dataset limit. At [`PAGE_SIZE`] this allows a million records before it trips.
const MAX_PAGES: u32 = 1_000;

/// A signed HTTP client for `simply_ip_vault`.
#[derive(Clone)]
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    signing_secret: String,
    last_timestamp: Arc<AtomicI64>,
    /// Records requested per page. Always [`PAGE_SIZE`] in production; overridable in tests so a
    /// multi-page walk can be exercised without seeding a thousand fixture records per page.
    page_size: u64,
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
        Some(Self { http, base_url, api_key, signing_secret, last_timestamp, page_size: PAGE_SIZE })
    }

    /// Overrides the pagination page size. Test-facing: exercising a multi-page walk against the
    /// real [`PAGE_SIZE`] would mean seeding a thousand fixture records per page, so a suite shrinks
    /// it instead — the same trade `config::TrustedProxies::with_ttls` makes for its DNS TTLs.
    #[cfg(test)]
    pub fn with_page_size(mut self, page_size: u64) -> Self {
        self.page_size = page_size;
        self
    }

    /// Fetches **every** IP record for `groups`, walking Vault's pagination to completion. When
    /// `since` is set, performs a differential query (`include_deleted=true`); otherwise a full one.
    ///
    /// # Why this loops rather than sending one big `limit`
    ///
    /// `simply_ip_vault`'s `GET /api/ips` paginates with `limit`/`offset` and **defaults to
    /// `limit=50`** (`example/simply_ip_vault/src/api/records.rs::list_ips`:
    /// `filters.limit.unwrap_or(50)`). This client used to send no `limit` at all, so every sync —
    /// full *and* differential — silently received only the 50 most recently updated records and
    /// treated that truncated page as the whole dataset. On a full sync that is actively
    /// destructive: `apply_full` has replace semantics, so records past the 50th were dropped from
    /// the cache and disappeared from published feeds.
    ///
    /// Vault currently applies no ceiling to `limit`, so `limit=100000` would also work today — but
    /// betting on that re-creates the exact failure mode being fixed here: the moment the dataset
    /// outgrows the hardcoded number, or Vault gains a cap, truncation resumes with no signal at
    /// all. A loop that stops only when Vault returns a short page is correct at any size and under
    /// any cap Vault might later impose, so it is the version that cannot silently regress.
    ///
    /// Note `limit=0` is **not** "unlimited" — it is `LIMIT 0`, which returns nothing (verified
    /// against the live daemon). Nothing here should ever send it.
    ///
    /// # Consistency caveat
    ///
    /// Vault orders this listing by `updated_at DESC` with no tiebreaker, so an offset walk is not
    /// a stable snapshot: a record re-registered mid-walk sorts to the front and can shift rows
    /// across a page boundary, which may duplicate or skip one. Duplicates are harmless (the cache
    /// is keyed by address), and a skipped record is picked up by the next sync cycle. Vault
    /// exposes no cursor that would avoid this; a larger [`PAGE_SIZE`] reduces the number of
    /// boundaries where it can happen at all, and most deployments fit in a single page.
    pub async fn fetch_ips(
        &self,
        groups: &str,
        since: Option<NaiveDateTime>,
    ) -> Result<Vec<VaultApiRecord>, VaultError> {
        let mut base = format!("/api/ips?groups={}", urlencode(groups));
        if let Some(since) = since {
            base.push_str(&format!(
                "&since={}&include_deleted=true",
                urlencode(&since.and_utc().timestamp().to_string())
            ));
        }

        let mut all: Vec<VaultApiRecord> = Vec::new();
        let mut offset: u64 = 0;
        let mut pages: u32 = 0;

        loop {
            let page: Vec<VaultApiRecord> = self
                .signed_get(&format!("{base}&limit={}&offset={offset}", self.page_size))
                .await?;
            let page_len = page.len() as u64;
            all.extend(page);
            pages += 1;

            // A short page is Vault saying "that was the last of them" — the only correct
            // termination signal, since this endpoint reports no total count.
            if page_len < self.page_size {
                break;
            }

            if pages >= MAX_PAGES {
                // Never reached by a well-behaved Vault: it means either a genuinely enormous
                // dataset or a Vault that is ignoring `offset` and serving page one forever. Loud
                // on purpose — this is the one path that still returns a truncated result, which is
                // precisely the defect this function exists to prevent, so it must never be quiet.
                tracing::error!(
                    "Stopped paginating simply_ip_vault after {pages} pages ({} records) for \
                     groups {groups:?}: refusing to loop further. The result IS truncated — a full \
                     sync will publish a short feed. Check whether Vault is honouring `offset`.",
                    all.len()
                );
                break;
            }

            offset += self.page_size;
        }

        Ok(all)
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

    // ── Pagination: the 50-record truncation guard ────────────────────────────

    /// Boots a mock Vault that paginates `GET /api/ips` **exactly as the real one does**: it honours
    /// `limit`/`offset`, and — critically — defaults to `limit=50` when the parameter is absent,
    /// which is the precise behaviour that silently truncated every sync before `fetch_ips` learned
    /// to paginate. Records are synthesised as `51.<i/256>.<i%256>.1`, each a lone host in its own
    /// /24 so nothing can aggregate and a count is a count.
    ///
    /// Also records every request's query string, so a test can assert *how* the walk was performed
    /// (page count, and that `since`/`include_deleted` survived onto every page) rather than only
    /// what it returned.
    async fn spawn_paginating_mock_vault(
        total: usize,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        use axum::{Router, extract::RawQuery, routing::get};

        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen_for_handler = std::sync::Arc::clone(&seen);

        let app = Router::new().route(
            "/api/ips",
            get(move |RawQuery(query): RawQuery| {
                let seen = std::sync::Arc::clone(&seen_for_handler);
                async move {
                    let query = query.unwrap_or_default();
                    if let Ok(mut guard) = seen.lock() {
                        guard.push(query.clone());
                    }

                    let param = |name: &str| -> Option<u64> {
                        query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                            .and_then(|v| v.parse().ok())
                    };
                    // The real default, and the whole point of this mock.
                    let limit = param("limit").unwrap_or(50) as usize;
                    let offset = param("offset").unwrap_or(0) as usize;

                    let page: Vec<serde_json::Value> = (offset..total.min(offset + limit))
                        .map(|i| {
                            serde_json::json!({
                                "target_address": format!("51.{}.{}.1", i / 256, i % 256),
                                "updated_at": "2026-08-11T10:00:00",
                                "is_deleted": false,
                            })
                        })
                        .collect();
                    axum::Json(serde_json::Value::Array(page))
                }
            }),
        );

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), seen, handle)
    }

    /// The regression this whole mechanism exists for: 250 records behind a Vault that serves 50 at
    /// a time must arrive as 250, not as the first 50. Walked with `page_size = 50` so the test
    /// exercises five full pages plus the terminating short one.
    #[tokio::test]
    async fn fetch_ips_walks_every_page_instead_of_stopping_at_vaults_default_50() {
        let (url, seen, _server) = spawn_paginating_mock_vault(250).await;
        let client = client_at(url).with_page_size(50);

        let records = client.fetch_ips("g1", None).await.expect("pagination succeeds");

        assert_eq!(records.len(), 250, "every record must survive the walk, not just the first page");
        let distinct: std::collections::HashSet<_> =
            records.iter().map(|r| r.target_address.clone()).collect();
        assert_eq!(distinct.len(), 250, "pages must not overlap or repeat");
        // 5 full pages (offsets 0,50,100,150,200) + one empty page at offset 250 that ends it.
        assert_eq!(seen.lock().expect("not poisoned").len(), 6);
    }

    /// A dataset smaller than one page must cost exactly one request — the common deployment, and
    /// proof the loop doesn't poll a second time just to discover what a short page already said.
    #[tokio::test]
    async fn a_dataset_smaller_than_one_page_costs_a_single_request() {
        let (url, seen, _server) = spawn_paginating_mock_vault(10).await;
        let client = client_at(url).with_page_size(50);

        let records = client.fetch_ips("g1", None).await.expect("fetch succeeds");

        assert_eq!(records.len(), 10);
        assert_eq!(seen.lock().expect("not poisoned").len(), 1);
    }

    /// The off-by-one that a naive `while page.len() == limit` gets wrong in the other direction:
    /// when the total is an exact multiple of the page size, the walk needs one extra request to
    /// see the empty page and know it is done.
    #[tokio::test]
    async fn a_total_that_is_an_exact_multiple_of_the_page_size_terminates_correctly() {
        let (url, seen, _server) = spawn_paginating_mock_vault(100).await;
        let client = client_at(url).with_page_size(50);

        let records = client.fetch_ips("g1", None).await.expect("fetch succeeds");

        assert_eq!(records.len(), 100);
        assert_eq!(seen.lock().expect("not poisoned").len(), 3, "50, 50, then the empty page");
    }

    /// A differential sync is paginated too — and Vault applies `since`/`include_deleted` per
    /// request, so dropping either on page two would silently widen or narrow the delta partway
    /// through the walk.
    #[tokio::test]
    async fn a_differential_fetch_carries_since_and_include_deleted_onto_every_page() {
        let (url, seen, _server) = spawn_paginating_mock_vault(120).await;
        let client = client_at(url).with_page_size(50);
        let since = chrono::DateTime::from_timestamp(1_700_000_000, 0)
            .expect("a valid timestamp")
            .naive_utc();

        let records = client.fetch_ips("g1", Some(since)).await.expect("fetch succeeds");
        assert_eq!(records.len(), 120);

        let queries = seen.lock().expect("not poisoned").clone();
        assert_eq!(queries.len(), 3);
        for query in &queries {
            assert!(query.contains("since=1700000000"), "every page must keep the cutoff: {query}");
            assert!(query.contains("include_deleted=true"), "every page must keep the flag: {query}");
            assert!(query.contains("groups=g1"), "every page must keep the group scope: {query}");
        }
        // And each page must actually advance, rather than re-requesting offset 0 forever.
        assert!(queries[0].contains("offset=0"));
        assert!(queries[1].contains("offset=50"));
        assert!(queries[2].contains("offset=100"));
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
