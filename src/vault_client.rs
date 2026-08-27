//! Outbound `simply_ip_vault` API client: `CANONICAL_V1` HMAC-signed `GET /api/ips` requests for
//! the hybrid differential/full sync protocol.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::NaiveDateTime;
use futures::stream::{self, StreamExt, TryStreamExt};
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

/// How many page requests may be in flight at once when Vault reports a page count up front.
///
/// Bounded rather than unbounded on purpose: `total_pages` is Vault's number, not ours, and a large
/// dataset would otherwise open one connection per page simultaneously — turning a routine sync
/// into a self-inflicted burst against the very service the exporter depends on. Five keeps the
/// wall-clock win of parallelism (a 4-page fetch costs roughly one round-trip instead of four)
/// while capping concurrent load at something a single Vault answers comfortably.
const MAX_CONCURRENT_PAGES: usize = 5;

/// Vault's `GET /api/ips?include_total=true` envelope.
///
/// Only the two fields this client acts on are modelled; `total`, `limit` and `offset` are also
/// present in Vault's response and deliberately ignored — `total_pages` already encodes everything
/// needed to enumerate the remaining offsets, and re-deriving it from `total`/`limit` here would
/// duplicate a calculation Vault has already made (and could disagree with it at the boundary).
#[derive(Debug, Deserialize)]
struct IpRecordsEnvelope {
    data: Vec<VaultApiRecord>,
    total_pages: u64,
}

/// What `GET /api/ips` answered with: the paginated envelope, or the historical bare array.
///
/// `untagged` so one deserialize attempt covers both shapes — an object with `data`/`total_pages`
/// matches [`IpRecordsEnvelope`], and a root array matches [`Self::Legacy`]. That is the *response*
/// half of legacy tolerance; see [`VaultClient::fetch_ips`] for the other, sharper half, where an
/// older Vault rejects the request outright.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IpsResponse {
    Envelope(IpRecordsEnvelope),
    Legacy(Vec<VaultApiRecord>),
}

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

        // Page one doubles as a capability probe: `include_total=true` asks Vault to report how
        // many pages exist, and how it answers decides which strategy the rest of this fetch uses.
        let first = self
            .signed_get::<IpsResponse>(&format!(
                "{base}&include_total=true&limit={}&offset=0",
                self.page_size
            ))
            .await;

        match first {
            Ok(IpsResponse::Envelope(envelope)) => {
                self.fetch_remaining_pages_in_parallel(&base, envelope, groups).await
            }
            // Vault answered, but with the historical root array — it does not implement
            // `include_total` yet simply ignored the parameter. Page one is still perfectly good
            // data, so it is kept and the sequential walk resumes from page two rather than
            // re-requesting offset 0.
            Ok(IpsResponse::Legacy(first_page)) => {
                self.fetch_sequentially(&base, groups, first_page).await
            }
            // The sharper legacy case, and the one that actually occurs in the field: Vault's
            // `QueryFilters` is `deny_unknown_fields`, so a deployment older than the
            // `include_total` change rejects the *request* with `400` rather than ignoring the
            // parameter. Retry once without the flag — an exporter upgraded ahead of its vault must
            // keep syncing, not fail every cycle until the vault catches up.
            Err(VaultError::Status(status)) if status == reqwest::StatusCode::BAD_REQUEST => {
                tracing::debug!(
                    "simply_ip_vault rejected `include_total` ({status}) — it predates that \
                     parameter. Falling back to sequential paging for groups {groups:?}."
                );
                self.fetch_sequentially(&base, groups, Vec::new()).await
            }
            Err(e) => Err(e),
        }
    }

    /// Fetches pages `2..=total_pages` concurrently, capped at [`MAX_CONCURRENT_PAGES`] in flight,
    /// and merges them onto the already-fetched first page.
    ///
    /// Every page reuses `base`, so `groups`/`since`/`include_deleted` are identical across the
    /// whole set — a delta that widened or narrowed partway through the walk would be worse than a
    /// slow one. `include_total` is *not* repeated on the follow-up pages: their count is already
    /// known, and asking Vault to recompute a `COUNT(*)` per page would pay for the same number
    /// four times over.
    ///
    /// Ordering is not preserved, and deliberately so: `buffer_unordered` yields pages as they
    /// complete. Nothing downstream depends on record order — `cache::IpCache` keys by address and
    /// `ipfilter::filter_and_aggregate` sorts — so paying for ordering here would buy nothing.
    async fn fetch_remaining_pages_in_parallel(
        &self,
        base: &str,
        envelope: IpRecordsEnvelope,
        groups: &str,
    ) -> Result<Vec<VaultApiRecord>, VaultError> {
        let mut all = envelope.data;

        // `total_pages` is 0 when there is nothing to page through and 1 when it all fit in page
        // one; both mean "no follow-up requests", which this range expresses without a branch.
        let offsets: Vec<u64> =
            (1..envelope.total_pages).map(|page| page * self.page_size).collect();
        if offsets.is_empty() {
            return Ok(all);
        }

        if offsets.len() + 1 > MAX_PAGES as usize {
            tracing::error!(
                "simply_ip_vault reports {} pages for groups {groups:?}, beyond the {MAX_PAGES}-page \
                 ceiling. Refusing to fetch them all; the result IS truncated.",
                envelope.total_pages
            );
        }
        let offsets: Vec<u64> = offsets.into_iter().take(MAX_PAGES as usize - 1).collect();

        let pages: Vec<Vec<VaultApiRecord>> = stream::iter(offsets)
            .map(|offset| async move {
                self.signed_get::<Vec<VaultApiRecord>>(&format!(
                    "{base}&limit={}&offset={offset}",
                    self.page_size
                ))
                .await
            })
            .buffer_unordered(MAX_CONCURRENT_PAGES)
            .try_collect()
            .await?;

        all.extend(pages.into_iter().flatten());
        Ok(all)
    }

    /// The original offset walk, kept as the fallback for any Vault that cannot report a page
    /// count. Terminates on the first short page — the only signal available without a total.
    ///
    /// `already_fetched` carries page one when the caller already has it (the "Vault ignored
    /// `include_total`" path), so the walk resumes at page two instead of re-requesting offset 0.
    /// An empty vector starts from the beginning, which is what the `400`-rejection path wants.
    async fn fetch_sequentially(
        &self,
        base: &str,
        groups: &str,
        already_fetched: Vec<VaultApiRecord>,
    ) -> Result<Vec<VaultApiRecord>, VaultError> {
        let resume_at_second_page = already_fetched.len() as u64 == self.page_size;
        let mut all = already_fetched;

        // A short (or empty) first page already ended the walk before it began.
        if !all.is_empty() && !resume_at_second_page {
            return Ok(all);
        }

        let mut offset: u64 = if resume_at_second_page { self.page_size } else { 0 };
        let mut pages: u32 = if resume_at_second_page { 1 } else { 0 };

        loop {
            let page: Vec<VaultApiRecord> = self
                .signed_get(&format!("{base}&limit={}&offset={offset}", self.page_size))
                .await?;
            let page_len = page.len() as u64;
            all.extend(page);
            pages += 1;

            // A short page is Vault saying "that was the last of them" — the only correct
            // termination signal, since this response shape reports no total count.
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

    // ── include_total envelope: bounded parallel paging ───────────────────────

    /// How a mock Vault should answer `GET /api/ips`, so one harness can model every deployment
    /// this client has to survive.
    #[derive(Clone, Copy, PartialEq)]
    enum VaultFlavour {
        /// Current Vault: honours `include_total=true` with the `{data, …, total_pages}` envelope.
        Envelope,
        /// A Vault that accepts the parameter but still answers with the historical root array.
        IgnoresIncludeTotal,
        /// Real pre-`b8bd281` Vault: `QueryFilters` is `deny_unknown_fields`, so `include_total`
        /// is an *unknown field* and the request is refused with `400` before any data is read.
        RejectsIncludeTotal,
    }

    /// Boots a mock Vault that paginates exactly as the real one does — honouring `limit`/`offset`,
    /// defaulting to `limit=50`, and (per `flavour`) implementing `include_total` the way a current,
    /// an indifferent, or an outdated deployment would.
    ///
    /// Records are `51.<i/256>.<i%256>.1`: lone hosts in distinct /24s, so a count is a count.
    /// Every request's query string is recorded, letting a test assert *how* the fetch was
    /// performed — page count, concurrency bound, and that the delta filters rode along.
    async fn spawn_flavoured_mock_vault(
        total: usize,
        flavour: VaultFlavour,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        use axum::{
            Router, extract::RawQuery, http::StatusCode, response::IntoResponse, routing::get,
        };

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

                    let has = |name: &str| query.split('&').any(|kv| kv == format!("{name}=true"));
                    let param = |name: &str| -> Option<u64> {
                        query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                            .and_then(|v| v.parse().ok())
                    };

                    let wants_total = has("include_total");
                    if wants_total && flavour == VaultFlavour::RejectsIncludeTotal {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "Failed to deserialize query string: unknown field `include_total`"
                            })),
                        )
                            .into_response();
                    }

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

                    if wants_total && flavour == VaultFlavour::Envelope {
                        let total_pages =
                            if limit == 0 { 0 } else { total.div_ceil(limit) } as u64;
                        return axum::Json(serde_json::json!({
                            "data": page,
                            "total": total,
                            "limit": limit,
                            "offset": offset,
                            "total_pages": total_pages,
                        }))
                        .into_response();
                    }

                    axum::Json(serde_json::Value::Array(page)).into_response()
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

    fn offsets_requested(queries: &[String]) -> Vec<u64> {
        let mut offsets: Vec<u64> = queries
            .iter()
            .filter_map(|q| {
                q.split('&').find_map(|kv| kv.strip_prefix("offset=")).and_then(|v| v.parse().ok())
            })
            .collect();
        offsets.sort_unstable();
        offsets
    }

    /// The headline scenario: 3,214 records over 4 pages at `limit=1000` (1000+1000+1000+214).
    /// One probing request learns `total_pages = 4`, then pages 2–4 are fetched concurrently, and
    /// all 3,214 distinct records arrive with no duplicates and nothing lost at a page boundary.
    #[tokio::test]
    async fn an_envelope_fetch_pulls_3214_records_across_four_pages_in_parallel() {
        let (url, seen, _server) =
            spawn_flavoured_mock_vault(3_214, VaultFlavour::Envelope).await;
        let client = client_at(url); // real PAGE_SIZE = 1000

        let records = client.fetch_ips("g1", None).await.expect("the parallel fetch succeeds");

        assert_eq!(records.len(), 3_214, "every record across all four pages must arrive");
        let distinct: std::collections::HashSet<_> =
            records.iter().map(|r| r.target_address.clone()).collect();
        assert_eq!(distinct.len(), 3_214, "pages must not overlap, duplicate, or drop a boundary row");

        let queries = seen.lock().expect("not poisoned").clone();
        assert_eq!(queries.len(), 4, "exactly four requests: one probe plus three follow-up pages");
        assert_eq!(
            offsets_requested(&queries),
            vec![0, 1_000, 2_000, 3_000],
            "each page requested exactly once, at the offsets total_pages implies"
        );

        // Only the probe pays for Vault's COUNT(*); re-requesting it per page would compute the
        // same total four times for no benefit.
        let with_total = queries.iter().filter(|q| q.contains("include_total=true")).count();
        assert_eq!(with_total, 1, "include_total belongs on the probe alone");
    }

    /// A dataset that fits in one page must cost exactly one request — `total_pages = 1` means
    /// there is nothing to parallelise, and the probe already returned the data.
    #[tokio::test]
    async fn a_single_page_envelope_costs_one_request_and_spawns_no_parallel_work() {
        let (url, seen, _server) = spawn_flavoured_mock_vault(10, VaultFlavour::Envelope).await;
        let client = client_at(url);

        let records = client.fetch_ips("g1", None).await.expect("fetch succeeds");

        assert_eq!(records.len(), 10);
        assert_eq!(seen.lock().expect("not poisoned").len(), 1);
    }

    /// `total_pages` is `0` (not `1`) when there is nothing to page through — Vault's documented
    /// edge case, and the one a naive `1..total_pages` loop would mishandle by requesting a page
    /// that does not exist.
    #[tokio::test]
    async fn an_empty_envelope_reporting_zero_pages_issues_no_follow_up_requests() {
        let (url, seen, _server) = spawn_flavoured_mock_vault(0, VaultFlavour::Envelope).await;
        let client = client_at(url);

        let records = client.fetch_ips("g1", None).await.expect("fetch succeeds");

        assert!(records.is_empty());
        assert_eq!(seen.lock().expect("not poisoned").len(), 1, "nothing to follow up on");
    }

    /// Concurrency must stay bounded: with 12 pages outstanding, no more than
    /// [`MAX_CONCURRENT_PAGES`] requests may be in flight at once. Measured by having the mock
    /// track its own live-request high-water mark rather than by inspecting the stream.
    #[tokio::test]
    async fn parallel_paging_never_exceeds_the_concurrency_cap() {
        use axum::{Router, extract::RawQuery, routing::get};

        let in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (in_flight_h, peak_h) =
            (std::sync::Arc::clone(&in_flight), std::sync::Arc::clone(&peak));

        let total = 12_000usize; // 12 pages at PAGE_SIZE 1000
        let app = Router::new().route(
            "/api/ips",
            get(move |RawQuery(query): RawQuery| {
                let (in_flight, peak) =
                    (std::sync::Arc::clone(&in_flight_h), std::sync::Arc::clone(&peak_h));
                async move {
                    let now = in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    // Held open long enough that genuinely concurrent requests overlap here; without
                    // the pause every request could complete before the next began and the peak
                    // would read 1 no matter how the client behaved.
                    tokio::time::sleep(Duration::from_millis(60)).await;

                    let query = query.unwrap_or_default();
                    let param = |name: &str| -> Option<u64> {
                        query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                            .and_then(|v| v.parse().ok())
                    };
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
                    in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

                    if query.contains("include_total=true") {
                        return axum::Json(serde_json::json!({
                            "data": page, "total": total, "limit": limit,
                            "offset": offset, "total_pages": total.div_ceil(limit),
                        }));
                    }
                    axum::Json(serde_json::Value::Array(page))
                }
            }),
        );
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback bind always succeeds");
        let addr = listener.local_addr().expect("a bound listener has a local address");
        let _server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = client_at(format!("http://{addr}"));
        let records = client.fetch_ips("g1", None).await.expect("fetch succeeds");

        assert_eq!(records.len(), 12_000);
        let observed = peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            observed > 1,
            "pages must actually overlap — a peak of 1 would mean the fetch ran sequentially"
        );
        assert!(
            observed <= MAX_CONCURRENT_PAGES,
            "at most {MAX_CONCURRENT_PAGES} requests may be in flight, saw {observed}"
        );
    }

    /// Delta-sync filters must ride along on every parallel page. Dropping `since` or
    /// `include_deleted` on page two would silently widen the delta partway through the fetch —
    /// and unlike the sequential walk, these requests are built independently, so it is a genuinely
    /// separate risk worth pinning.
    #[tokio::test]
    async fn parallel_pages_each_carry_since_include_deleted_and_groups() {
        let (url, seen, _server) =
            spawn_flavoured_mock_vault(2_500, VaultFlavour::Envelope).await;
        let client = client_at(url);
        let since = chrono::DateTime::from_timestamp(1_700_000_000, 0)
            .expect("a valid timestamp")
            .naive_utc();

        let records = client.fetch_ips("g1,g2", Some(since)).await.expect("fetch succeeds");
        assert_eq!(records.len(), 2_500);

        let queries = seen.lock().expect("not poisoned").clone();
        assert_eq!(queries.len(), 3, "one probe plus two follow-up pages");
        for query in &queries {
            assert!(query.contains("since=1700000000"), "every page keeps the cutoff: {query}");
            assert!(query.contains("include_deleted=true"), "every page keeps the flag: {query}");
            assert!(query.contains("groups=g1,g2"), "every page keeps the group scope: {query}");
        }
    }

    // ── Legacy tolerance: two distinct shapes of "older Vault" ────────────────

    /// The failure mode that actually occurs in the field. Vault's `QueryFilters` is
    /// `deny_unknown_fields`, so a deployment predating `include_total` refuses the *request* with
    /// `400`. An exporter upgraded ahead of its vault must keep syncing, not fail every cycle — so
    /// it retries without the flag and completes the fetch sequentially.
    #[tokio::test]
    async fn a_vault_that_rejects_include_total_with_400_falls_back_to_sequential_paging() {
        let (url, seen, _server) =
            spawn_flavoured_mock_vault(120, VaultFlavour::RejectsIncludeTotal).await;
        let client = client_at(url).with_page_size(50);

        let records = client.fetch_ips("g1", None).await.expect("the fallback must succeed");

        assert_eq!(records.len(), 120, "a 400 on the probe must not lose any data");
        let queries = seen.lock().expect("not poisoned").clone();
        // The refused probe, then a clean sequential walk: 50, 50, 20.
        assert_eq!(queries.len(), 4);
        assert!(queries[0].contains("include_total=true"), "the probe is attempted once");
        assert!(
            queries[1..].iter().all(|q| !q.contains("include_total")),
            "and never repeated after it was refused"
        );
        assert_eq!(offsets_requested(&queries), vec![0, 0, 50, 100]);
    }

    /// The gentler legacy shape: Vault accepts the parameter but still answers with the historical
    /// root array. Page one is real data, so it is kept and the walk resumes at page two rather
    /// than re-requesting offset 0 — which would both waste a round-trip and duplicate records.
    #[tokio::test]
    async fn a_vault_that_ignores_include_total_reuses_page_one_and_pages_on_sequentially() {
        let (url, seen, _server) =
            spawn_flavoured_mock_vault(120, VaultFlavour::IgnoresIncludeTotal).await;
        let client = client_at(url).with_page_size(50);

        let records = client.fetch_ips("g1", None).await.expect("the fallback must succeed");

        assert_eq!(records.len(), 120);
        let distinct: std::collections::HashSet<_> =
            records.iter().map(|r| r.target_address.clone()).collect();
        assert_eq!(distinct.len(), 120, "page one must not be fetched twice");

        let queries = seen.lock().expect("not poisoned").clone();
        assert_eq!(queries.len(), 3, "offset 0 is not re-requested");
        assert_eq!(offsets_requested(&queries), vec![0, 50, 100]);
    }

    /// A legacy first page shorter than the page size ends the fetch immediately — there is no
    /// second page to ask for, and asking anyway would be a wasted round-trip on every small sync.
    #[tokio::test]
    async fn a_short_legacy_first_page_completes_without_a_second_request() {
        let (url, seen, _server) =
            spawn_flavoured_mock_vault(10, VaultFlavour::IgnoresIncludeTotal).await;
        let client = client_at(url).with_page_size(50);

        let records = client.fetch_ips("g1", None).await.expect("fetch succeeds");

        assert_eq!(records.len(), 10);
        assert_eq!(seen.lock().expect("not poisoned").len(), 1);
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
