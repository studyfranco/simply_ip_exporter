# File Map — `simply_ip_exporter`

Exhaustive, file-by-file map of the source tree. Grouped by directory in the order a reader would
want to approach them: entry points first, then the shared foundations, then feature modules,
then the frontend and test suites.

---

## Root

| File | Responsibility |
| :--- | :--- |
| `Cargo.toml` | Crate manifest. `sea-orm`/`sea-orm-migration` (SQLite only), `axum` 0.8, `ipnet` (aggregation), `reqwest` (rustls, no native-tls), `chacha20poly1305`/`hmac`/`sha2` (crypto), `chrono`, `uuid`. |
| `Cargo.lock` | Pinned dependency graph. Intentionally **not** committed (see `.gitignore`) — matches the reference `simply_ip_vault`/`simply_hook_executor` convention. |
| `Dockerfile` | Two-stage build (`rust:slim` builder → `docker-baseimages-debian:testing` runtime). Exposes `3002`; `HEALTHCHECK` polls `/ready`, not `/health`, so an unhealthy container (DB down, Master unpinned) is taken out of rotation. |
| `docker-compose.yml` | Single-service compose file binding `3002:3002`, persisting `./data` (config DB only), with commented-out Vault-sync env vars as a template. |
| `.gitignore` | Excludes `target/`, `*.db*`, `Cargo.lock`, `.claude/`, and `example/` (the reference checkouts are not part of this repo's history). |
| `AGENT.MD` | Normative architectural/security ruleset this crate was built against. Read this before `SCHEMA.MD`. |
| `SCHEMA.MD` | Authoritative SQLite schema for `api_keys`/`endpoints`/`audit_logs`, including the `master_marker` generated-column mechanism. |
| `RBAC_MODEL.md` | The fuller Master/Parent/Daughter RBAC spec shared by `simply_ip_vault`/`simply_hook_executor`. This crate implements a simpler two-tier subset — see `AGENT_NOTES.MD` for the deliberate deviation. |
| `AGENT_NOTES.MD` | Running worklog: architectural decisions, deviations, and verification performed, updated after each significant change. |
| `SECURITY_COMPARISON_REPORT.md` | Independent, zero-knowledge security comparison against `example/simply_ip_vault` (the RBAC_MODEL.md-scoped peer this crate has an actual runtime relationship with). Overwritten wholesale on each fresh audit pass — see its own header for the peer commit audited and `AGENT_NOTES.MD` for the pull log. |
| `STRUCTURAL_CONVERGENCE_REPORT.md` | Companion architectural/naming-convention comparison against the same peer. Same overwrite convention. |
| `README.md` | User-facing documentation: architecture, quickstart, env var reference, pfBlockerNG integration, API/probe overview. |
| `FILE_MAP.MD` | This file. |
| `LICENSE` | Project license. |

---

## `src/` — entry points

| File | Responsibility |
| :--- | :--- |
| `src/main.rs` | Process entry point. Loads `.env`, initializes `tracing`, reads `RuntimeConfig`/`INITIAL_MASTER_KEY`, connects the DB, runs migrations, builds the `SecretCipher`, runs `bootstrap_master_key` (mints and once-prints the Master key/signing secret if `api_keys` is empty; supports deterministic `INITIAL_MASTER_KEY`/`INITIAL_MASTER_SIGNING_SECRET` for CI), then `verify_encryption_key` (a canary decrypt of the Master key's sealed `signing_secret` — `SecretCipher::from_env` only checks the configured key is 64 hex characters, so a syntactically valid but *wrong* key would otherwise pass silently and only surface later as opaque per-request `401`s; this aborts boot loudly instead, `exit(1)` with an explicit log line), pins the Master identity via `MasterPin::pin_at_boot`, spawns the sync worker, binds the listener, and serves with graceful shutdown (`SIGINT`/`SIGTERM`). Has its own `#[cfg(test)]` module covering `verify_encryption_key`. |
| `src/lib.rs` | Library root (`#![warn(missing_docs)]`). Declares every module, the `MAX_REQUEST_BODY_BYTES` constant shared between the router's `DefaultBodyLimit` and `middleware::MAX_SIGNED_BODY_BYTES`, and `create_app(AppState) -> Router` — the single place the full route table is assembled (probes and `/feed/v1/*` outside `auth_middleware`; `/api/*` nested behind it; `static/` as the fallback service). |

## `src/` — shared foundations

| File | Responsibility |
| :--- | :--- |
| `src/state.rs` | `AppState`: the `Clone`-cheap bundle of `db`, `config`, `cipher`, `replay_guard`, `master_pin`, `ip_cache`, `rate_limiter`, and an optional `vault_client`, threaded through every handler via Axum's `State` extractor. |
| `src/config.rs` | `RuntimeConfig::from_env()` and everything it depends on: `TrustedProxies`/`resolve_client_ip` (the `X-Forwarded-For`/`X-Real-IP` trust-boundary logic — headers are honored only from a configured trusted peer), `resolve_bind_addr`/`parse_bind_addr` (`BIND_HOST`/`PORT`), and `validate_initial_master_key` (the strict-hex, fail-closed check on `INITIAL_MASTER_KEY`). |
| `src/error.rs` | `AppError`, the single enum every handler returns via `Result<_, AppError>`, and its `IntoResponse` impl — the one place HTTP status codes and the `{"error": "..."}` envelope are decided. Includes `BodyRejected(StatusCode, String)`, which lets `src/extract.rs`'s strict extractors normalize a rejected request into this envelope while still passing through a non-`400` status (e.g. `413`) verbatim. |
| `src/extract.rs` | `StrictJson<T>`/`StrictPath`: wrappers around axum's built-in `Json`/`Path` extractors that remap a rejection (malformed body, invalid UUID segment) through `AppError` instead of axum's own plain-text rejection body — closing a gap where a malformed request bypassed this service's error envelope entirely. Used by every mutating handler in `api/keys.rs` and `api/endpoints.rs`. |
| `src/crypto.rs` | Two independent primitives sharing a file because they protect the same column (`api_keys.signing_secret`): `canonical_v1_payload`/`compute_signature`/`verify_signature` (the `CANONICAL_V1` HMAC-SHA256 scheme used both inbound and outbound), and `SecretCipher` (XChaCha20-Poly1305 sealing, keyed by `EXPORTER_ENCRYPTION_KEY`, with a plaintext fallback when unset). |
| `src/master.rs` | `MasterPin`: resolves and freezes the Master key's UUID once per process (`pin_at_boot` at startup; `resolve`/`authenticate` for on-demand use), so a direct-database `UPDATE api_keys SET is_master = true` on a different row cannot elevate that row without a restart. `pin_at_boot` checks the `master_marker` unique index via `crate::db::has_index` (not `sea_orm_migration::SchemaManager::has_index` — see `db.rs`'s entry for why). |
| `src/replay.rs` | `ReplayGuard`: an in-memory, self-pruning `HashMap` of recently-accepted `(key_id, digest)` pairs, enforcing single-use signatures within the `SIGNATURE_MAX_AGE_SECONDS` window. Bounded at 250k entries with backoff-limited sweeps under sustained saturation. |
| `src/db.rs` | `connect`/`run_migrations`/`apply_sqlite_pragmas`: builds the SQLite pool pinned to exactly one connection (`SQLITE_MAX_CONNECTIONS = 1`), declares `journal_mode=WAL`/`synchronous=NORMAL`/`foreign_keys=ON`/`busy_timeout` at connect time, and confirms them afterward. Also `has_index` (2026-08-18, ported from `example/simply_ip_vault`): a per-backend catalog query (`sqlite_master`/`pg_indexes`/`information_schema.statistics`) used by `master.rs::pin_at_boot` instead of `sea_orm_migration::SchemaManager::has_index`, which answers `BackendNotSupported` on PostgreSQL rather than correctly reporting the index. |
| `src/middleware.rs` | `auth_middleware`: the Axum middleware guarding every `/api/*` route. Validates `X-Timestamp` before touching the database, looks up the key by `X-API-Key`, applies `MasterPin::authenticate`, verifies the mandatory `X-Signature-256` over the full request target, checks `ReplayGuard`, and only then evaluates `bound_ips` — cheapest-and-unauthenticated checks first, network authorization last. A `Content-Length` over the router's body limit is rejected as `413` before any of the body is read; the same limit hit mid-stream (a `Content-Length`-less chunked body) falls back to the same `413` via `to_bytes`'s own cap. |

## `src/entities/` — SeaORM models (configuration only)

| File | Responsibility |
| :--- | :--- |
| `src/entities/mod.rs` | Module declarations for the three entities below. |
| `src/entities/prelude.rs` | `pub use` re-exports (`ApiKey`, `Endpoint`, `AuditLog`) for ergonomic `use crate::entities::prelude::*`. |
| `src/entities/api_key.rs` | The `api_keys` table `Model`/`ActiveModel`/`Relation`. Deliberately has **no** `master_marker` field — that column is database-engine-generated and would reject any client-supplied value. |
| `src/entities/endpoint.rs` | The `endpoints` table `Model`/`ActiveModel`/`Relation`, with a `belongs_to` FK to `api_key` (`ON DELETE SET NULL`). |
| `src/entities/audit_log.rs` | The `audit_logs` table `Model`/`ActiveModel`/`Relation`: the audit trail for mutating `/api/keys/*`/`/api/endpoints/*` actions, with a `belongs_to` FK to `api_key` (`ON DELETE SET NULL` — deleting the acting key must never delete the history of what it did). |

## `src/migration/` — schema

| File | Responsibility |
| :--- | :--- |
| `src/migration/mod.rs` | `Migrator` — the ordered `Vec<Box<dyn MigrationTrait>>` SeaORM runs at startup. |
| `src/migration/m20260101_000001_initial_schema.rs` | The single initial migration: creates `api_keys` and `endpoints` per `SCHEMA.MD`, then adds `api_keys.master_marker` as a raw-SQL `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END) VIRTUAL` column under a unique index — the database-level half of the Master-uniqueness guarantee, done correctly from the start rather than as a later correction. |
| `src/migration/m20260101_000002_add_audit_logs.rs` | Adds `audit_logs` per `SCHEMA.MD` §3: `api_key_id` `ON DELETE SET NULL`, `api_key_name`/`api_key_prefix`/`client_ip`/`action`/`timestamp` all `NOT NULL` from the start (no later correction needed, unlike the reference `simply_ip_vault`'s two-step history for the equivalent columns), plus indexes on `action`, `timestamp`, and `api_key_id`. |

## `src/` — in-memory cache, IP pipeline, and Vault sync

| File | Responsibility |
| :--- | :--- |
| `src/cache.rs` | `IpCache`: the `Arc<RwLock<HashMap<Uuid, EndpointCache>>>` at the center of the "zero disk wear" requirement. `apply_full`/`apply_diff` merge Vault's full/differential sync responses; `snapshot` returns an endpoint's current live networks; `full_sync_due` tracks the 24h full-resync clock in-process (via `tokio::time::Instant`, not persisted — a restart re-triggers an immediate full sync, which is correct). `parse_target_address` accepts both bare addresses and CIDR notation. |
| `src/ipfilter.rs` | `filter_and_aggregate`: the output sanitization pipeline. Static `RFC1918`/`LOOPBACK`/`BOGONS` range tables (lazily built via `std::sync::LazyLock`), an `overlaps_any` containment check applied per configured flag, and a final `ipnet::IpNet::aggregate()` pass to collapse the survivors into the smallest equivalent CIDR set. |
| `src/vault_client.rs` | `VaultClient`: the outbound, `CANONICAL_V1`-signed HTTP client for `GET /api/ips`. `fetch_ips(groups, since)` builds either a full query (no `since`) or a differential one (`since=<ts>&include_deleted=true`), signs it, and deserializes Vault's `VaultApiRecord` shape (`target_address`, `updated_at` as `chrono::NaiveDateTime`, `is_deleted`). `from_config` returns `None` when `VAULT_BASE_URL`/`VAULT_API_KEY`/`VAULT_SIGNING_SECRET` aren't all set. |
| `src/sync.rs` | `spawn_sync_worker`: the background `tokio::spawn` loop (15s tick) implementing the hybrid protocol described in `README.md` — per endpoint, a full sync when 24h have elapsed (or none has ever run) and a differential sync when `ttl_seconds` has elapsed since `endpoints.last_synced_at`, updating that DB column after each successful sync and logging-and-continuing (never failing the process) when Vault is unreachable. |
| `src/ratelimit.rs` | `RateLimiter`: the public feed's anti-DoS gate. A `Mutex`-protected `HashMap<IpAddr, Instant>` plus an insertion-ordered eviction queue, capped at `MAX_TRACKED_IPS = 10,000`, enforcing `RATE_LIMIT_WINDOW = 120s` per source IP. |
| `src/feed.rs` | `serve_feed`, the `GET /feed/v1/{token_secret}/list.txt` handler. Resolves the client IP, looks up the endpoint by token (`404` if unknown), checks `bound_ips` (`403` if disallowed), aggregates+filters the cached snapshot, computes the SHA-256 `ETag`, answers a matching `If-None-Match` with a free `304` (no rate-limit consumption — see the ordering rationale in the file's own doc comment), and otherwise applies the rate limiter before returning the full `text/plain` body. |

## `src/api/` — admin API (`/api/*`, behind `auth_middleware`) and probes

| File | Responsibility |
| :--- | :--- |
| `src/api/mod.rs` | Module declarations and `pub use` re-exports consumed by `lib.rs`'s route table. |
| `src/api/support.rs` | Shared helpers: `generate_random_key`/`hash_key` (credential minting/lookup), `validate_bound_ips` (parses and validates a comma-separated CIDR/address list), `describe_resource` (renders a `kind:id (name)` audit-log target reference), and `create_audit_log` (writes one `audit_logs` row; propagates a write failure rather than swallowing it, since the mutation it follows has already committed — see its doc comment). |
| `src/api/auth.rs` | `GET /api/auth/me` — reports the caller's own identity and RBAC flags, so the SPA (and this README's curl example) can authenticate once and introspect what it's allowed to do. |
| `src/api/keys.rs` | CRUD for `api_keys`, every route gated `require_master`: `create_api_key` (mints a Daughter key, returns its plaintext secret + signing secret exactly once), `list_api_keys`, `update_api_key` (name/`bound_ips`/`can_manage_keys` — `is_master` is not a field on the payload type, so it cannot be set through the API by construction), `delete_api_key` (refuses to delete the Master; judges success on `rows_affected`, not merely "the query didn't error", so a second concurrent delete of the same key is a `404` rather than a second `204` and a duplicate audit entry), `rotate_api_key` (refuses to rotate the Master). `CreateKeyPayload`/`UpdateKeyPayload` both carry `#[serde(deny_unknown_fields)]` (2026-08-18, matching `example/simply_ip_vault`) — a stray field is refused with a `400` naming it, not silently dropped. Every mutating route writes a `KEY_CREATE`/`KEY_UPDATE`/`KEY_DELETE`/`KEY_ROTATE` audit entry after its write commits. |
| `src/api/endpoints.rs` | CRUD for `endpoints`. `create_endpoint` — any authenticated key may call it; the new row is owned by the caller. `list_endpoints` — Master sees every row, a Daughter sees only its own (`owner_key_id` filter). `update_endpoint`/`delete_endpoint` — gated by `may_manage` (Master or owner); `delete_endpoint` has the same `rows_affected`-checked concurrent-delete handling as `delete_api_key`. `reassign_endpoint_owner` — Master only. `CreateEndpointPayload`/`UpdateEndpointPayload`/`ReassignOwnerPayload` all carry `#[serde(deny_unknown_fields)]` (2026-08-18, same rationale as `keys.rs`). Every mutating route writes an `ENDPOINT_CREATE`/`ENDPOINT_UPDATE`/`ENDPOINT_DELETE`/`ENDPOINT_OWNER_REASSIGN` audit entry after its write commits. |
| `src/api/audit.rs` | `GET /api/audit-logs` — lists the audit trail, most recent first, optionally filtered by exact `action` and paginated (`limit`, capped at 500; `offset`). Master-only: audit entries span every key and endpoint in the system, so a scoped Daughter key seeing them would be an RBAC leak regardless of what it owns. |
| `src/api/health.rs` | `health_check` (`GET /health`/`/healthz`, always `200`, no DB query) and `readiness_check` (`GET /ready`/`/readyz`, `200` only when an `api_keys` count query succeeds — an ordinary SeaORM query, not raw SQL — and `MasterPin::get()` is `Some`). Both mounted outside `auth_middleware` in `lib.rs`. |

## `static/` — embedded admin dashboard SPA

Zero external dependencies (no CDN links, no build step); served as the router's fallback service,
so any path not matched by `/health`, `/ready`, `/feed/v1/*`, or `/api/*` resolves here.

| File | Responsibility |
| :--- | :--- |
| `static/index.html` | Markup: a login screen (API key + signing secret fields) and a dashboard (identity badge, endpoints table + creation form, a Master-only API keys table + creation form, and a Master-only Audit Logs table with an action filter). |
| `static/app.js` | All client logic. `PureCrypto` — a self-contained FIPS 180-4/RFC 2104 SHA-256/HMAC-SHA256 implementation used only when `crypto.subtle` is unavailable (any non-secure-context origin, i.e. plain HTTP/LAN, which `AGENT.MD` documents as a supported deployment shape). `hmacSign` — picks Web Crypto when available, the pure-JS fallback otherwise, and always returns `sha256=<hex>`. `Session` — holds the API key/signing secret in `sessionStorage`. `apiCall` — signs and sends every admin-API request, throwing on a non-2xx response. The remaining functions render/wire the login flow, the endpoints/keys CRUD tables (create, delete, rotate, copy-feed-URL-to-clipboard), and `loadAuditLogs` (fetches and renders `GET /api/audit-logs`, optionally filtered by action; shown and loaded only for a Master identity). |
| `static/style.css` | Dark theme (CSS custom properties for the palette), matching the visual convention of `simply_ip_vault`/`simply_hook_executor`'s dashboards. No external fonts or frameworks. |

## `tests/` — automated test suites

| File | Responsibility |
| :--- | :--- |
| `tests/integration.rs` | End-to-end-in-process tests driving the real Axum router (via `tower::ServiceExt::oneshot`) against an in-memory SQLite database: health/readiness probes — including readiness failing independently on a genuinely broken database (an unmigrated connection) with the Master already pinned, not just on an unpinned Master — unsigned/signed/replayed/stale-timestamp admin API requests, Master-vs-Daughter RBAC on both `api_keys` and `endpoints`, the full feed pipeline (aggregation, RFC1918 filtering, ETag/304 including the "conditional revalidation bypasses the throttle" property, 429 rate limiting, `bound_ips` enforcement, unknown-token `404`), audit logging (every key/endpoint mutation writes the expected entry with correct attribution, `GET /api/audit-logs` is Master-only, and its `action` filter narrows results), malformed-request handling (`StrictJson`/`StrictPath`'s `{"error": ...}` envelope, `413` vs `400`, and an unknown field in a mutating payload naming itself in a `400` rather than being silently dropped), and concurrency (two identical signed requests racing the replay guard; two concurrent deletes of the same resource racing `rows_affected`). |
| `tests/common/mod.rs` | Shared fixtures: `setup_test_db` (migrated in-memory SQLite), `test_state` (plaintext-cipher `AppState`), `insert_key` (seeds an `api_keys` row and returns its plaintext credentials), and the `CANONICAL_V1` request-signing helpers (`signed_request`/`signed_request_at`/`with_connect_info`) that every integration test builds its requests through. |
| `tests/source_hygiene.rs` | Static source-hygiene checks nothing else in the build enforces, per `AGENT.MD`. Raw SQL: `no_raw_sql_outside_the_documented_exceptions` (marker-API scan) and `no_dml_keyword_is_hand_written_outside_the_exceptions` (scans for hand-written DML *inside string literals*, not just marker APIs) over `RAW_SQL_ALLOWED` — a `(path, reason)` list, each entry checked by `no_raw_sql_handler_is_ever_exempted` (no `src/api/` path may ever be exempted) and `every_allowlisted_raw_sql_exception_still_exists_and_is_still_needed` (an allowlist entry naming a path that no longer exists or no longer contains raw SQL must be dropped), plus `the_raw_sql_scanner_detects_what_it_is_looking_for` proving the scanner can actually see a violation (ported and strengthened from `example/simply_ip_vault`'s version — see `AGENT_NOTES.MD`'s 2026-08-17 session 2 entry). `no_unwrap_or_expect_in_production_code`, file-scanning over `src/` cut off at each file's `#[cfg(test)] mod tests` boundary — `every_source_file_places_its_test_module_last` independently verifies that boundary-detection heuristic itself. Plus `app_js_has_no_syntax_errors` (an `oxc_parser`-based real ECMAScript parse of `static/app.js`) and `every_dom_id_referenced_in_app_js_exists_in_index_html` (cross-checks every `el('...')` lookup against `static/index.html`'s `id=` attributes). |

Unit tests live beside the code they test, in `#[cfg(test)] mod tests` blocks within the `src/`
files listed above (80 of them, at last count) rather than in a separate directory — see each
file's own `tests` module for its specific coverage.

## `scripts/` — operational tooling

| File | Responsibility |
| :--- | :--- |
| `scripts/test_e2e.sh` | Standalone, executable Bash E2E suite, 100 checks across 14 numbered sections. Builds `simply_ip_vault` (from `example/`) and this crate, boots both against throwaway SQLite databases with deterministic `INITIAL_MASTER_KEY`/`INITIAL_MASTER_SIGNING_SECRET` bootstrap, provisions Vault, configures an exporter endpoint, and asserts: the full public-feed pipeline (`text/plain`, `ipnet` aggregation, RFC1918/bogon filtering, `ETag`/`304`, `429` rate limiting); Vault soft-delete propagation via a real differential sync; hot-reload of `filter_rfc1918` with no restart; `bound_ips` client-IP restriction; a full graceful-`SIGTERM`-and-restart cycle proving the Master key, a Daughter key's encrypted-at-rest `signing_secret`, and the endpoint row all survive against the same SQLite file, and the in-memory cache re-hydrates from Vault afterward; a wrong (but syntactically valid) `EXPORTER_ENCRYPTION_KEY` being refused at startup — process exits non-zero with an explicit log line and no panic, then a correct restart proves no DB corruption; HMAC anti-replay timestamp-skew rejection (`+301s`/`-301s` from server time, both directions, `401`); real-time Daughter key rotation and deletion each instantly invalidating the old credentials with no restart; resilience to Vault being killed; and a full audit-log traversal (every administrative action performed during the run present, correctly attributed, and accurately timestamped). Requires `curl`, `jq`, `cargo`, `openssl`, and the `example/simply_ip_vault` reference checkout. |
| `scripts/verify_convergence.sh` | Standalone, executable Bash wrapper around `tests/source_hygiene.rs`. Builds the test binary once, then runs each hygiene check individually by name so a failure is reported as a named, described convention violation rather than an undifferentiated `cargo test` failure list. |

## `example/` — reference implementations (not part of this crate)

Gitignored, untracked checkouts of `simply_ip_vault` and `simply_hook_executor` used as pattern
references for the `CANONICAL_V1` HMAC scheme, `SecretCipher`, `MasterPin`, and `ReplayGuard` — see
`AGENT.MD` and `AGENT_NOTES.MD` for what was adapted versus deliberately simplified for this
crate's two-tier RBAC model. `scripts/test_e2e.sh` additionally builds and runs
`example/simply_ip_vault` as a live dependency of its own test run.
