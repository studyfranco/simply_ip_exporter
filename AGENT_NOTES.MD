# Agent Worklog — `simply_ip_exporter`

## 2026-08-11 — Initial implementation

Built the full crate from the empty scaffold (`Cargo.toml`, `Dockerfile`, `docker-compose.yml` were
present but were copies of `simply_ip_vault`'s — renamed/repointed at the exporter's own binary
name and port `3002`). Reference implementations `example/simply_ip_vault` and
`example/simply_hook_executor` were used to source the `CANONICAL_V1` HMAC scheme,
`SecretCipher` (XChaCha20-Poly1305), `MasterPin` boot-time pinning, and `ReplayGuard` verbatim in
spirit — reimplemented rather than copied, since this crate's RBAC is the simpler two-tier
Master/Daughter model from `AGENT.MD`, not the vault's group-permission model.

### Architectural decisions

- **IP data never touches SQLite.** `cache::IpCache` is `Arc<RwLock<HashMap<Uuid,
  EndpointCache>>>`, keyed by endpoint id. `SCHEMA.MD`'s `api_keys`/`endpoints` tables are the only
  SeaORM entities in `src/entities/`.
- **`master_marker` is a database-engine-derived generated column**, added via raw `ALTER TABLE`
  in the single initial migration (`m20260101_000001_initial_schema`), not an
  application-maintained column — `RBAC_MODEL.md` §5's rationale for why a plain application write
  path defeats the uniqueness guarantee applies here too, so it was done correctly from the start
  rather than repeating the vault's two-migration correction.
- **`/api/*` requires a valid `CANONICAL_V1` signature unconditionally.** Unlike
  `simply_hook_executor` (where signing is optional and a bearer key alone suffices unless
  `REQUIRE_SIGNED_REQUESTS` is set), `AGENT.MD` describes the admin API as "Secured with
  HMAC-SHA256", so `middleware::auth_middleware` demands `X-Timestamp` and `X-Signature-256` on
  every request — there is no bearer-only fallback mode to configure.
- **RBAC is two-tier, not three.** No "Parent" tier distinct from Master: `can_manage_keys` exists
  on the schema (per `SCHEMA.MD`) but only the Master key can manage `api_keys` in practice
  (`api::keys::require_master`), matching `AGENT.MD`'s literal two-tier description rather than the
  fuller Master/Parent/Daughter model in `RBAC_MODEL.md` (which is scoped to
  `simply_ip_vault`/`simply_hook_executor` only, per its own header). Endpoint management uses
  ownership (`owner_key_id`) instead: any key may create an endpoint it then owns; Master or the
  owner may manage it.
- **`TRUSTED_PROXIES` has no hostname/DNS-resolution support**, unlike the reference
  implementations' `TrustedProxies`. Only literal IPs/CIDRs are accepted. This is a deliberate
  scope cut — nothing in `AGENT.MD` requires container-hostname trust entries — revisit if a
  deployment needs it.
- **Vault sync credentials (`VAULT_BASE_URL`/`VAULT_API_KEY`/`VAULT_SIGNING_SECRET`) are env-only**,
  never persisted to SQLite. `SCHEMA.MD` scopes the database to `api_keys`/`endpoints`; there is no
  table for outbound Vault credentials, so they live in `RuntimeConfig` for the process lifetime.
  `sync::spawn_sync_worker` is a no-op loop (checks every 15s, does nothing) when they're unset,
  rather than failing startup — matches the "fault tolerant, keep serving the cache" posture
  `AGENT.MD` asks for on Vault being unreachable, extended to "not configured yet".
- **`last_synced_at` in the DB is the sync cursor**, not a value derived from the cache's own
  bookkeeping. `cache::IpCache` also tracks a `last_synced_at` internally (max `updated_at` seen),
  but `sync::sync_endpoint` reads/writes the DB column as the authoritative `since` parameter and
  TTL clock, per `AGENT.MD`'s literal "update `last_synced_at` in DB" instruction. The cache's own
  field is presently unused outside its own tests; harmless but worth removing if it stays
  unused.
- **Full sync cadence is tracked in-memory only** (`EndpointCache.last_full_sync_at`, a
  `tokio::time::Instant`), not persisted — a restart re-triggers an immediate full sync for every
  endpoint, which is correct (nothing survives a restart to make a stale in-memory cursor
  meaningful anyway).
- **Rate limiting is global per source IP**, not per (IP, endpoint) pair, per `AGENT.MD`'s literal
  wording ("Restrict public queries per client source IP"). Confirmed live: a second request to a
  *different* token from the same source IP inside the window is still 429'd — this is intended
  behavior, not a bug, and was caught during the manual smoke test below.
- **Bogon list is not exhaustive** of the full IANA special-purpose registries (`ipfilter.rs`) —
  covers the ranges that matter for a firewall feed (CGN, TEST-NETs, multicast, link-local,
  documentation ranges) without attempting completeness.

### Deviations worth flagging

- No audit log table — `SCHEMA.MD` doesn't define one for this service (unlike the vault's
  `audit_logs`), so none was added.
- `static/app.js`'s pure-JS SHA-256/HMAC fallback has no automated syntax check in the test suite
  (the reference repos pin an `oxc` parser dev-dependency for this; skipped here to keep the
  dependency tree smaller — `cargo test` cannot catch a static-asset syntax error). Verified by eye
  and via a brace/paren balance check; worth adding a real JS parser test if the file grows.

### Verification performed

- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo test`: 63 tests pass (52 unit + 11 integration in `tests/integration.rs`).
- Manual smoke test: built and ran the release-mode-equivalent binary against a scratch SQLite
  file, confirmed bootstrap-key banner, `/health`, `/ready`, static SPA serving, signed
  `/api/auth/me`, `/api/endpoints` creation, and `/feed/v1/<token>/list.txt` (including the 429
  above) all behave as specified.

### Pending / not yet done

- No CI workflow (`.forgejo/workflows`, `.github/workflows`) — the reference repos have one each;
  none was requested or added here.
- `scripts/verify_convergence.sh` was not authored — `RBAC_MODEL.md`'s version of that script is
  specific to the vault/hook-executor pair being byte-identical, which doesn't apply to this
  service. `scripts/test_e2e.sh` itself now exists (see below).

## 2026-08-11 — Documentation, `scripts/test_e2e.sh`, and a real bug it found

Added `README.md`, `FILE_MAP.MD`, and a full live E2E suite (`scripts/test_e2e.sh`) that boots a
real `simply_ip_vault` (built from `example/`) alongside `simply_ip_exporter` and drives the whole
workflow — provisioning, sync, feed aggregation/filtering, ETag/304, rate limiting, and Vault-outage
resilience — through 37 assertions. `./scripts/test_e2e.sh` passes end to end (exit 0, no stray
processes or temp files left behind); see the script's own header comment for the full matrix.

### A real bug the E2E script surfaced: rate limiter vs. ETag ordering

Writing §5 of the test matrix (fetch ETag, repeat with `If-None-Match`, assert `304`) exposed that
`feed::serve_feed` checked the rate limiter **before** computing the ETag. That meant *any* second
request from the same source IP inside the 2-minute window got `429`, including one carrying a
correct `If-None-Match` — a well-behaved poller that dutifully revalidates on every fetch (exactly
what ETags exist to make cheap) would get throttled for doing so, making conditional GET support
functionally useless against the very throttle it's supposed to coexist with. `AGENT.MD` specifies
both features independently and says nothing about their interaction, so this wasn't a spec
violation, but it was a design defect: it defeated the stated purpose of ETag support.

**Fix:** reordered `feed::serve_feed` to look up the endpoint, check `bound_ips`, and compute the
aggregated body + ETag *before* consulting the rate limiter. A request whose `If-None-Match`
matches gets a free `304` with no rate-limit consumption at all — cheap (in-memory only, no extra
DB work beyond the token lookup every request needs anyway), and not exploitable: an attacker
without the current body cannot produce a matching digest, so this cannot be used to bypass
throttling on the expensive path (a full `200` body). Only a request that does *not* match — no
header, a stale one, or a guess — reaches the rate limiter, exactly as before. Locked in with a new
integration-test assertion (`feed_aggregates_filters_etags_and_rate_limits`: a matching
`If-None-Match` from an already-throttled IP still returns `304`, not `429`) and exercised live by
§5 of the E2E script.

### Other additions this session

- `main.rs::bootstrap_master_key` now honors `INITIAL_MASTER_SIGNING_SECRET` (mirroring the
  existing `INITIAL_MASTER_KEY` support), so `scripts/test_e2e.sh` can bootstrap both services
  deterministically without scraping the one-time banner out of a buffered log — the same
  convention `simply_ip_vault`'s own `scripts/test_e2e.sh` uses.
- The E2E script's seed data deliberately does **not** reuse the `10.0.0.0/24`+`10.0.0.1/32` /
  `203.0.113.5/32` examples that appear elsewhere as illustrations: `10.0.0.0/8` is itself RFC 1918
  and `203.0.113.0/24` is IANA's TEST-NET-3 (a bogon by definition), so seeding either while the
  test endpoint has `filter_rfc1918=true`/`filter_bogons=true` set — as the task specified — would
  make the corresponding "survives filtering" assertions self-defeating against a spec-compliant
  implementation. The script uses `8.8.8.0/24`+`8.8.8.1/32` for the aggregation fixture instead
  (real public space, clear of every filter list) and keeps `192.168.1.50/32` (genuinely RFC 1918)
  and `100.64.0.5/32` (CGN, a real bogon, and *not* "private" per `std::net::Ipv4Addr::is_private()`
  so Vault's own `/ban` validation accepts it) as the two addresses each filter is meant to remove.
- `simply_ip_vault`'s `/api/ban` refuses to store a private/link-local IPv4 address (by design —
  "banning" one is meaningless). The script therefore registers `192.168.1.50/32` into a dedicated
  **whitelist** group (`pfBlocker_Private_Test`) via `/api/white` instead, and grants the exporter's
  Vault key `can_read` on both groups. `simply_ip_exporter` has no concept of Vault's ban/whitelist
  distinction — it just aggregates whatever addresses live in the groups it's configured to read —
  so this is a faithful test of the filtering behavior despite the source group's Vault-side type.

### Verification performed

- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo test`: 63 tests pass (52 unit + 11 integration — a new assertion was added to the
  existing feed test rather than as a separate test function, so the count is unchanged).
- `./scripts/test_e2e.sh`: 37/37 checks pass, exit code 0, confirmed no leftover processes or
  temp files after a full run.
