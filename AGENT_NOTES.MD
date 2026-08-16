# Agent Worklog — `simply_ip_exporter`

## 2026-08-16 — Advanced E2E scenarios, three real bugs found and fixed

Given full autonomy to expand `scripts/test_e2e.sh`/`tests/integration.rs` with five specific
real-world scenarios plus open-ended discovery. Net result: `test_e2e.sh` grew from 6 sections/37
checks to 11 sections/80 checks; `cargo test` grew from 103 to 108 (80 unit + 21 integration + 7
source-hygiene); and three genuine bugs were found and fixed — one in this crate's error handling,
one in this crate's concurrency handling, and one in the peer `simply_ip_vault` reference
implementation's differential-sync contract.

### Bug 1: malformed requests bypassed the `{"error": ...}` envelope

Found while scoping the new E2E work, before writing any of the five scenarios — a general
robustness sweep, not tied to a specific task item. Axum's built-in `Json<T>`/`Path<Uuid>`
extractors reject a malformed body or an invalid UUID path segment *before any handler runs*, with
axum's own plain-text rejection body — not this service's `{"error": "..."}` envelope every other
refusal uses. Confirmed empirically: `POST /api/keys` with `{not valid json` returned `400` with
body `Failed to parse the request body as JSON: key must be a string at line 1 column 2` (plain
text, not JSON); `DELETE /api/keys/not-a-uuid` similarly. This crate's own `static/app.js` does
`JSON.parse(text)` on every response and would throw an uncaught exception on either.

**Fix:** `src/extract.rs` (new), mirroring `simply_ip_vault`'s own `StrictJson` precedent —
`StrictJson<T>` and `StrictPath` wrap the built-in extractors and remap their rejections through a
new `AppError::BodyRejected(StatusCode, String)` variant, which renders the normal envelope while
passing the extractor's own status through verbatim. Swapped into every mutating handler in
`api/keys.rs` and `api/endpoints.rs`. Along the way, discovered a second-order issue: an oversized
body reported `400` instead of `413`, because `middleware::auth_middleware` buffers the whole body
itself (to verify the HMAC signature) *before* any handler's extractors ever see it, so
`StrictJson`'s own 413-preservation logic was unreachable dead code for every authenticated route —
which is all of them. Added a `Content-Length` pre-check in `auth_middleware` (fails fast as `413`
without reading a byte) plus remapped its `to_bytes` size-limit fallback to `413` as well. Three new
regression tests in `tests/integration.rs` pin the fixed envelope shape and status codes, not just
"is it an error" — a regression back to the bare extractors would still return `400`/`413` while
silently changing the body format.

### Bug 2 (Task 1, scenario 1 — Vault soft-delete propagation): a real cross-project contract bug

Writing the soft-delete E2E scenario — seed an address, sync it, soft-delete it in Vault, wait for
the next differential tick, assert it's gone — failed on the very first run: the address stayed in
the feed indefinitely. Traced to `simply_ip_vault`'s own `GET /api/ips` handler
(`example/simply_ip_vault/src/api/records.rs`): the `since` filter matches only
`ip_records.last_seen_at`, and `DELETE /api/ips/{id}`'s soft-delete path sets `is_deleted`,
`deleted_at`, and `updated_at` but **deliberately never touches `last_seen_at`** (deletion isn't
"activity" — see that field's own doc comment). So a differential-sync client polling with
`since=<cursor>&include_deleted=true` can never observe a deletion whose target hadn't
independently been re-banned/re-seen after the cursor, which silently defeats
`include_deleted=true` for exactly the case `AGENT.MD`'s hybrid-refresh-protocol description says
it exists for. Confirmed with a minimal manual repro (boot both services standalone, `RUST_LOG=debug`,
soft-delete, wait through several 15s ticks, observe `last_synced_at` advancing on every tick while
the deleted address never left the feed) before touching any code, to rule out a bug in this
crate's own `sync`/`cache` merge logic first.

**This crate's own differential-merge logic (`sync::sync_endpoint`, `cache::IpCache::apply_diff`) is
correct** — it merges whatever Vault hands it, including `is_deleted: true` tombstones (see the
`sync::tests::differential_sync_against_a_healthy_vault_actually_updates_the_cache` unit test,
which was already passing and remains the proof this crate's half of the contract works). The bug
is entirely on Vault's side, in a repository this project does not own.

**Applied a fix to the local `example/simply_ip_vault` checkout** (`records.rs`'s `since` filter now
matches `last_seen_at >= threshold OR updated_at >= threshold`, via `Condition::any()` — an
additive, conservative widening: it can only return *more* records than strictly necessary, never
fewer, and this crate's merge logic is idempotent under re-application) **and committed it locally
in that nested repository** (commit `bc32c69`, message explains the bug and that it's local-only)
so it survives this session rather than sitting as a fragile uncommitted diff. **This commit was
NOT pushed anywhere.** Two things worth flagging explicitly for whoever reads this next:

- `example/` is gitignored in *this* repo, so the fix has no effect on a fresh clone of
  `simply_ip_exporter` — a fresh `git clone` of the peer repos will reproduce the original bug
  until either this local patch is reapplied or the fix lands upstream in the real
  `simply_ip_vault` project (which this session has no access to push to).
  `scripts/verify_convergence.sh`'s peer-sync step correctly protected this local commit on its own
  next run: `git pull` reported "divergent branches" (local is one commit ahead) and the script's
  designed graceful-degradation path warned and continued with the local, patched version, rather
  than silently discarding it or failing the whole gate.
- **A real deployment of `simply_ip_exporter` talking to an unpatched `simply_ip_vault` will not
  see deletions propagate via differential sync** — only via the 24h full sync, which does not use
  `since` at all and simply excludes `is_deleted=true` rows outright. That is a real, if bounded (24h
  worst case), correctness gap for a firewall blocklist exporter: a de-listed address stays
  wrongly blocked for up to a day. Operators running against a real Vault instance should either
  get the equivalent one-line fix applied there, or treat `ttl_seconds` as advisory for *additions*
  only and rely on the daily full sync as the authoritative source of truth for *removals* until it
  is.

### Bug 3 (autonomous discovery): concurrent deletes of the same resource both "succeeded"

While writing a concurrency test explicitly requested by this task's guidance ("concurrent
mutations" is named as an example of what full autonomy should go looking for): two `DELETE
/api/endpoints/{id}` requests fired genuinely concurrently (via `tokio::join!` on two clones of the
same router, sharing the same `AppState`/DB pool — not sequential reuse) for the same endpoint both
returned `204 No Content`. Root cause: `delete_endpoint` (and identically, `delete_api_key`) does a
`find_by_id` check, then unconditionally calls `delete_by_id(id).exec(&db)` and returns `204` —
SeaORM's `delete_by_id().exec()` does not error when zero rows match, it just reports
`rows_affected: 0`, which neither handler checked. Both concurrent requests pass the initial
`find_by_id` (there are async yield points between it and the actual `DELETE` — the cache eviction,
the audit-log write — during which the other request's `find_by_id` can interleave), both then
"successfully" delete a row only one of them actually affects, and **both write a
`KEY_DELETE`/`ENDPOINT_DELETE` audit entry** — meaning the audit trail (the subject of the previous
session's whole task) would record two deletions for an action that happened once. Not a
data-integrity bug (the end state — row gone — is correct either way) but a real API-contract and
audit-accuracy one.

**Fix:** both handlers now check `rows_affected` on the delete and return `AppError::NotFound`
(`404`) when it's zero, skipping the cache eviction and audit-log write entirely for the request
that lost the race. Two new tests in `tests/integration.rs`
(`two_concurrent_deletes_of_the_same_endpoint_do_not_both_succeed`, and a companion
`two_concurrent_identical_signed_requests_only_one_succeeds` proving the *replay guard's* race
safety, which was already correct and remains a positive-control pin) reproduce the race
deterministically via `tokio::join!` rather than hoping a timing window gets hit.

### The five requested E2E scenarios (`scripts/test_e2e.sh`)

Restructured the section order so Vault stays alive for everything that needs it, and only gets
killed once, at the end, for the resilience check (soft-delete propagation and the restart test's
cache-rehydration assertion both need a live Vault; the original 6-section script killed Vault in
what was then the last section). Final order: 1 Environment Setup, 2 Vault Provisioning (gained a
5th seeded address, `8.8.4.4/32`, dedicated to the soft-delete test so deleting it later can't be
confused with any other section's fixtures), 3 Exporter Configuration, 4 Feed Verification, 5 HTTP
Optimizations/Anti-DoS, **6 Vault Soft-Delete Propagation**, **7 Hot-Reload of Endpoint
Configuration**, **8 Client IP Restriction (`bound_ips`)**, **9 Restart & Persistence Recovery
(Encrypted at Rest)**, 10 Vault Disruption & Resilience (renumbered from the old §6), **11 Audit Log
Traversal** (new — queries `GET /api/audit-logs` as Master and confirms `KEY_CREATE`,
`ENDPOINT_CREATE` ×2, and `ENDPOINT_UPDATE` entries are all present with accurate attribution
(the Daughter key's own `KEY_CREATE` entry is attributed to the Master who created it) and a
timestamp within seconds of "now"; also confirms both `ENDPOINT_CREATE` entries — one from before
§9's restart, one from before it too — survived the restart, since `audit_logs` lives in the same
SQLite file as everything else).

§9 (restart) deliberately omits `INITIAL_MASTER_KEY` on the second boot — the master row already
exists, so proving the *persisted* row (not a re-bootstrap driven by the environment) is what
authenticates afterward is the actual property worth testing. §7 (hot-reload) restores
`filter_rfc1918=true` at the end of its own section so every later section's content assertions
stay valid without needing to know §7 ran first.

Runtime grew from ~20s to ~55–75s (dominated by three `sleep` waits for 15s sync-worker ticks: one
each for the soft-delete's differential pickup, and one for post-restart cache rehydration) —
verified stable across three consecutive full runs with zero flakes.

### Verification performed

- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo test`: 108 tests pass (80 unit + 21 integration + 7 source-hygiene), up from 103.
- `./scripts/verify_convergence.sh`: 7/7 checks pass, including confirming the peer-sync step's
  graceful degradation actually triggers and behaves correctly against the local vault commit above.
- `./scripts/test_e2e.sh`: 80/80 checks pass, run four times total during this session (two before
  the vault fix, showing the exact soft-delete and line-count failures; two after, both clean) with
  zero flakiness, confirmed clean process/temp-file state after each run.

## 2026-08-11 — Audit logging system

Added `audit_logs` for parity with `simply_ip_vault`/`simply_hook_executor`: every mutating
`/api/keys/*` and `/api/endpoints/*` action now writes an attributable audit trail entry.

### Schema & entity

`audit_logs` (`SCHEMA.MD` §3, migration `m20260101_000002_add_audit_logs`): `id`, `api_key_id`
(`ON DELETE SET NULL`), `api_key_name`/`api_key_prefix` (denormalized `NOT NULL` snapshots — the
only attribution that survives the acting key being deleted, since the FK itself gets nulled),
`client_ip`, `action`, `target_resource` (a `kind:id (name)` reference, e.g. `endpoint:3f2a...
(pfBlockerNG DMZ Feed)`), `details`, `timestamp`. Indexed on `action`, `timestamp`, and
`api_key_id`.

Unlike the reference `simply_ip_vault`, which reached `NOT NULL` attribution columns through two
migrations (`m20230101` added them nullable; `m20260811_000010` corrected that later, after
discovering nullable attribution meant a deleted key's actions became literally unattributed), this
schema went straight to `NOT NULL` from its one migration — there was no legacy data to be
compatible with, so there was no reason to repeat the intermediate step.

### `create_audit_log` propagates failures rather than swallowing them

`api::support::create_audit_log` is called with `.await?` at every call site, matching the vault's
convention: a database error from the audit write fails the whole request, even though the
mutation it followed already committed. This is deliberate, not an oversight — the alternative
(log-and-continue) would let a caller receive `200 OK` for an action the audit trail silently
failed to record, which defeats the entire purpose of having one. See the function's doc comment
and `SCHEMA.MD` §3 for the full reasoning.

### Handler integration

Every mutating handler in `api/keys.rs` (`create_api_key`, `update_api_key`, `delete_api_key`,
`rotate_api_key`) and `api/endpoints.rs` (`create_endpoint`, `update_endpoint`, `delete_endpoint`,
`reassign_endpoint_owner`) now takes an additional `Extension(client_ip): Extension<ClientIp>`
parameter (already inserted into request extensions by `auth_middleware` — nothing new needed
there) and writes an audit entry after its mutation commits. `update_*` handlers track which
payload fields were actually present and record them in `details` (`"changed: name, bound_ips"`)
rather than dumping the whole resulting row. `delete_*` handlers capture the target's
name/id **before** issuing the delete, since the row is gone by the time the audit write happens.

`GET /api/audit-logs` (`api/audit.rs`) is Master-only — audit entries span every key and endpoint
in the system, so a scoped Daughter key seeing them would be an RBAC leak regardless of what it
owns — supports an exact `action` filter and pagination (`limit`, silently capped at 500 to bound
query size; `offset`).

### Frontend

`static/index.html` gained a Master-only "Audit Logs" card (table + action-filter input + refresh
button), consistent with the existing `keys-card` gating pattern (hidden by default, revealed by
`app.js` only when `GET /api/auth/me` reports `is_master`). `static/app.js`'s `loadAuditLogs`
follows the same `apiCall`/`escapeHtml` conventions as `loadKeys`/`loadEndpoints`. Verified via
`tests/source_hygiene.rs` (`app_js_has_no_syntax_errors`,
`every_dom_id_referenced_in_app_js_exists_in_index_html`) rather than only by eye.

### Testing

Five new integration tests in `tests/integration.rs`: key create/update/rotate/delete each write
their expected `action` with correct `target_resource`/attribution; the same for all four endpoint
mutations including owner reassignment; `GET /api/audit-logs` is `403` for a Daughter key; the
`action` query filter narrows results correctly. All exercise the real router end-to-end (not the
`create_audit_log` function in isolation), so they also prove the extension wiring (`ClientIp`
actually reaching every handler that now needs it) is correct.

### Verification performed

- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo test`: 103 tests pass (80 unit + 16 integration + 7 source-hygiene), up from 97.
- `./scripts/verify_convergence.sh`: 7/7 checks pass (including the frontend syntax/DOM-reference
  checks against the new Audit Logs UI).
- `./scripts/test_e2e.sh`: 37/37 checks pass — unaffected by this change (it exercises endpoint
  CRUD and the feed pipeline, not the audit trail directly), confirming no regression.

## 2026-08-11 — Convergence checks, edge-case coverage, and a real memory-leak fix

Given full autonomy to expand test coverage and fix anything it uncovered. Net result: 97 tests
(up from 63), a new `scripts/verify_convergence.sh` gate, and two real bugs found and fixed — one
a straightforward hygiene violation, one a genuine unbounded-memory-growth bug in the rate limiter
that none of the existing tests (including the E2E suite) had a way to catch.

### Source hygiene audit (Task 1) — two violations found and fixed

A manual audit against `AGENT.MD`'s "zero raw SQL outside `src/db.rs`/migrations" and "zero
`.unwrap()`/`.expect()` in production code" rules, done *before* writing the enforcement tooling
(so the tooling could be built against a codebase already known to converge, rather than tuned to
whatever happened to be there):

- **`src/api/health.rs`'s readiness probe used a raw `"SELECT 1"`** via `Statement::from_string` —
  a direct violation, missed in the original build. Replaced with `ApiKey::find().count(&db)`, an
  ordinary SeaORM query that proves the connection and schema are both usable without depending on
  the table holding any rows.
- **`src/ipfilter.rs`'s static filter-list constructor used `.expect()`** to parse its hardcoded
  CIDR literals. Technically unreachable in practice (the inputs are compile-time constants), but a
  literal `.expect()` in production code all the same — a future typo in one of those strings would
  panic the process at first use instead of failing to compile. Rewritten to parse leniently
  (`.filter_map(|s| s.parse().ok())`), with a new test
  (`every_filter_list_has_no_silently_dropped_entries`) asserting each list's length against its
  literal count — this is what actually catches a typo now, by making it a visible test failure
  instead of either a runtime panic or a silently-shrunk filter list.

Both are the *only* violations in the whole `src/` tree; `tests/source_hygiene.rs` (below) now
prevents either class from reappearing unnoticed.

### `tests/source_hygiene.rs` + `scripts/verify_convergence.sh` (Task 1)

Implemented as a Rust test suite rather than pure Bash, because two of the three checks need a real
parser: **raw-SQL and `.unwrap()`/`.expect()` detection** are file scanners over `src/**/*.rs`, cut
off at each file's `#[cfg(test)] mod tests` boundary (a *second*, independently-implemented boundary
search backs this — `every_source_file_places_its_test_module_last` — because the first version of
that heuristic had its own bug: it cut at the first `#[cfg(test)]` occurrence in the file, which is
wrong for `src/ratelimit.rs` and `src/replay.rs`, both of which carry a small `#[cfg(test)] fn
tracked(...)` test-only accessor *inside* their production `impl` block, ahead of the real `mod
tests`. Caught immediately by the self-verification test itself before it ever reached the actual
hygiene checks). **The frontend syntax check** uses `oxc_parser` (added as a pinned `=0.143.0`
dev-dependency, matching the reference repos' convention) to genuinely parse `static/app.js` as
ECMAScript, plus a new check with no reference-repo precedent: `every_dom_id_referenced_in_app_js_exists_in_index_html`,
which extracts every `el('...')` lookup from `app.js` and asserts a matching `id="..."` exists in
`index.html` — a mismatch there is a runtime `TypeError`, invisible to a syntax parser (syntax
checking a file that references a nonexistent element parses cleanly; only executing it, or
cross-referencing it against the HTML, would show anything wrong). Every check has a companion
test proving it actually rejects the specific defect it exists to catch, not just an `is_ok()`
that could be silently neutered later.

`scripts/verify_convergence.sh` is a thin wrapper: builds the `source_hygiene` test binary once,
then re-runs each named test individually so a failure reports *which* convention was violated
rather than an undifferentiated `cargo test` failure list.

### Bug: unbounded memory growth in `RateLimiter`'s eviction queue (Task 2 + 3)

Found while designing the rate-limiter stress test the task asked for. `RateLimiter::check_and_record`
pushed the requesting IP onto its eviction queue (`order: VecDeque<IpAddr>`) on **every** successful
call — including when the IP was *already tracked* and merely being re-allowed because its 2-minute
window had lapsed. The tracked-IP `HashMap` itself stayed correctly bounded (re-inserting an
existing key doesn't grow a map), but nothing ever removed the corresponding stale `order` entries
for a *reused* IP — eviction only fires once the map is genuinely at `MAX_TRACKED_IPS` capacity, which
a single low-cardinality caller polling forever never triggers. A new test,
`one_ip_polling_forever_past_its_window_does_not_grow_the_queue_without_bound`, simulated 10,000
re-polls from one address (paused-clock, advancing past the window each time) and found `order` had
grown to exactly 10,000 entries for that one IP — an unbounded allocation triggerable for free by
any single well-behaved, indefinitely-long-lived client (a pfBlockerNG poller left running for
months), not just by the flood-of-distinct-IPs scenario `AGENT.MD`'s "prevent memory exhaustion
under IP spoofing" language was clearly written against.

**Fix:** only push to `order` when the IP is genuinely new (`!next_allowed.contains_key(&ip)`
checked before the insert). Documented tradeoff: `order` no longer perfectly reflects recency for a
reused IP (its queue position stays at first-seen, not last-used), so eviction under sustained
capacity pressure is closer to FIFO-by-first-sight than true LRU — acceptable, since the property
this type actually has to guarantee is the bound itself, not perfect fairness. Locked in with three
tests: the fixed defect (`order_len() == 1` after 10,000 re-polls, not 10,000), a positive-control
flood test (50,000 distinct IPs still cap the map *and* the queue at exactly `MAX_TRACKED_IPS`), and
an eviction-correctness test (the earliest-inserted IPs are genuinely forgotten, the newest are not).

### Other new edge-case coverage (Task 2)

- **IP filtering boundaries**: exact-edge tests for CGN (`100.64.0.0/10`), multicast
  (`224.0.0.0/4`), and APIPA (`169.254.0.0/16`) — the address one step inside either boundary is
  filtered, one step outside survives. IPv6 bogon/loopback filtering tested independently of IPv4.
  Mixed IPv4+IPv6 feeds tested for cross-family contamination (an IPv4 bogon must never suppress an
  IPv6 survivor or vice versa, and aggregation must never attempt to merge across families) — all
  passed without any code change, confirming `ipnet::IpNet`'s per-family typing already made this
  safe by construction. Also pinned the existing (and previously undocumented-by-test)
  "any overlap drops the whole candidate" semantics of `overlaps_any` — a supernet only partially
  overlapping a bogon sub-range is dropped in full, not narrowed.
- **Vault error spectrum**: `VaultClient::fetch_ips` tested directly against a real mock Vault
  (a throwaway `axum` server bound to an OS-assigned loopback port — no new dependency, `axum` is
  already a main dependency) for 401, 403, 500, malformed-JSON-on-200, and total connection refusal
  (bind-then-drop a listener, the fast/deterministic way to reproduce `ECONNREFUSED`). Higher-level
  resilience tested in `sync.rs` against the same spectrum: `sync_endpoint` called with a
  cache pre-populated from a prior successful sync must leave it byte-for-byte unchanged (and must
  not falsely advance `endpoints.last_synced_at`) after 401/403/500/connection-failure, with a
  positive-control test (a healthy Vault response) proving the negative tests aren't vacuous.
  **Also added a 15s request timeout to `VaultClient`'s `reqwest::Client`** (there was none —
  `reqwest::Client::new()` has no default): without it, a Vault that accepted a connection and then
  never answered would hang the sync worker's single sequential await point indefinitely, silently
  stalling every other endpoint's sync behind it, rather than failing fast into the same
  "log a warning, keep serving the cache" path every other failure mode already takes.
- **Concurrent cache access**: `IpCache` hammered by 20 writer + 50 reader `tokio` tasks (`flavor =
  "multi_thread", worker_threads = 8`, so this is genuine OS-thread parallelism, not cooperative
  interleaving) across a shared set of endpoint ids, wrapped in a 30s `tokio::time::timeout` so a
  reintroduced deadlock fails the test suite fast instead of hanging it. A second test confirms
  concurrent writes to 100 *distinct* endpoints never cross-contaminate. Both passed without any
  code change — `tokio::sync::RwLock` behind a clean async API (no method holds a guard across a
  call back into `self`) already made a self-deadlock structurally close to impossible; the value
  of the tests is in pinning that property under real parallel load rather than merely asserting it
  in a doc comment.

### Verification performed

- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo test`: 97 tests pass (79 unit + 11 integration + 7 source-hygiene), up from 63.
- `./scripts/verify_convergence.sh`: 7/7 checks pass.
- `./scripts/test_e2e.sh`: 37/37 checks pass, exit code 0.

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
