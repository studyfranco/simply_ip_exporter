# Simply IP Exporter - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_ip_exporter`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, documentation standards, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.
4. **`example/`**: Live checkouts of the wider ecosystem's sibling projects (`simply_ip_vault`, `simply_hook_executor`, `simply_ip_sync`, and any later additions) — reference material for security, structural, and testing-strategy parity, not a dependency of this crate. **Read [Peer Repository Synchronization](#-peer-repository-synchronization) before reading anything in here.**

---

## 🔄 Peer Repository Synchronization

`example/` holds **live git clones** of the peer services, not flat snapshots.
They are what `scripts/verify_convergence.sh` compares against and what every convergence or security report describes.

### Philosophy: why `example/` exists

`simply_ip_exporter` is one member of a wider ecosystem of closely related Rust services that share
one security architecture, implemented independently in each codebase rather than via a shared
library. That ecosystem's structural and security convergence historically originated with two
foundational sibling projects, `simply_ip_vault` and `simply_hook_executor` — the pair
`RBAC_MODEL.md` is scoped to, and the first two services to establish the `CANONICAL_V1` HMAC
scheme, the `SecretCipher` secrets-at-rest envelope, and the boot-time `MasterPin` pattern this crate
also implements. The ecosystem has since scaled: `simply_ip_sync` and `simply_ip_exporter` itself
are later members, each implementing a deliberate, documented subset or extension of the founding
model rather than copying it wholesale (see `AGENT_NOTES.MD` for this crate's own "two-tier, not
three" deviation).

Every sibling project checked out under `example/` — currently `simply_ip_vault`,
`simply_hook_executor`, and `simply_ip_sync`, and any further services the ecosystem grows to
include — serves the same three purposes for an agent working in this repository:

- **Security posture parity.** A pattern this crate implements (signing, replay, secrets at rest,
  RBAC enforcement) can be checked against how the rest of the ecosystem implements the same
  concern, surfacing gaps or regressions neither codebase's own test suite would catch alone.
- **Architectural alignment.** Module layout, naming conventions, and error-handling shape are
  expected to converge across the ecosystem where the underlying concern is shared, and to diverge
  only where the service's actual domain differs. `STRUCTURAL_CONVERGENCE_REPORT.md` is the
  standing record of how well that currently holds.
- **Testing-strategy comparison.** Peer test suites (dedicated concurrency/contract tests,
  source-hygiene scanners, `verify_convergence.sh`/`test_e2e.sh` harnesses) are a live source of
  patterns this crate's own suite may be missing, and vice versa — convergence is not assumed to
  flow only from the founding pair outward; a later project can and does improve on a founder's
  pattern (see `SECURITY_COMPARISON_REPORT.md`'s and `STRUCTURAL_CONVERGENCE_REPORT.md`'s executive
  verdicts for current examples in both directions).

`example/` is reference material for all three purposes, never a dependency of this crate's build,
and never a target of this crate's own commits — see **Rules** below.

### Mandatory: pull before you analyse

**Before reading any file under `example/`, and before generating a convergence, parity, or security report, you MUST run:**

```sh
git -C example/<peer_repo> pull
```

for every peer repo you are about to consult. Skipping this and analyzing a stale checkout risks
comparing against code the peer project has already changed, producing a "convergence" report that
is convergent with the past rather than the present. This does not apply to routine work that
merely *uses* `example/` as a pattern reference during normal feature implementation (as opposed to
producing a comparison/audit artifact) — use judgment, but default to pulling first when in doubt.

`scripts/verify_convergence.sh` automates this at the start of every run for any `example/*`
directory that contains a `.git` — see that script for the graceful offline-mode fallback.

### Rules

- **Pull first, read second.** Not "pull if it looks stale" — staleness is invisible from inside the tree.
- **State the revision.** A report that does not name the peer commit it audited cannot be reproduced or re-checked. Both reports in this repository carry the peer's short SHA in their header.
- **A failed pull is reportable, not ignorable.** If the remote is unreachable, say so in the report and name the local `HEAD` being analysed instead. Silent analysis of an unknown revision is the thing this section exists to prevent.
- **Never commit the peer.** `example/` is `.gitignore`d. Reports about the peer belong in this repository; the peer's own code does not.
- **Read-only.** Never modify, stage, or commit inside a peer checkout. `git pull --ff-only` is the only write this repository's tooling performs there.
- **A bug found in a peer is a report, not a fix.** If auditing a peer checkout turns up a real defect, write it up in `AGENT_NOTES.MD` (with the peer's commit SHA) and stop there — do not patch, and do not carry the fix into this crate's own `src/` unless this crate has the identical bug independently. See `AGENT_NOTES.MD`'s 2026-08-17 (session 2) entry for the current list of `simply_ip_sync` findings reported this way.

---

## 🎯 Project Overview

`simply_ip_exporter` is a high-performance DMZ proxy and IP list exposure daemon written in Rust. It periodically fetches, aggregates, cleans, and deduplicates IP records from a central `simply_ip_vault` instance and exposes plaintext (`text/plain`) feeds formatted for pfSense (`pfBlockerNG`) and external firewall alias list importers.

To protect the underlying storage hardware, **IP records are kept strictly in-memory**. SQLite is utilized exclusively for persistent configuration (endpoints, URL secret tokens, local API keys, and system settings).

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **Default Port:** `3002` (`BIND_HOST` / `PORT`).
- **Encryption Key:** `EXPORTER_ENCRYPTION_KEY` (XChaCha20-Poly1305, 64 hex characters).
- **ORM (Configuration Only):** SeaORM (2.0+). Defaults to **SQLite** for configuration persistence. **Never write vendor-specific raw SQL queries.** Zero raw SQL for DML in `src/`.
- **IP Processing:** `ipnet` crate (`IpNet::aggregate`) for subnet merging and contiguous block consolidation.
- **Frontend:** STRICTLY Vanilla JS, HTML5, and CSS3 embedded SPA. **NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios).
- **Quality & Safety:**
  - Zero compiler warnings, zero `clippy` warnings.
  - **Zero `.unwrap()` or `.expect()`** in production code or HTTP handlers. Use structured `AppError` and Axum's `IntoResponse`.
  - **Mandatory `rustdoc`**: `#![warn(missing_docs)]` enforced in `lib.rs`.

---

## 🏛️ Core Architectural Rules

### 1. In-Memory Cache Engine (Zero Disk Wear for IP Data)

- **In-Memory State (`Arc<RwLock<...>>`):** Cleaned and aggregated IP sets per endpoint/feed are maintained strictly in RAM. IP data is **NEVER** written to SQLite or disk.
- **Hybrid Refresh Protocol:**
  1. **Differential Sync (TTL Expiration):** On endpoint TTL expiry, query Vault using `GET /api/ips?groups=g1,g2&since=<last_sync_timestamp>&include_deleted=true`. Update the in-memory cache incrementally.
  2. **Full Daily Sync (24 Hours):** Once every 24 hours, clear the in-memory state for the feed and execute a full query (`GET /api/ips?groups=g1,g2`) to prevent state drift or orphaned deleted records.
- **Vault API Contract (Commit 6ca29ab Alignment):**
  - **Restrict-not-Reject:** Queries with `include_deleted=true` return HTTP 200 with soft-deleted records (`is_deleted: true`, `deleted_at: ...`) for authorized groups. Restricted or unknown groups are silently filtered out by the Vault (no `403` error).
  - **Timestamp Serialization:** All timestamp fields (`created_at`, `updated_at`, `deleted_at`) arrive as UTC Naive ISO-8601 strings (e.g. `"2026-08-11T10:26:46"`). Parse uniformly using `chrono::NaiveDateTime` for `since` delta filtering.
- **Fallbacks & Fault Tolerance:** If `simply_ip_vault` is offline or unreachable during a refresh cycle, `simply_ip_exporter` continues serving the existing in-memory cached list to public clients while logging a warning.

### 2. Public Feed Exposure (`/feed/v1/<token_secret>/list.txt`)

- **Authentication:** Unauthenticated in terms of HTTP headers. Security is established via unique 128-bit entropy URL secret tokens (`<token_secret>`).
- **Network Filtering (`bound_ips`):** Optional CIDR network filtering per endpoint. Requests originating from outside configured `bound_ips` receive `403 Forbidden`.
- **In-Memory Anti-DoS / Rate Limiting:**
  - Restrict public queries per client source IP (e.g., maximum 1 request every 2 minutes per IP).
  - Track client IPs using an in-memory bounded LRU / map with a hard ceiling (`MAX_TRACKED_IPS = 10000`) to prevent memory exhaustion under IP spoofing attacks. Excess attempts receive `429 Too Many Requests`.
- **HTTP Optimizations:**
  - Compute SHA-256 hash of the generated text body as `ETag`.
  - If the client sends a matching `If-None-Match` header, respond immediately with `304 Not Modified` (0 bytes payload).
- **Pipeline & Sanitization:**
  - Format output strictly as `text/plain` (one IP/CIDR per line).
  - Use `ipnet::IpNet::aggregate()` to collapse contiguous blocks and overlapping subnets.
  - Optional per-endpoint switches:
    - `filter_rfc1918`: Remove private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
    - `filter_bogons` / `filter_loopback`: Strip loopback (`127.0.0.0/8`, `::1`) and invalid ranges.

### 3. Security & Network Protocols

#### Outbound Vault Communication (`Exporter -> Vault`)
- Authenticates using **HMAC-SHA256 (`CANONICAL_V1`)** over headers:
  - `X-API-Key`
  - `X-Timestamp` (UTC seconds)
  - `X-Signature-256` (`sha256=<hex>`)
- Signature payload: `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`.
- Interoperable regardless of whether `simply_ip_vault` runs on SQLite or PostgreSQL.
- Secrets stored in SQLite encrypted at rest via `EXPORTER_ENCRYPTION_KEY` (XChaCha20-Poly1305).

#### Inbound Administrative WebUI & API (`/api/*`)
- Secured with **HMAC-SHA256 (`CANONICAL_V1`)**, matching the security model of `simply_ip_vault` and `simply_hook_executor`.
- Single-use anti-replay guard with a symmetric ±300-second freshness window.

#### IP Extraction & Trusted Proxies
- Respect `X-Forwarded-For` / `X-Real-IP` **only** when TCP peer is in `TRUSTED_PROXIES`.
- Walk `X-Forwarded-For` right-to-left, skipping trusted proxy hops.
- `TRUSTED_PROXIES` entries may be a literal address, a CIDR range, **or a hostname/Docker
  container name** (2026-08-19, e.g. `traefik_tomidejetsu`), resolved via DNS
  (`config::TrustedProxies`, ported from `example/simply_ip_vault`/`example/simply_hook_executor`'s
  identical design — see `AGENT_NOTES.MD`). A well-formed hostname is accepted **whether or not it
  currently resolves**; only a genuinely unparseable entry (not an address, not a CIDR, not shaped
  like a hostname) is fatal at startup. An unresolvable hostname is not trusted until it resolves
  (fails closed, per-entry, not service-wide) and is retried in the background: once immediately at
  boot, once more after a 60s grace period (a container and its reverse proxy often start
  together, and the proxy's DNS record may not exist for the first few seconds), and thereafter on
  every request whose 30s/5s positive/negative cache entry has expired. Startup is never blocked
  waiting on DNS.

---

## 🔐 Local RBAC Model (Master / Daughter)

1. **Master Key:** Auto-generated on boot if `api_keys` contains no master records.
   - Holds `is_master = true` and `can_manage_keys = true`.
   - Only key capable of creating or revoking local API keys.
   - **Immutable through the API** beyond its own `bound_ips`: `PUT /api/keys/{id}` refuses any
     request touching `name` or `can_manage_keys` when the target is the Master
     (`api::guards::guard_master_update`), and deletion/rotation are refused outright
     (`api::guards::guard_master_delete_or_rotate`, shared by both `POST /api/keys/{id}/rotate`
     — replaces the API key *and* signing secret — and the narrower `POST
     /api/keys/{id}/rotate-secret`, which replaces only the signing secret). `is_master` itself
     needs no separate guard — it is not a field on `CreateKeyPayload`/`UpdateKeyPayload` at all, so
     no request body can name it regardless of which key is targeted.
2. **Daughter Keys:** Created by the Master key (`can_manage_keys = false`).
   - May create, edit, and delete their own endpoints/feeds.
   - May **NEVER** create, modify, or list other API keys.
3. **Master Uniqueness & Pinning:**
   - Database level uniqueness via generated marker column.
   - Identity pinned at boot in a write-once `tokio::sync::OnceCell`.

### Why two tiers, not three

This is a deliberate scope boundary, not an unfinished migration toward the fuller model. `example/`
peers `simply_ip_vault` and `simply_hook_executor` implement a three-tier Master/Parent/Daughter
model with M:N per-resource group permissions (`RBAC_MODEL.md`, scoped to those two projects
specifically) because their domains need it: multiple tenants sharing partial, overlapping access to
the same managed resources. `simply_ip_exporter` has no such requirement — it is a **single-purpose
feed exposition daemon**. Every endpoint has exactly one owner at a time (`endpoints.owner_key_id`);
there is no concept of two keys jointly administering the same endpoint with different verbs, no
delegated-grant mechanism to reason about, and therefore no R1–R7-style conjunction rules for a third
tier to enforce. Adding one would mean building and maintaining an authorization surface with no
present requirement driving its shape — see `STRUCTURAL_CONVERGENCE_REPORT.md`'s note that this
divergence from the wider ecosystem is domain-justified, not a gap.

`src/api/guards.rs` exists despite the small RBAC surface for the same reason three of four
`example/` peers already centralize their own authorization decisions: reviewability. It holds
exactly the checks a two-tier model actually needs (`require_master`,
`guard_master_delete_or_rotate`, `guard_master_update`) — not a scaffold for tiers this crate does
not have.

### Endpoint ownership: transfer and the `DELETE /api/keys/{id}` conflict

An endpoint's `owner_key_id` is a single, exclusive pointer, reassignable in two ways:

- **Explicitly**, at any time, via `PUT /api/endpoints/{id}/owner` (Master-only) — a direct,
  single-write reassignment with no other side effect.
- **As a side effect of deleting the owning key**, via `DELETE /api/keys/{id}?reassign_to=<key id>`.
  A key that still owns endpoints cannot simply be deleted out from under them:
  - **Without `reassign_to`**, if the target key owns any endpoints, the delete is refused with
    `409 Conflict` and a structured body — `{"error": "...", "owned_endpoints": [{"id", "name"}, ...]}`
    (`AppError::ConflictWithDetails`) — naming exactly what is blocking the delete, so the caller
    does not have to separately query `GET /api/endpoints` to discover it.
  - **With `reassign_to`**, the reassignment (`Endpoint::update_many().filter(...).col_expr(...)`)
    and the key deletion happen inside one `SeaORM` transaction (`state.db.begin()` /
    `txn.commit()`), including the audit log write — either the endpoints move to their new owner
    and the old key is gone, or neither happens. A losing concurrent delete of the same key
    (`rows_affected == 0` on the delete itself) rolls the whole transaction back, including any
    reassignment already applied within it, rather than leaving endpoints reassigned to a delete
    that never actually took effect.
  - `reassign_to` must name an existing key other than the one being deleted; either violation is
    `400 Bad Request`, checked *inside* the transaction so the check and the write it gates observe
    a consistent snapshot.
  - This is why `endpoints.owner_key_id` being `ON DELETE SET NULL` at the schema level (see
    `SCHEMA.MD`) is a *backstop*, not the primary mechanism: the API path above is what a normal
    admin-driven deletion goes through, and it never lets ownership silently fall through to `NULL`
    without the caller either being told first (`409`) or explicitly redirecting it (`reassign_to`).

### Multi-backend readiness (SQLite, PostgreSQL, MariaDB)

`SCHEMA.MD`/AGENT.MD historically describe this crate's configuration store as SQLite-exclusive in
practice, but every query, migration, and transaction in `src/` is written to be portable regardless:

- All mutations go through SeaORM's entity/query builders (`ActiveModel::update`,
  `Entity::update_many().col_expr(...)`, `Entity::delete_by_id`) or `db.transaction`/explicit
  `begin()`/`commit()` — never a hand-assembled, backend-specific SQL string. `tests/source_hygiene.rs`
  enforces the "zero raw SQL outside `src/db.rs`/`src/migration/`" half of this mechanically.
- The one place this crate previously used a non-portable check — `master.rs::pin_at_boot`'s
  uniqueness-index lookup, via `sea_orm_migration::SchemaManager::has_index`, which answers
  `BackendNotSupported` on PostgreSQL rather than correctly reporting the index — was replaced
  2026-08-18 with `db::has_index`, a per-backend catalog query (`sqlite_master`/`pg_indexes`/
  `information_schema.statistics`) ported from `simply_ip_vault`'s identical fix. See
  `AGENT_NOTES.MD` (session 5) for the incident this addresses.
- `src/migration/`'s DDL (`ColumnDef`/`Table`/`ForeignKey` builders, plus the one documented raw-SQL
  exception for `api_keys.master_marker`'s `GENERATED ALWAYS AS` column, which has no SeaQuery
  builder representation on any backend) uses no vendor-specific syntax either.

---

## 🗄️ Database Migrations (SeaORM)

### Naming convention

Every migration file is named `m<YYYYMMDD>_<HHMMSS>_<migration_name>.rs`: an `m` prefix, an 8-digit
UTC date, an underscore, a 6-digit UTC time-of-day, an underscore, and a `snake_case` description.
Both of this crate's current migrations — `m20260811_115204_initial_schema.rs` and
`m20260811_152352_add_audit_logs.rs` — carry their real authorship timestamp (derived from git
history at the time each was renamed into this form; see `AGENT_NOTES.MD`, 2026-08-19).

A 6-digit segment that is instead a plain monotonic sequence counter (`000001`, `000002`, …) — the
shape `sea-orm-cli migrate generate` produces by default, and what every other project in the wider
`example/` ecosystem currently uses (see `AGENT.MD`'s "Peer Repository Synchronization" section) — is
also accepted and orders correctly against a real-timestamp segment or another counter; the
requirement is a valid 6-digit value in that position, monotonically non-decreasing against every
migration before it, not that it be a literal clock reading. Prefer a real timestamp for a new
migration when convenient; do not renumber an existing file's counter into a synthetic timestamp
just to convert its shape (see below).

### Renaming an already-generated migration is forbidden (outside a narrow, explicit exception)

**Never rename, renumber, or reorder a migration file that has already been committed**, with one
narrow exception: this crate has not yet reached a real deployment, and its owner explicitly
authorized a one-time rename of both existing migrations for exactly that reason (2026-08-19, see
`AGENT_NOTES.MD`) after this document's own prior wording had declined the same request on safety
grounds. That authorization does not generalize — the reason the rule exists is unchanged and takes
effect again the moment a real deployment exists, including this crate's own CI/test databases only
being exempt because they are ephemeral, never because a rename is generally low-risk.

The rule itself: SeaORM tracks applied migrations by filename (the `seaql_migrations` table records
each migration's version string as derived from its module name) — renaming a migration after it has
run against any real database, including a deployed instance this crate's own maintainers cannot
see, orphans that row: the running service no longer recognizes its own migration history, and on
next boot either silently re-attempts a migration already applied (erroring on an object that
already exists) or skips one it should have run. A migration needing correction after a real
deployment exists gets a new, later migration that fixes it forward instead; the original file's
name and contents are never touched again from that point on.

### Audit attribution & soft-deletion interaction

`audit_logs`' attribution columns (`api_key_name`, `api_key_prefix`) are `NOT NULL` from this
crate's *first* migration that creates the table — not retrofitted after a backfill, because the
schema was designed to avoid ever needing one. This is deliberate and must not regress:

- `api_key_id` (the *live* foreign key to `api_keys`) is nullable, with `ON DELETE SET NULL` — so
  deleting the acting key never deletes or blocks deletion of the audit rows it wrote; the link
  simply severs.
- `api_key_name`/`api_key_prefix` are **denormalized snapshots**, captured at write time and never
  updated afterwards. They carry no foreign key at all, so they are free to be `NOT NULL` without
  ever conflicting with the `SET NULL` behavior on `api_key_id` — the two columns answer different
  questions ("what can we still join to" vs. "what did we already know and record"), and only the
  first one is allowed to go empty.
- Any future migration adding a new denormalized attribution column must follow this same shape:
  `NOT NULL` on the snapshot, nullable + `SET NULL` only on the live reference, with a data backfill
  in the migration's own `up()` *before* the `NOT NULL` constraint is added if the column is not
  present from the table's first migration.

---

## 🌐 Public Probes

- `GET /health` or `/healthz`: Liveness probe (HTTP 200 `{"status":"ok","service":"simply_ip_exporter"}`). No DB query.
- `GET /ready` or `/readyz`: Readiness probe (HTTP 200 if DB is up and master key pinned, HTTP 503 otherwise).

---

## 🧪 Testing & Validation Standards

1. **In-Memory Cache Integrity:** Assert differential updates properly merge new records, handle `include_deleted=true` soft-deletes, and parse UTC Naive ISO-8601 timestamps without disk I/O.
2. **IP Aggregation (`ipnet`):** Verify overlapping subnets (e.g. `10.0.0.0/24` and `10.0.0.1/32`) consolidate into a single CIDR (`10.0.0.0/24`).
3. **ETag & 304 Responses:** Assert `If-None-Match` returns `304 Not Modified` when content is unchanged.
4. **Public Anti-DoS:** Verify source IPs querying within the 2-minute window are throttled with `429 Too Many Requests` while LRU tracking memory stays capped.
5. **HMAC Canonical Signing:** Test inbound and outbound signed requests against invalid signatures, tampered query parameters, and replay attempts.