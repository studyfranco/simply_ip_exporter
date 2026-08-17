# Simply IP Exporter - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_ip_exporter`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, documentation standards, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.
4. **`example/`**: You can find the code of other similar/linked project inside. **Read [Peer Repository Synchronization](#-peer-repository-synchronization) before reading anything in here.**

---

## 🔄 Peer Repository Synchronization

`example/` holds **live git clones** of the peer services, not flat snapshots.
They are what `scripts/verify_convergence.sh` compares against and what every convergence or security report describes.

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
- Invalid syntax in `TRUSTED_PROXIES` is fatal at startup.

---

## 🔐 Local RBAC Model (Master / Daughter)

1. **Master Key:** Auto-generated on boot if `api_keys` contains no master records.
   - Holds `is_master = true` and `can_manage_keys = true`.
   - Only key capable of creating or revoking local API keys.
2. **Daughter Keys:** Created by the Master key (`can_manage_keys = false`).
   - May create, edit, and delete their own endpoints/feeds.
   - May **NEVER** create, modify, or list other API keys.
3. **Master Uniqueness & Pinning:**
   - Database level uniqueness via generated marker column.
   - Identity pinned at boot in a write-once `OnceLock`.

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