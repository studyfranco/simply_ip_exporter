# Simply IP Exporter - Database Schema & SeaORM Specifications

This document defines the official database schema, SeaORM entity models, relationships, and technical specifications for `simply_ip_exporter`. All entities are managed through **SeaORM** (2.0+) and default to **SQLite**.

> **CRITICAL ARCHITECTURAL CONSTRAINT:**
> IP records, subnets, and aggregated feed lists are maintained **STRICTLY IN-MEMORY** (`Arc<RwLock<...>>`).
> They MUST NEVER be stored in SQLite. This database handles local management configuration, API key access, and public endpoint definitions ONLY.

---

## 📊 Entity Relationship Diagram

```
+-------------------+       +---------------------------+
|      api_keys     | 1   M |         endpoints         |
+-------------------+-------+---------------------------+
| id (UUID)         |       | id (UUID)                 |
| name              |       | owner_key_id (UUID)       |
| prefix            |       | name                      |
| key_hash          |       | description               |
| signing_secret    |       | token_secret              |
| bound_ips         |       | vault_groups              |
| is_master         |       | ttl_seconds               |
| master_marker     |       | bound_ips                 |
| can_manage_keys   |       | filter_rfc1918            |
| parent_key_id     |       | filter_bogons             |
| owner_key_id      |       | filter_loopback           |
+----+---------+----+       | last_synced_at            |
     | 1        \            +---------------------------+
     |           \ 1
     | M           \
+----+--------+   +-+-----------------------+
| audit_logs  |   | vault_group_permissions |
+-------------+   +--------------------------+
| id (UUID)   |   | id (UUID)                |
| api_key_id  |   | api_key_id (UUID)         |
| api_key_name|   | vault_group_id (UUID)     |  <- Vault's own group id; not a
| api_key_prfx|   | vault_group_name          |     local FK (Vault is a
| client_ip   |   | created_at                |     separate service/database)
| action      |   +---------------------------+
| target_rsrc |
| details     |
| timestamp   |
+-------------+
```

---

## 📁 Database Tables & Fields

### 1. `api_keys`
Stores administrative authentication keys, global scopes, and CIDR network restrictions.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the API Key. |
| `name` | String | NOT NULL | Human-readable label (e.g., "pfSense DMZ Exporter Admin"). |
| `prefix` | String | NOT NULL, INDEXED | Public identifier prefix (e.g., `sie_exp1`) for display/logs. |
| `key_hash` | String | NOT NULL, UNIQUE, INDEXED | SHA-256 hash of the plaintext secret key. |
| `signing_secret` | Text | NULLABLE | HMAC-SHA256 signing secret encrypted with XChaCha20-Poly1305 when `EXPORTER_ENCRYPTION_KEY` is set (`v1.xchacha20poly1305.<nonce>.<ct>`), or plain fallback (`v1.plain.<hex>`). Never returned by any read endpoint. |
| `bound_ips` | String / Text | NULLABLE | Comma-separated CIDR ranges permitted to use this key. |
| `is_master` | Boolean | NOT NULL, DEFAULT `false` | Bypasses all local RBAC checks. Bootstrap-only, not settable through request payloads. |
| `master_marker` | Integer | **GENERATED**, NULLABLE, UNIQUE (`idx_api_keys_master_marker`) | `1` when `is_master`, `NULL` otherwise — database-level guarantee that at most one Master key exists (`RBAC_MODEL.md` §5). |
| `can_manage_keys` | Boolean | NOT NULL, DEFAULT `false` | Global right to manage **other** local API keys. Master-granted only. |
| `parent_key_id` | UUID / String | NULLABLE, INDEXED (`idx_api_keys_parent_key_id`) | The key that created this one. Lineage tracking for cascading deletion and visibility scoping. |
| `owner_key_id` | UUID / String | NULLABLE, INDEXED (`idx_api_keys_owner_key_id`) | The key answerable for this key record. |
| `created_at` | DateTimeUtc | NOT NULL | Creation timestamp (UTC). |
| `updated_at` | DateTimeUtc | NOT NULL | Last modification timestamp (UTC). |

#### Master uniqueness (`master_marker`)
As required by `RBAC_MODEL.md` §5, "exactly one Master key exists, enforced by a database constraint rather than by application logic alone".
- `master_marker` is defined as `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a plain unique index.
- Because NULLs do not collide in SQL unique indexes, ordinary keys (`is_master = false`) coexist freely, while `is_master = true` is capped at exactly one row.
- The column is omitted from `api_key::Model` so SeaORM never attempts to include it in `INSERT` statements.

---

### 2. `endpoints`
Defines public feed routes exposed at `/feed/v1/<token_secret>/list.txt`.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the endpoint route. |
| `owner_key_id` | UUID / String | NULLABLE, INDEXED (`idx_endpoints_owner_key_id`), FOREIGN KEY (`api_keys.id` ON DELETE SET NULL) | Key holding lifecycle authority over this endpoint route (§3). |
| `name` | String | NOT NULL | Human-readable name (e.g. `pfBlockerNG_Blacklist_DMZ`). |
| `description` | Text | NULLABLE | Detailed summary of the endpoint purpose. |
| `token_secret` | String | NOT NULL, UNIQUE, INDEXED (`idx_endpoints_token_secret`) | Unique random secret token used in the public URL path (`/feed/v1/<token_secret>/list.txt`). |
| `vault_groups` | Text | NOT NULL | Comma-separated list of target group names/UUIDs fetched from `simply_ip_vault`. |
| `ttl_seconds` | Integer | NOT NULL, DEFAULT `3600` | In-memory cache retention duration and refresh interval. |
| `bound_ips` | Text | NULLABLE | Comma-separated allowed CIDR networks for client queries against this public feed endpoint. |
| `filter_rfc1918` | Boolean | NOT NULL, DEFAULT `false` | When `true`, strips private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) from output. |
| `filter_bogons` | Boolean | NOT NULL, DEFAULT `false` | When `true`, strips invalid, unallocated, or reserved IP ranges. |
| `filter_loopback` | Boolean | NOT NULL, DEFAULT `false` | When `true`, strips loopback blocks (`127.0.0.0/8`, `::1`). |
| `last_synced_at` | DateTimeUtc | NULLABLE | Timestamp of the last successful synchronization with `simply_ip_vault`. |
| `created_at` | DateTimeUtc | NOT NULL | Endpoint creation timestamp (UTC). |
| `updated_at` | DateTimeUtc | NOT NULL | Last modification timestamp (UTC). |

---

### 3. `audit_logs`
The audit trail for every mutating `/api/keys/*` and `/api/endpoints/*` action. Written by
`api::support::create_audit_log` immediately after each mutation commits; read exclusively via
`GET /api/audit-logs`, restricted to the Master key (audit entries span every key and endpoint in
the system, so a scoped Daughter key seeing them would be an RBAC leak regardless of what it owns).

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the audit log entry. |
| `api_key_id` | UUID / String | NULLABLE, INDEXED (`idx_audit_logs_api_key_id`), FOREIGN KEY (`api_keys.id` ON DELETE SET NULL) | The key that performed the action. `NULL` once that key is later deleted — the row survives, only the live link is severed. |
| `api_key_name` | String | NOT NULL | The acting key's name, denormalized at write time. Survives the key's deletion, unlike `api_key_id`. |
| `api_key_prefix` | String | NOT NULL | The acting key's prefix, denormalized for the same reason as `api_key_name`. |
| `client_ip` | String | NOT NULL | The caller's resolved client IP (see `middleware::ClientIp`), as text. |
| `action` | String | NOT NULL, INDEXED (`idx_audit_logs_action`) | Operation type: `KEY_CREATE`, `KEY_UPDATE`, `KEY_DELETE`, `KEY_ROTATE`, `KEY_SECRET_ROTATE`, `ENDPOINT_CREATE`, `ENDPOINT_UPDATE`, `ENDPOINT_DELETE`, `ENDPOINT_OWNER_REASSIGN`. |
| `target_resource` | String | NULLABLE | The resource the action targeted, rendered as `kind:id (name)` (e.g. `endpoint:3f2a... (pfBlockerNG DMZ Feed)`). |
| `details` | Text | NULLABLE | Additional context — which fields changed on an update, or a short human-readable summary. |
| `timestamp` | DateTimeUtc | NOT NULL, INDEXED (`idx_audit_logs_timestamp`) | Log entry creation timestamp (UTC). |

#### Attribution survives key deletion
Unlike `endpoints.owner_key_id`, `audit_logs.api_key_id` losing its link on key deletion does not
lose the *attribution* — `api_key_name`/`api_key_prefix` are point-in-time snapshots written once
and never updated, so the audit trail stays legible ("Daughter Key XYZ created endpoint ABC") even
long after that key no longer exists.

#### Write failures are not swallowed
`create_audit_log` propagates a database error rather than logging and continuing. The mutation it
follows has already committed by the time it's called, so silently dropping an audit-write failure
would report `200 OK` for an action the audit trail never recorded. The two are meant to be
inseparable: if the audit write fails, the request fails too.

---

### 4. `vault_group_permissions`
Which local API keys may reference which `simply_ip_vault` groups in their own endpoints'
`vault_groups`. A Daughter key's `POST`/`PUT /api/endpoints` is refused if it names a group the key
holds no grant for (`api::endpoints::validate_group_access`); the Master key is exempt entirely.
There is exactly one right to grant — read — so a grant's mere existence *is* the permission; unlike
`example/simply_ip_vault`'s own `api_key_group_permissions`, there is no `can_read`/`can_write`/
`can_delete`/`can_manage` column set, because this crate never writes back to Vault.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the grant. |
| `api_key_id` | UUID / String | NOT NULL, FOREIGN KEY (`api_keys.id` ON DELETE CASCADE) | The local key this grant applies to. |
| `vault_group_id` | UUID / String | NOT NULL | The Vault group's own id, exactly as Vault assigned it. **Not** a local foreign key — Vault is a separate service reachable only over HTTP, so this database cannot enforce referential integrity against it. |
| `vault_group_name` | String | NOT NULL | The group's name as observed at grant time (or the cleanup worker's last successful refresh) — used for both display and `vault_groups` enforcement without a live Vault call on every use. |
| `created_at` | DateTimeUtc | NOT NULL | Grant timestamp (UTC). |

Unique index on (`api_key_id`, `vault_group_id`): one grant per (key, group) pair — granting an
already-granted group is idempotent, not a duplicate row.

#### Grants outlive the Vault group they reference — deliberately
Because `vault_group_id` cannot be a real foreign key, a grant survives a group being renamed or
deleted in Vault with no signal at all — this crate never re-validates a grant against a live Vault
call on ordinary use. The only place a stale grant is ever removed is
`groups::spawn_group_permission_cleanup_worker`, a background task that runs once at boot and then
monthly: it lists Vault's current groups and deletes any local grant whose `vault_group_id` isn't
among them — but **only** after a live call to Vault actually succeeds. A failed or unreachable
Vault call skips that cycle's cleanup entirely rather than treating "couldn't ask" as "doesn't
exist" and deleting every grant.

---

## 🔗 SeaORM Entity Relations

- **`ApiKey` -> `Endpoint`**: HasMany (`owner_key_id`)
- **`ApiKey` -> `ApiKey` (Parent)**: BelongsTo (`parent_key_id`)
- **`ApiKey` -> `AuditLog`**: HasMany (`api_key_id`)
- **`ApiKey` -> `VaultGroupPermission`**: HasMany (`api_key_id`)

---

## 🔐 Foreign Key Enforcement

| Child Table | Column | Parent Table | On Delete |
| :--- | :--- | :--- | :--- |
| `endpoints` | `owner_key_id` | `api_keys.id` | **`SET NULL`** |
| `audit_logs` | `api_key_id` | `api_keys.id` | **`SET NULL`** |
| `vault_group_permissions` | `api_key_id` | `api_keys.id` | **`CASCADE`** |

### Lineage & Ownership
- `parent_key_id` on `api_keys` is deliberately unconstrained at the database level to prevent recursive CASCADE drops of whole key subtrees outside §6's pre-flight inventory.
- Deleting an API key sets `endpoints.owner_key_id` to `NULL`, transferring lifecycle control over the endpoint route to Master alone.
- Deleting an API key sets `audit_logs.api_key_id` to `NULL` too, but never deletes the audit rows themselves — `api_key_name`/`api_key_prefix` keep them attributable regardless.
- Deleting an API key **cascades** to its `vault_group_permissions` rows — unlike the other two, a permission grant has no meaning once the key it was granted to no longer exists, so nothing worth preserving survives the delete.

---

## ⚡ Database Indexing Summary

1. `api_keys.prefix`: Fast lookup during `X-API-Key` middleware matching.
2. `api_keys.key_hash`: Fast exact matching for authentication hashes.
3. `api_keys.master_marker`: Unique marker index enforcing single Master invariant.
4. `endpoints.token_secret`: Unique index for public URL feed resolution.
5. `endpoints.owner_key_id`: Fast filtering of endpoints by key owner.
6. `audit_logs.action`: Fast filtering by operation type on `GET /api/audit-logs?action=...`.
7. `audit_logs.timestamp`: Fast ordering/pagination of the audit trail (most recent first).
8. `audit_logs.api_key_id`: Fast lookup of a given key's audit history.
9. `vault_group_permissions.(api_key_id, vault_group_id)`: Unique index — one grant per (key, group) pair, and the lookup `validate_group_access` and the cleanup worker both use.

---

## 🔌 Connection Setup (`src/db.rs`)

### SQLite Single Connection Pool
SQLite permits a single concurrent writer. To ensure DDL migrations and configuration writes succeed reliably without locking contention, `SQLITE_MAX_CONNECTIONS = 1` MUST be explicitly enforced on the connection pool.

### Session Pragmas
The following pragmas are initialized on every SQLite connection via `SqliteConnectOptions`:

| Pragma | Value | Scope | Description |
| :--- | :--- | :--- | :--- |
| `foreign_keys` | `ON` | per-connection | Hardens relational integrity enforcement. |
| `journal_mode` | `WAL` | persistent (file header) | Enables concurrent readers alongside a writer. |
| `synchronous` | `NORMAL` | per-connection | Balances durability with high-throughput performance. |
| `busy_timeout` | `5000` ms | per-connection | Prevents instant `SQLITE_BUSY` errors on write lock waits. |