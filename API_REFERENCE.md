# `simply_ip_exporter` — API Reference

Exhaustive catalogue of every HTTP route this service exposes: the administrative API, the public
feed, and the probes. Generated from an audit of `src/lib.rs`'s route table and every handler,
extractor, guard and middleware it reaches.

Companion to `AGENT.MD` (the architectural ruleset), `SCHEMA.MD` (persisted shapes) and
`RBAC_MODEL.md` (the wider Master/Parent/Daughter spec this crate implements a two-tier subset of).
Structured to mirror `example/simply_ip_vault/API_REFERENCE.md`, so an operator moving between the
two services reads the same document twice.

## Contents

- [1. Route map](#1-route-map)
- [2. Authentication](#2-authentication)
- [3. Error model](#3-error-model)
- [4. Conventions](#4-conventions)
- [5. Health & readiness (unauthenticated)](#5-health--readiness-unauthenticated)
- [6. Public feed (URL-secret authenticated)](#6-public-feed-url-secret-authenticated)
- [7. Identity](#7-identity)
- [8. API keys](#8-api-keys)
- [9. Endpoints](#9-endpoints)
- [10. Vault group access](#10-vault-group-access)
- [11. Audit log](#11-audit-log)
- [12. Static dashboard](#12-static-dashboard)

---

## 1. Route map

Every route registered in `create_app` (`src/lib.rs`), in one place. "Auth" is the *primary*
gate; §2 covers what every `/api/*` route additionally requires.

| Method | Path | Auth | Section |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` · `/healthz` | none | [§5](#5-health--readiness-unauthenticated) |
| `GET` | `/ready` · `/readyz` | none | [§5](#5-health--readiness-unauthenticated) |
| `GET` | `/feed/v1/{token_secret}/list.txt` | URL secret | [§6](#6-public-feed-url-secret-authenticated) |
| `GET` | `/api/auth/me` | signed | [§7](#7-identity) |
| `POST` | `/api/keys` | signed + Master | [§8](#8-api-keys) |
| `GET` | `/api/keys` | signed + Master | [§8](#8-api-keys) |
| `PUT` | `/api/keys/{id}` | signed + Master | [§8](#8-api-keys) |
| `DELETE` | `/api/keys/{id}` | signed + Master | [§8](#8-api-keys) |
| `POST` | `/api/keys/{id}/rotate` | signed + Master | [§8](#8-api-keys) |
| `POST` | `/api/keys/{id}/rotate-secret` | signed + Master | [§8](#8-api-keys) |
| `POST` | `/api/endpoints` | signed (any key) | [§9](#9-endpoints) |
| `GET` | `/api/endpoints` | signed (scoped) | [§9](#9-endpoints) |
| `PUT` | `/api/endpoints/{id}` | signed + owner/Master | [§9](#9-endpoints) |
| `DELETE` | `/api/endpoints/{id}` | signed + owner/Master | [§9](#9-endpoints) |
| `PUT` | `/api/endpoints/{id}/owner` | signed + Master | [§9](#9-endpoints) |
| `GET` | `/api/vault-groups` | signed + Master | [§10](#10-vault-group-access) |
| `GET` | `/api/keys/{id}/groups` | signed + Master or self | [§10](#10-vault-group-access) |
| `POST` | `/api/keys/{id}/groups` | signed + Master | [§10](#10-vault-group-access) |
| `DELETE` | `/api/keys/{id}/groups/{permission_id}` | signed + Master | [§10](#10-vault-group-access) |
| `GET` | `/api/audit-logs` | signed + Master | [§11](#11-audit-log) |
| `GET` | *(any unmatched path)* | none | [§12](#12-static-dashboard) |

**There are no path aliases.** Unlike `simply_ip_vault` (which serves `/api/groups` and
`/api/ip_groups` as synonyms), every route here is registered exactly once. A path not in this
table falls through to the static file service (§12), so a typo'd API path returns the dashboard's
`404` from `ServeDir`, **not** this service's JSON error envelope.

---

## 2. Authentication

Everything under `/api/*` passes through `middleware::auth_middleware`. Probes, the public feed and
the static fallback sit **outside** it — deliberately, since none of their callers can compute an
HMAC (see each section).

### Required headers

| Header | Value |
| :--- | :--- |
| `X-API-Key` | The key's plaintext secret, exactly as issued. |
| `X-Timestamp` | Unix seconds, as a decimal string. |
| `X-Signature-256` | `sha256=<hex>` — HMAC-SHA256 over the canonical payload below. |
| `Content-Type` | `application/json` on any request carrying a body. |

### `CANONICAL_V1` payload

```
METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY
```

- `METHOD` is upper-case (`GET`, `POST`, `PUT`, `DELETE`).
- `PATH_AND_QUERY` **includes the query string** (`/api/audit-logs?limit=10`), and is read from
  axum's `OriginalUri` — the path the client sent, not the path relative to the `/api` mount.
- `RAW_BODY` is the exact request body bytes; empty when there is no body.

### Anti-replay

Two independent halves, both enforced:

1. **Freshness** — `|server_time - X-Timestamp| > SIGNATURE_MAX_AGE_SECONDS` (default **300**) is
   rejected. The window is *symmetric*: a future-dated timestamp is as suspect as a stale one.
2. **Single use** — a `(key_id, signature)` pair already accepted inside that window is rejected.
   Checked **after** the HMAC verifies.

> **Operational consequence.** A signature covers method, target, timestamp and body and nothing
> else, so **repeating a call unchanged within the same wall-clock second is indistinguishable from
> a replay** and is refused `401`. Real clients never hit this — a retry lands on a later timestamp.
> A caller that genuinely needs the same request twice in one second must wait.

### Ordering, and why it is fixed

`auth_middleware` runs: resolve client IP → validate `X-Timestamp` → look up key by hash → pin-check
Master identity → buffer body → verify HMAC → replay check → **`bound_ips` last**.

Step order is load-bearing. The timestamp check precedes any database work, so a stale or malformed
one costs an unauthenticated caller nothing. `bound_ips` is evaluated only *after* the signature
verifies, so a caller holding a leaked `X-API-Key` alone cannot use the `403`-vs-`401` split to map
which networks a key is bound to.

### `bound_ips` (network restriction)

Each key may carry a comma-separated allowlist of CIDR ranges, bare IPs, **and hostnames**
(resolved at request time through a shared 30s/5s positive/negative DNS cache — see
`src/bound_ips.rs`). Empty or absent means unrestricted. A caller outside the list gets `403`
`{"error": "Client IP not allowed"}`.

The address compared is the *resolved* client IP: `X-Forwarded-For` / `X-Real-IP` are honoured
**only** when the TCP peer is itself listed in `TRUSTED_PROXIES`; otherwise the raw peer address is
used. `X-Forwarded-For` is walked right-to-left, skipping trusted hops.

### Request size

A global `DefaultBodyLimit` of **3 MiB** (`MAX_REQUEST_BODY_BYTES`) applies to `/api/*` and the
static fallback alike. A declared `Content-Length` over the limit is refused `413` before any body
is read; a chunked body that exceeds it mid-stream hits the same `413` from the buffering read.

---

## 3. Error model

Every failure on every `/api/*` route and the feed returns the same envelope, defined once in
`src/error.rs`:

```json
{ "error": "human-readable message" }
```

| `AppError` variant | Status | Notes |
| :--- | :--- | :--- |
| `InvalidInput` | `400` | Failed validation, malformed payload, unknown field/parameter. |
| `BodyRejected` | *passes through* | Carries an extractor's own status verbatim — `400` for a malformed body, `413` for an oversized one. Exists so a size rejection is not flattened into a generic `400`. |
| `Unauthorized` | `401` | Missing/invalid credentials, bad signature, stale timestamp, replayed signature. |
| `Forbidden` | `403` | Authenticated but not permitted — RBAC guard, or `bound_ips`. |
| `NotFound` | `404` | `{"error": "Resource not found"}`. |
| `Conflict` | `409` | |
| `ConflictWithDetails` | `409` | **The one variant whose body is not just `error`** — machine-readable detail is merged at the *top level* alongside `error`, so a client reading only `error` behaves identically. See `DELETE /api/keys/{id}`. |
| `TooManyRequests` | `429` | |
| `DbError` | `500` | Logged server-side; the client sees only `"Internal database error"`. |
| `Internal` | `500` | |
| `VaultNotConfigured` | `503` | No `VAULT_BASE_URL`/`VAULT_API_KEY`/`VAULT_SIGNING_SECRET` — an operator configuration state, not a bug. |
| `VaultUnreachable` | `502` | A live call to Vault failed. This service is a *client* of Vault for that request, and the upstream did not answer usably. |

---

## 4. Conventions

- **Unknown fields are refused, not ignored.** Every request body and query struct carries
  `#[serde(deny_unknown_fields)]`, so a mistyped field (`bound_ip` for `bound_ips`) returns `400`
  naming it rather than silently doing nothing. This is also what makes privilege escalation
  structurally impossible on `POST /api/keys`: `is_master` is absent from the payload type *and*
  a stray `"is_master": true` is refused outright.
- **Strict extractors.** `StrictJson` / `StrictPath` / `StrictQuery` (`src/extract.rs`) re-map
  axum's own rejections into the envelope above, so a malformed UUID path segment or query string
  never escapes as axum's plain-text default.
- **Timestamps** are UTC naive ISO-8601 (`"2026-08-11T10:26:46"`), matching `SCHEMA.MD`.
- **`PUT` semantics on optional fields:** an **absent** field means "leave unchanged"; a
  **present-but-empty string** means "clear it". Sending `null` is therefore *not* how a field is
  cleared — `""` is.
- **Secrets are shown once.** A minted `api_key` / `signing_secret` is returned only by the call
  that creates or rotates it. No read endpoint ever echoes either.

---

## 5. Health & readiness (unauthenticated)

Mounted **outside** `auth_middleware`. The callers are Docker's `HEALTHCHECK`, Kubernetes probes and
load balancers, none of which can compute an HMAC over a rolling timestamp. Both handlers are safe
without a caller identity: no data, no error detail, no writes.

### `GET /health` · alias `GET /healthz`

**Handler:** `api::health_check` · **Auth:** none · **Liveness.** Always `200`, never touches the
database.

**Response `200`**

```json
{ "status": "ok", "service": "simply_ip_exporter" }
```

### `GET /ready` · alias `GET /readyz`

**Handler:** `api::readiness_check` · **Auth:** none · **Readiness.**

`200` only when **both** hold: the database answers a `count()` against `api_keys` (an ordinary
SeaORM query, not raw SQL — `AGENT.MD` forbids raw SQL outside `src/db.rs` and migrations), and the
Master identity is pinned (`MasterPin`). Otherwise `503`.

**Response `200`**

```json
{ "status": "ready" }
```

**Response `503`** — names which half failed, so an operator does not have to guess:

```json
{ "status": "not_ready", "database": true, "master_pinned": false }
```

> The Dockerfile's `HEALTHCHECK` polls `/ready`, not `/health`: a container whose database is
> unreachable or whose Master row is missing is *live* but cannot serve, and should be taken out of
> rotation.

---

## 6. Public feed (URL-secret authenticated)

### `GET /feed/v1/{token_secret}/list.txt`

**Handler:** `feed::serve_feed` · **Auth:** the 128-bit `token_secret` embedded in the path **is**
the credential. No HMAC, no headers.

This shape is deliberate: pfBlockerNG and comparable importers fetch a remote list with a bare `GET`
and no custom headers, so a header-based credential would be unusable. Security rests entirely on
the secrecy of the URL.

**Path parameters**

| Name | Type | Description |
| :--- | :--- | :--- |
| `token_secret` | string | The endpoint's `token_secret`, as issued at creation. An unknown token is `404`. |

**Query parameters:** none.

**Request headers**

| Header | Required | Description |
| :--- | :--- | :--- |
| `If-None-Match` | no | Conditional revalidation. A value matching the current `ETag` is answered `304`. |

**Response headers**

| Header | Description |
| :--- | :--- |
| `Content-Type` | `text/plain; charset=utf-8` on `200`. |
| `ETag` | `"<sha256 hex>"` of the exact body. Returned on both `200` and `304`. |
| `Retry-After` | Seconds remaining in the throttle window. `429` only. |

**Response `200`** — one aggregated CIDR/address per line, sorted, `\n`-terminated:

```
8.8.4.4/32
8.8.8.0/24
2a01:4f8:1::1/128
```

The body is produced by, in order: the endpoint's `max_age_seconds` retention window (records whose
`updated_at` is older than `now - max_age_seconds` are excluded; `0` = unlimited), then the
`filter_rfc1918` / `filter_bogons` / `filter_loopback` switches, then `ipnet::IpNet::aggregate()`
over the survivors. IPv4 and IPv6 are aggregated independently and never merged across families.

An endpoint with no cached records returns `200` with an **empty body** — which is the correct
answer only when the endpoint genuinely has nothing. To keep that from also being the answer during
startup, `sync::run_boot_sync` completes one full pass *before* the listener binds.

**Response `304`** — empty body, `ETag` echoed. **Consumes no rate-limit budget:** the caller has
already proven it holds a current copy, and throttling a well-behaved revalidating poller would
defeat the mechanism's purpose. Guessing an ETag is not a workable bypass — an attacker without the
current body cannot produce a matching digest.

**Response `403`** — `Client IP not allowed for this endpoint`. The endpoint's own `bound_ips`
(CIDR / IP / hostname, resolved through the same cached DNS pipeline as §2) evaluated against the
resolved client IP. Separate from, and additional to, any admin key's `bound_ips`.

**Response `404`** — unknown `token_secret`. Deliberately indistinguishable from a token that never
existed.

**Response `429`** — `Rate limit exceeded: at most one request per source IP every 2 minutes`, with
`Retry-After`. Throttles the **expensive path only** (a full `200` body), keyed on the resolved
client IP, with at most `MAX_TRACKED_IPS` (10 000) addresses tracked and FIFO eviction beyond that.

---

## 7. Identity

### `GET /api/auth/me`

**Handler:** `api::get_me` · **Auth:** any authenticated key. No RBAC gate — every key may
introspect itself, and only itself.

**Query parameters / body:** none.

**Response `200`**

```json
{
  "id": "uuid",
  "name": "System Master",
  "prefix": "a1b2c3d4",
  "is_master": true,
  "can_manage_keys": true,
  "bound_ips": "0.0.0.0/0,::/0"
}
```

`bound_ips` is `null` when unrestricted. This is what the bundled dashboard calls first, to decide
which tabs to render.

---

## 8. API keys

Every route in this section is **Master-only** (`guards::require_master`); a Daughter key gets `403`
`Only the Master key can manage API keys`. See `AGENT.MD`'s "Why two tiers, not three" for why this
crate does not implement `RBAC_MODEL.md`'s full delegation model.

### `POST /api/keys`

Mints a Daughter key, parented and owned by the caller.

**Body** (`CreateKeyPayload`, `deny_unknown_fields`)

| Field | Type | Req. | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `name` | string | **yes** | — | Must not be empty/whitespace. |
| `bound_ips` | string \| null | no | `null` | Comma-separated CIDR / IP / hostname allowlist. Each entry is validated; a malformed one is `400`. |
| `can_manage_keys` | bool | no | `false` | |

> `is_master` is **not a field on this type**, so a new key can never be minted as Master; combined
> with `deny_unknown_fields`, sending it is a `400` naming the field rather than a silent no-op.

**Response `200`** (`MintedKeyResponse` — the full key object plus both secrets, shown **once**):

```json
{
  "id": "uuid", "name": "pfSense", "prefix": "e4f5a6b7",
  "bound_ips": null, "is_master": false, "can_manage_keys": false,
  "parent_key_id": "uuid", "owner_key_id": "uuid",
  "created_at": "...", "updated_at": "...",
  "api_key": "<64 hex — shown once>",
  "signing_secret": "<shown once>"
}
```

**Errors:** `400` empty name / invalid `bound_ips` / unknown field · `403` not Master.

### `GET /api/keys`

**Response `200`** — array of `KeyResponse` (the object above **without** `api_key` /
`signing_secret`; neither is ever echoed by a read).

### `PUT /api/keys/{id}`

**Body** (`UpdateKeyPayload`, `deny_unknown_fields`) — every field optional; absent means unchanged.

| Field | Type | Description |
| :--- | :--- | :--- |
| `name` | string | |
| `bound_ips` | string | **`""` clears the restriction**; absent leaves it unchanged. |
| `can_manage_keys` | bool | |

**Master immutability** (`guards::guard_master_update`): when the target is the Master key, `name`
or `can_manage_keys` being *merely present* — even carrying the current value — is refused `403`
`The Master key is immutable through the API except for its own bound_ips`. Only `bound_ips` may be
changed on Master.

**Response `200`** — the updated `KeyResponse`. **Errors:** `400` · `403` · `404`.

### `DELETE /api/keys/{id}`

**Query parameters** (`DeleteKeyQuery`, `deny_unknown_fields`)

| Name | Type | Req. | Description |
| :--- | :--- | :--- | :--- |
| `reassign_to` | UUID | no | If the target owns endpoints, transfer them to this key **in the same transaction** as the delete. Omit when the target owns nothing. |

The Master key cannot be deleted (`403`). Concurrent-delete safety comes from `rows_affected`, not
merely "the query did not error": a second delete of a row already gone is `404`, and writes no
second audit entry.

**Response `204`** — deleted.

**Response `409`** — the target still owns endpoints and no `reassign_to` was given. This is
`ConflictWithDetails`: the inventory is merged at the **top level** so the caller can resolve it
without a second round-trip.

```json
{
  "error": "this key still owns 2 endpoint(s); reassign or delete them first, or retry with ?reassign_to=<key id>",
  "owned_endpoints": [ { "id": "uuid", "name": "pfBlockerNG DMZ Feed" } ]
}
```

**Errors:** `400` `reassign_to` naming a nonexistent key (nothing is changed) · `403` Master or not
Master-authenticated · `404`.

### `POST /api/keys/{id}/rotate`

Replaces **both** credential halves — a new `api_key` *and* a new `signing_secret`. The previous
pair stops working immediately. Refused against the Master key (`403`).

**Response `200`** — `MintedKeyResponse`, as `POST /api/keys`.

### `POST /api/keys/{id}/rotate-secret`

The narrower sibling: replaces **only** the signing secret. The `X-API-Key`, `name`, `bound_ips` and
`can_manage_keys` are untouched by construction. Refused against the Master key (`403`).

**Response `200`** (`RotateSigningSecretResponse`) — note there is no `api_key` field, because it
did not change:

```json
{ "id": "uuid", "name": "pfSense", "signing_secret": "<new — shown once>" }
```

---

## 9. Endpoints

An endpoint is one public feed route. **Any authenticated key may create one**, and becomes its
owner; managing an existing one requires being that owner or the Master key (`may_manage`).

### `POST /api/endpoints`

**Body** (`CreateEndpointPayload`, `deny_unknown_fields`)

| Field | Type | Req. | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `name` | string | **yes** | — | Must not be empty/whitespace. |
| `description` | string \| null | no | `null` | |
| `vault_groups` | string (CSV) | **yes** | — | Vault group names this feed aggregates. Must name at least one. |
| `ttl_seconds` | i32 | no | `3600` | Differential-sync interval. Must be `> 0`. |
| `max_age_seconds` | i64 | no | `0` | Retention window in seconds; **`0` = unlimited**. Must be `>= 0`. Governs which synced records are *published*, as distinct from `ttl_seconds`, which governs how often they are *re-fetched*. |
| `bound_ips` | string \| null | no | `null` | Comma-separated CIDR / IP / hostname allowlist for the *public feed* request. Absent = unrestricted. |
| `filter_rfc1918` | bool | no | `false` | Strip `10/8`, `172.16/12`, `192.168/16`. |
| `filter_bogons` | bool | no | `false` | Strip CGN, TEST-NET, multicast, `2001:db8::/32`, and other reserved ranges. |
| `filter_loopback` | bool | no | `false` | Strip `127/8` and `::1`. |

**Vault-group authorization.** For a **Daughter** caller, every name in `vault_groups` must have a
matching grant in `vault_group_permissions` (§10), or the request is refused `403` naming **every**
ungranted group at once — a partial grant is not a partial pass. Master bypasses this check
entirely.

**Response `200`** (`EndpointResponse`)

```json
{
  "id": "uuid", "owner_key_id": "uuid",
  "name": "pfBlockerNG DMZ Feed", "description": null,
  "token_secret": "<32 hex>", "feed_path": "/feed/v1/<token_secret>/list.txt",
  "vault_groups": "fail2ban,sshd",
  "ttl_seconds": 3600, "max_age_seconds": 0,
  "bound_ips": null,
  "filter_rfc1918": true, "filter_bogons": true, "filter_loopback": false,
  "last_synced_at": null, "created_at": "...", "updated_at": "..."
}
```

`feed_path` is derived, not stored — it is `token_secret` rendered into the public route so a client
never has to assemble it.

**Errors:** `400` empty name / empty `vault_groups` / `ttl_seconds <= 0` / `max_age_seconds < 0` /
invalid `bound_ips` / unknown field · `403` ungranted Vault group.

### `GET /api/endpoints`

**Scoped by tier:** Master sees every endpoint; a Daughter key sees only the ones it owns
(`owner_key_id` filter). Not an error either way — the list is simply narrower.

**Response `200`** — array of `EndpointResponse`.

### `PUT /api/endpoints/{id}`

**Body** (`UpdateEndpointPayload`, `deny_unknown_fields`) — every field optional; absent means
unchanged. Same fields and validation as creation, with:

- `description` / `bound_ips`: **`""` clears**, absent leaves unchanged.
- `vault_groups`: re-runs the same Daughter grant check as creation.
- `owner_key_id` is **absent from this type by construction** — ownership moves only through the
  dedicated Master-only route below, so a delegable update can never smuggle a reassignment.

**Auth:** owner or Master, else `403` `You do not have management rights over this endpoint`.

**Response `200`** — the updated `EndpointResponse`.

### `DELETE /api/endpoints/{id}`

**Auth:** owner or Master. Evicts the endpoint's in-memory cache entry as well as its row. Same
`rows_affected` concurrent-delete handling as `DELETE /api/keys/{id}`: the second of two racing
deletes is `404` and writes no second audit entry.

**Response `204`.** **Errors:** `403` · `404`.

### `PUT /api/endpoints/{id}/owner`

**Master-only** (`403` otherwise): `Only the Master key can reassign endpoint ownership`.

**Body** (`ReassignOwnerPayload`, `deny_unknown_fields`)

| Field | Type | Req. | Description |
| :--- | :--- | :--- | :--- |
| `owner_key_id` | UUID \| null | **yes** | The new owner. `null` orphans the endpoint (Master-managed only). A non-null id that names no existing key is `400`. |

**Response `200`** — the updated `EndpointResponse`.

---

## 10. Vault group access

Which local API keys may reference which `simply_ip_vault` group in their endpoints'
`vault_groups`. Narrower than Vault's own M:N model on purpose: this crate only ever *reads* from
Vault, so there is exactly one right to grant, and **a grant's existence is the permission** — there
is no read/write/delete/manage axis and no boolean column.

`vault_group_id` is Vault's own group UUID and is deliberately **not** a local foreign key: Vault is
a separate service reachable only over HTTP, so this database cannot enforce referential integrity
against it. `vault_group_name` is snapshotted at grant time, which is what lets enforcement run
without a live Vault call on the request path.

### `GET /api/vault-groups`

**Master-only.** Lists the groups Vault currently has, as seen by *this service's own* Vault
credentials — a live `GET /api/groups` call to Vault, scoped Vault-side to what that key may read.

**Response `200`**

```json
[ { "id": "uuid", "name": "fail2ban" } ]
```

Vault's response carries more per group (`group_type`, `description`, `owner_key_id`,
`created_at`); only the two fields this service uses are surfaced.

**Errors:** `403` not Master · **`503`** no Vault configured · **`502`** Vault unreachable or
answered unusably.

> A Vault key with no group permissions at all is **not** an error: Vault answers `200 []` and this
> route returns an empty array. A `403` from Vault is likewise degraded to an empty list rather than
> propagated, so a restricted Vault key yields an empty picker instead of a broken dashboard.

### `GET /api/keys/{id}/groups`

**Auth:** Master may inspect any key; a Daughter may inspect **only its own** grants (`403`
otherwise). Deliberately self-or-Master rather than Master-only: a Daughter's own endpoint-creation
form needs to know what it may use, without holding `can_manage_keys`.

**Response `200`**

```json
[ {
  "id": "uuid",                  // the grant's own id — used to revoke it
  "api_key_id": "uuid",
  "vault_group_id": "uuid",      // Vault's group id
  "vault_group_name": "fail2ban",// snapshotted at grant time
  "created_at": "..."
} ]
```

### `POST /api/keys/{id}/groups`

**Master-only.** Grants a local key read access to a Vault group.

**Body** (`GrantGroupPayload`, `deny_unknown_fields`)

| Field | Type | Req. | Description |
| :--- | :--- | :--- | :--- |
| `vault_group_id` | UUID | **yes** | The Vault group's id. **The name is not accepted** — it is resolved from a *fresh* call to Vault. |

Taking only the id is a correctness property, not an ergonomic one: a client-supplied name could
disagree with the id, and a typo'd id that was simply stored would become a silently broken
reference. Resolving server-side means a nonexistent id is refused at grant time.

**Idempotent:** granting a group the key already holds returns the existing grant, not a conflict.

**Response `200`** — the grant object shown above.

**Errors:** `400` `No such Vault group` · `403` not Master · `404` no such local key · `503` /
`502` as §10 above (a grant needs a live Vault lookup).

### `DELETE /api/keys/{id}/groups/{permission_id}`

**Master-only.** Revokes a grant. `permission_id` is the grant's own `id`, not the group id; a grant
whose `api_key_id` does not match `{id}` is `404` rather than being revoked from the wrong key.

> The only two-path-segment route in this crate. It takes axum's `Path<(Uuid, Uuid)>` directly
> rather than `StrictPath`, which wraps a single segment — the rejection is normalized to the same
> `400` envelope by hand.

**Response `204`.** **Errors:** `400` malformed UUID · `403` · `404`.

---

## 11. Audit log

### `GET /api/audit-logs`

**Master-only** (`403` `Only the Master key can view audit logs`). Audit entries span every key and
endpoint in the system, so a scoped Daughter key reading them would be an RBAC leak regardless of
what it owns.

**Query parameters** (`AuditLogQuery`, `deny_unknown_fields`)

| Name | Type | Req. | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `action` | string | no | — | Exact match on the action name (not a substring). Empty is ignored. |
| `limit` | u64 | no | `50` | Page size, **capped at 500** — a larger value is silently clamped, not refused. |
| `offset` | u64 | no | `0` | Page offset. |

Ordered by `timestamp` descending (most recent first).

**Response `200`** — array of `audit_logs` rows:

```json
[ {
  "id": "uuid",
  "api_key_id": "uuid" | null,   // NULL once the acting key is deleted
  "api_key_name": "System Master",
  "api_key_prefix": "a1b2c3d4",
  "client_ip": "203.0.113.9",
  "action": "ENDPOINT_CREATE",
  "target_resource": "endpoint:<uuid> (pfBlockerNG DMZ Feed)" | null,
  "details": "vault_groups=fail2ban,sshd" | null,
  "timestamp": "2026-08-11T10:26:46"
} ]
```

`api_key_name` / `api_key_prefix` are denormalized point-in-time snapshots, not a live join:
`audit_logs.api_key_id` is `ON DELETE SET NULL`, so an entry stays legible and attributable after
the key that wrote it is gone.

**Recorded actions:** `KEY_CREATE`, `KEY_UPDATE`, `KEY_DELETE`, `KEY_ROTATE`, `KEY_SECRET_ROTATE`,
`KEY_GROUP_GRANT`, `KEY_GROUP_REVOKE`, `ENDPOINT_CREATE`, `ENDPOINT_UPDATE`, `ENDPOINT_DELETE`,
`ENDPOINT_OWNER_REASSIGN`.

Every mutating route writes its entry **after** its write commits, and a failed audit write fails
the request — the two are meant to be inseparable, so a `200` never describes an action the trail
never recorded. Where a mutation is transactional (key deletion with reassignment), the audit write
joins the same transaction.

---

## 12. Static dashboard

**`GET /`** and every unmatched path are served by `ServeDir::new("static")` — the bundled
single-page dashboard (`index.html`, `app.js`, `style.css`). Unauthenticated at the HTTP layer: the
SPA authenticates its own `fetch` calls with the same `CANONICAL_V1` scheme, signing in-browser via
Web Crypto with a pure-JS HMAC fallback for plain-HTTP/LAN deployments where `crypto.subtle` is
unavailable.

Because this is the router's **fallback**, an unmatched `/api/...` path is served by `ServeDir`
(yielding its own `404`), not by this service's JSON error envelope. A `404` with a non-JSON body
therefore means the path does not exist at all — check it against §1.
