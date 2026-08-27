# simply_ip_exporter

A high-performance DMZ proxy and public feed exporter. It periodically pulls IP records from a
central [`simply_ip_vault`](../simply_ip_vault) instance, aggregates and sanitizes them entirely
in memory, and exposes plain-text lists formatted for pfSense (`pfBlockerNG`) and other firewall
alias-list importers.

## Contents

- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Admin API & RBAC](#admin-api--rbac)
- [Public feed endpoint](#public-feed-endpoint)
- [pfSense / pfBlockerNG integration](#pfsense--pfblockerng-integration)
- [Probes](#probes)
- [Testing](#testing)

## Architecture

```
                     HMAC-signed, outbound                 unauthenticated, URL-secret
  simply_ip_vault  <───────────────────────  simply_ip_exporter  ───────────────────────>  pfSense
  (source of truth)     GET /api/ips              (DMZ host)         GET /feed/v1/<token>/list.txt
                                                        │
                                                        ▼
                                              SQLite (config only:
                                              api_keys, endpoints)
```

`simply_ip_exporter` is designed to sit in a DMZ, one hop closer to the firewalls that consume its
feeds than the vault it reads from — a compromise of the exporter should not hand an attacker
write access to the vault, and the vault should never need to be reachable from the public side of
the network at all.

**Zero-trust, zero-disk-wear for IP data.** IP records and their aggregated CIDR form are held
strictly in an `Arc<RwLock<...>>` in-memory cache (`src/cache.rs`) and are **never** written to
SQLite or disk — a restart clears the cache and the background sync worker repopulates it from
Vault within one tick. SQLite is used exclusively for local configuration: `api_keys` (this
service's own admin credentials) and `endpoints` (public feed route definitions). See `SCHEMA.MD`
for the exact schema and `AGENT.MD` for the full architectural ruleset this service was built
against.

**Two independent trust boundaries, two independent HMAC handshakes:**

- **Outbound** (exporter → vault): every sync request is signed with `CANONICAL_V1`
  HMAC-SHA256 (`X-API-Key` / `X-Timestamp` / `X-Signature-256`) using credentials configured via
  `VAULT_API_KEY` / `VAULT_SIGNING_SECRET`.
- **Inbound** (admin → exporter's `/api/*`): the same `CANONICAL_V1` scheme, mandatory on every
  request, with single-use anti-replay enforcement inside a ±300s freshness window.

**The public feed** (`/feed/v1/<token_secret>/list.txt`) carries no HMAC handshake at all —
security rests entirely on the secrecy of the URL token, matching how pfBlockerNG and similar
importers actually fetch remote lists (a bare `GET`, no custom headers).

### Hybrid sync protocol

Each `endpoints` row names one or more Vault group(s) and a `ttl_seconds`. A background worker
(`src/sync.rs`) wakes every 15 seconds and, per endpoint:

- performs a **differential sync** (`GET /api/ips?groups=...&since=<last_synced_at>&include_deleted=true`)
  once `ttl_seconds` has elapsed since the last sync, merging additions and soft-deletes into the
  in-memory cache; or
- performs a **full, unconstrained sync** (`GET /api/ips?groups=...`) at least once every 24 hours
  regardless of `ttl_seconds`, replacing the cached set outright to clear any orphaned records a
  differential sync might have missed.

If Vault is unreachable, the worker logs a warning and leaves the existing in-memory cache
untouched — the public feed keeps serving its last-known-good content without interruption.

## Quickstart

### Local (`cargo run`)

```sh
cargo run
# listens on 0.0.0.0:3002 by default; a Master API key + signing secret are generated
# and printed to the log exactly once on first boot.
```

Point it at a running `simply_ip_vault`:

```sh
VAULT_BASE_URL=http://127.0.0.1:3000 \
VAULT_API_KEY=<a vault key scoped can_read on the groups you want> \
VAULT_SIGNING_SECRET=<that key's signing secret> \
cargo run
```

### Docker

```sh
docker compose up --build
```

`docker-compose.yml` builds the image, binds port `3002`, and persists the SQLite configuration
database (not IP data — there is none on disk) under `./data`. Set `VAULT_BASE_URL` /
`VAULT_API_KEY` / `VAULT_SIGNING_SECRET` in the compose file's `environment:` block (or an
`.env` file) to enable syncing.

### First admin API call

The bootstrap banner (printed once, to stdout, on first boot with an empty `api_keys` table) looks
like:

```
╔══════════════════════════════════════════════════════════════╗
║  BOOTSTRAP: Master API Key Generated
║  X-API-Key:        <64-hex-character key>
║  Signing Secret:   <64-hex-character secret>
║  Bound IPs:        0.0.0.0/0,::/0
║  Shown once. Store the key and signing secret securely!
╚══════════════════════════════════════════════════════════════╝
```

Every `/api/*` request must carry `X-API-Key`, `X-Timestamp` (Unix seconds), and
`X-Signature-256: sha256=<hex>` — an HMAC-SHA256 over `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nBODY`,
keyed by the signing secret:

```sh
KEY="<X-API-Key from the banner>"
SECRET="<Signing Secret from the banner>"
TS=$(date +%s)
SIG="sha256=$(printf 'GET\n/api/auth/me\n%s\n' "$TS" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')"

curl -H "X-API-Key: $KEY" -H "X-Timestamp: $TS" -H "X-Signature-256: $SIG" \
  http://127.0.0.1:3002/api/auth/me
```

The bundled dashboard (`static/`, served at `/`) does this signing for you via the browser's
Web Crypto API, with a pure-JS fallback for plain-HTTP/LAN deployments where `crypto.subtle` is
unavailable (it requires a secure context).

## Configuration

All configuration is environment-variable driven; nothing security-relevant has a config file.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `BIND_HOST` / `HOST` | `0.0.0.0` | Listen address. `BIND_HOST` takes precedence if both are set. |
| `PORT` | `3002` | Listen port. |
| `DATABASE_URL` | `sqlite://simply_ip_exporter.db?mode=rwc` | SQLite connection string for **configuration only** (`api_keys`, `endpoints`). |
| `EXPORTER_ENCRYPTION_KEY` | *(unset)* | 64 hex characters (32 bytes). Encrypts `api_keys.signing_secret` at rest with XChaCha20-Poly1305. Unset means secrets are stored hex-encoded but unencrypted — fine for local dev, not for production. Generate with `openssl rand -hex 32`. |
| `VAULT_BASE_URL` | *(unset)* | Base URL of the `simply_ip_vault` instance to sync from, e.g. `http://vault:3000`. Sync stays idle (feeds remain empty) until this and the two variables below are all set. |
| `VAULT_API_KEY` | *(unset)* | The `X-API-Key` used to authenticate outbound requests to Vault. Should belong to a Vault key scoped `can_read`-only on the groups this exporter needs. |
| `VAULT_SIGNING_SECRET` | *(unset)* | The HMAC-SHA256 signing secret paired with `VAULT_API_KEY`. |
| `TRUSTED_PROXIES` | *(unset)* | Comma-separated CIDR ranges, bare IPs, or hostnames/Docker container names (e.g. `traefik_tomidejetsu`), resolved via DNS and re-checked periodically. `X-Forwarded-For`/`X-Real-IP` are honored **only** from these peers; everything else is matched against the raw TCP connection. A malformed entry is fatal at startup; a well-formed hostname that doesn't currently resolve is not — it's simply untrusted until it does, retried automatically. Leave unset for a directly-exposed deployment. |
| `SIGNATURE_MAX_AGE_SECONDS` | `300` | Symmetric freshness window (±) for `X-Timestamp` on signed `/api/*` requests. |
| `INITIAL_MASTER_KEY` / `INITIAL_MASTER_SIGNING_SECRET` | *(unset)* | Deterministic bootstrap credentials for test/CI (see `scripts/test_e2e.sh`). Each must be exactly 64 hex characters if set. **Do not set these in a real deployment** — let the daemon generate a random Master key. |
| `BOOTSTRAP_SUBNET` | `0.0.0.0/0,::/0` | `bound_ips` assigned to the auto-generated Master key. |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter. |

The public-feed rate limiter (max one request per source IP every 2 minutes, tracked in a
10,000-entry bounded LRU) and the sync worker's tick interval (15s) and full-resync interval (24h)
are fixed constants, not environment-configurable — see `src/ratelimit.rs` and `src/sync.rs`.

## Admin API & RBAC

Two tiers, per `AGENT.MD`:

- **Master** — exactly one, auto-generated at first boot if `api_keys` is empty, pinned to a
  single database row for the life of the process (`src/master.rs`). Can manage every API key and
  every endpoint.
- **Daughter** — created by Master (`can_manage_keys = false`), can create endpoints (which it
  then owns) and manage only the endpoints it owns. Cannot manage API keys at all. Additionally
  restricted to naming only Vault groups it holds a read grant for in its own endpoints'
  `vault_groups` — Master grants these per key via `POST /api/keys/{id}/groups` and is itself
  exempt from the restriction (see `AGENT.MD`'s "Per-key Vault-group read permissions").

| Method & Path | Who | Purpose |
| :--- | :--- | :--- |
| `GET /api/auth/me` | any authenticated key | Reports the caller's own identity/RBAC flags. |
| `POST /api/keys` | Master | Mint a Daughter key. Returns the plaintext key + signing secret **once**. |
| `GET /api/keys` | Master | List every local API key (never returns secrets). |
| `PUT /api/keys/{id}` | Master | Rename, rebind IPs, or grant/revoke `can_manage_keys`. |
| `DELETE /api/keys/{id}` | Master | Delete a key (not the Master itself). |
| `POST /api/keys/{id}/rotate` | Master | Re-mint a key's secret + signing secret (both halves change). |
| `POST /api/keys/{id}/rotate-secret` | Master | Re-mint only the signing secret — the API key, name, and `can_manage_keys` are untouched. |
| `POST /api/endpoints` | any authenticated key | Create a feed endpoint, owned by the caller. |
| `GET /api/endpoints` | any authenticated key | List endpoints (Master sees all; a Daughter sees only its own). |
| `PUT /api/endpoints/{id}` | owner or Master | Update an endpoint's configuration. |
| `DELETE /api/endpoints/{id}` | owner or Master | Delete an endpoint and evict its in-memory cache. |
| `PUT /api/endpoints/{id}/owner` | Master | Reassign an endpoint's owner. |
| `GET /api/audit-logs` | Master | List the audit trail (most recent first), optionally filtered by `action` and paginated (`limit`/`offset`). |
| `GET /api/vault-groups` | Master | List every group `simply_ip_vault` currently has (live, Vault-side scoped to this crate's own configured Vault key). |
| `GET /api/keys/{id}/groups` | Master or the key itself | List a key's Vault-group read grants. |
| `POST /api/keys/{id}/groups` | Master | Grant a key read access to a Vault group (by group id — independently re-verified against a fresh Vault call, not trusted from the request). Idempotent. |
| `DELETE /api/keys/{id}/groups/{permission_id}` | Master | Revoke a previously granted Vault-group read right. |

Every mutating route above (`POST`/`PUT`/`DELETE` on `/api/keys/*` and `/api/endpoints/*`) writes
an entry to `audit_logs` after its write commits — see `SCHEMA.MD` §3. The write is not
best-effort: if it fails, the request fails too, since a `200 OK` for an action the audit trail
never recorded would be worse than an honest `500`.

An `endpoints` row's fields:

| Field | Meaning |
| :--- | :--- |
| `vault_groups` | Comma-separated Vault group names/UUIDs this endpoint pulls from. |
| `ttl_seconds` | Differential-sync interval and in-memory cache "freshness" window. |
| `bound_ips` | Optional comma-separated CIDR/IP/hostname allowlist for the *public* feed request (separate from any admin-API `bound_ips`). A hostname entry is resolved via DNS at request time (30s/5s positive/negative cache, shared with `TRUSTED_PROXIES`'s own resolver). |
| `filter_rfc1918` | Strip `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. |
| `filter_bogons` | Strip CGN, TEST-NET, multicast, and other reserved/unallocated ranges. |
| `filter_loopback` | Strip `127.0.0.0/8` and `::1`. |

## Public feed endpoint

```
GET /feed/v1/<token_secret>/list.txt
```

- **No headers required.** The token embedded in the path *is* the credential.
- Response is `text/plain; charset=utf-8`, one aggregated CIDR/address per line, sorted.
- `filter_rfc1918` / `filter_bogons` / `filter_loopback` are applied first; the survivors are
  merged with `ipnet::IpNet::aggregate()` (so `10.0.0.0/24` + `10.0.0.1/32` collapse to
  `10.0.0.0/24`).
- An `ETag` (SHA-256 of the body) is always returned. A matching `If-None-Match` gets a free `304
  Not Modified` — this does **not** count against the rate limit, so a well-behaved poller that
  revalidates on every fetch is never throttled for doing so.
- Requests that *do* need a full body are throttled to one per source IP per 2 minutes; excess
  requests get `429 Too Many Requests` with a `Retry-After` header.
- An optional per-endpoint `bound_ips` CIDR/IP/hostname allowlist returns `403 Forbidden` for
  disallowed source addresses.
- An unknown token returns `404 Not Found`.

## pfSense / pfBlockerNG integration

1. In the dashboard (or via the admin API), create an endpoint naming the Vault group(s) you want
   exported, and copy its `feed_path`.
2. In pfBlockerNG: **Firewall → pfBlockerNG → IP → IPv4 (or IPv6)**, add a new alias:
   - **Action**: Alias Native (or Deny/Permit, per your policy)
   - **List Type**: `URL Table` (or `URL Table (IPs)` depending on pfBlockerNG version)
   - **Source**: `http://<exporter-host>:3002/feed/v1/<token_secret>/list.txt`
   - **Update Frequency**: at least as long as the endpoint's `ttl_seconds` — polling faster than
     the cache refreshes buys nothing but risks the 2-minute per-source-IP throttle.
3. Force an update and confirm the alias populates. pfBlockerNG's own downloader sends
   `If-Modified-Since`/no conditional headers by default depending on version; either way, a
   `200` with a changed body or a `304`/cached-`200` with an unchanged one are both handled
   correctly by this endpoint.
4. If pfSense reaches the exporter through a reverse proxy or load balancer, set `TRUSTED_PROXIES`
   to that proxy's address so `bound_ips` (if configured on the endpoint) evaluates the real
   client address rather than the proxy's.
5. The admin web UI (`static/`) works unmodified when mounted under a subpath (e.g.
   `https://host/ip_exporter/`) — it derives its own API base path from the page's URL, no
   configuration needed, as long as the proxy strips its prefix before forwarding to this service
   (the common case). If it does *not* strip the prefix, set the "API base path override" field on
   the login screen to that prefix so client-side request signing matches what this process
   actually receives.

## Probes

| Path | Auth | Meaning |
| :--- | :--- | :--- |
| `GET /health`, `/healthz` | none | Liveness. Always `200`, never touches the database. |
| `GET /ready`, `/readyz` | none | Readiness. `200` only when the database answers **and** the Master key identity is pinned; `503` otherwise. |

Both are mounted outside the admin-API auth middleware, since their callers (container
orchestrators, load balancers) cannot compute an HMAC signature.

## Testing

```sh
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test                     # 123 unit + 4 main.rs unit + 40 integration + 13 source-hygiene tests
./scripts/verify_convergence.sh  # source hygiene (raw SQL, unwrap/expect, frontend syntax/DOM refs) + clippy -D warnings + cargo test, one gate
./scripts/test_e2e.sh          # full live E2E against a real simply_ip_vault + simply_ip_exporter pair
```

`scripts/test_e2e.sh` builds and boots both services against throwaway SQLite databases with
deterministic bootstrap keys, provisions Vault, configures an exporter endpoint, and asserts —
across 141 checks in 15 sections — the feed pipeline (aggregation, filtering, ETag/304, rate
limiting), Vault soft-delete propagation via differential sync, hot-reload of endpoint config with
no restart, `bound_ips` client-IP restriction, a full graceful-restart-with-encryption cycle
(Master key, a Daughter key's encrypted secret, and the endpoint row all surviving a `SIGTERM` and
restart against the same SQLite file), a wrong `EXPORTER_ENCRYPTION_KEY` being refused at startup
with an explicit error rather than starting up broken, HMAC anti-replay timestamp-skew rejection,
real-time Daughter key rotation/revocation with no restart, resilience to a Vault outage, and a full
audit-log traversal. It needs the reference `example/simply_ip_vault` checkout, and
`curl`/`jq`/`cargo`/`openssl` on `PATH`.
