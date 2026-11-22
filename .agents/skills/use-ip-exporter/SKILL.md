---
name: use-ip-exporter
description: Operate and configure simply_ip_exporter via its CANONICAL_V1 HMAC-SHA256 admin API, manage Master/Daughter keys, Vault group grants, and tokenized /feed/v1/* endpoints, and consume plain-text feeds across firewalls and reverse proxies.
---

# Using `simply_ip_exporter`

`simply_ip_exporter` is a DMZ proxy and public feed exporter that pulls IP/CIDR records from `simply_ip_vault` into RAM, filters and aggregates them with `ipnet::IpNet::aggregate()`, and serves tokenized `text/plain; charset=utf-8` lists at `GET /feed/v1/<token_secret>/list.txt`.

## Network Boundary (`isolate`-Only)

- **Attach strictly to `isolate`:** Run `simply_ip_exporter` on the internal Docker `isolate` bridge (zero outbound Internet access). Keep it off `ext`.
- **Vault pulls:** Outbound traffic is limited to signed `GET /api/ips` and `GET /api/groups` calls to `https://vault.example.test` over `isolate`.
- **Feed & admin ingress:** Expose `/feed/v1/*` to firewalls (pfSense, OPNsense, MikroTik) or a reverse proxy joined to both `ext` and `isolate`. Restrict `/api/*` admin access separately from public feed ingress.
- **Zero-disk-wear for IP data:** SQLite/Postgres/MySQL stores only `api_keys`, `endpoints`, `vault_group_permissions`, and `audit_logs`. IP records and aggregated snapshots live strictly in RAM (`IpCache`).

## Authentication: `CANONICAL_V1` HMAC-SHA256

Every `/api/*` route requires `CANONICAL_V1` request signing enforced by `src/middleware.rs`:

- **Headers:**
  - `X-API-Key`: 64-hex-character API key (or `INITIAL_MASTER_KEY`).
  - `X-Timestamp`: UTC Unix timestamp in seconds (default anti-replay window: `±300s`, configurable via `SIGNATURE_MAX_AGE_SECONDS`).
  - `X-Signature-256`: `sha256=<hex>` HMAC-SHA256 digest using the key's `signing_secret`.
- **Canonical payload (`METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`):**
  - `METHOD`: uppercase HTTP verb (`GET`, `POST`, `PUT`, `DELETE`).
  - `TARGET`: request path + query string as seen by the server (via Axum `OriginalUri`, so reverse-proxy subpath prefixes must match the signed target).
  - `TIMESTAMP`: exact `X-Timestamp` header value.
  - `RAW_BODY`: exact raw request body bytes (empty string for `GET`/`DELETE`; max `3 MiB`).
- **Single-use anti-replay:** Each `(key_id, signature)` is accepted at most once within the timestamp window. Never reuse the same timestamp for identical consecutive requests.

```bash
sign_and_call() {
  local base="$1" method="$2" target="$3" api_key="$4" secret="$5" body="${6:-}"
  local ts sig
  ts=$(date -u +%s)
  sig="sha256=$(printf '%s\n%s\n%s\n%s' "$method" "$target" "$ts" "$body" \
    | openssl dgst -sha256 -hmac "$secret" | sed 's/^.*= //')"
  curl -sS -X "$method" "${base}${target}" \
    -H "X-API-Key: ${api_key}" \
    -H "X-Timestamp: ${ts}" \
    -H "X-Signature-256: ${sig}" \
    ${body:+-H "Content-Type: application/json" --data-binary "$body"}
}
```

## RBAC: Master vs Daughter Keys vs Feed Tokens

| Capability | Master Key | Daughter Key | Feed Token (`token_secret`) |
| --- | --- | --- | --- |
| `GET /api/auth/me` | Yes (`is_master: true`) | Yes (`is_master: false`) | No |
| `POST /api/keys`, `GET /api/keys`, `PUT/DELETE /api/keys/{id}`, rotate/secret | Yes | `403 Forbidden` | No |
| `GET/POST /api/keys/{id}/groups`, `DELETE /api/keys/{id}/groups/{permission_id}` | Yes | `403 Forbidden` | No |
| `GET /api/settings`, `GET /api/audit-logs` | Yes | `403 Forbidden` | No |
| `PUT /api/endpoints/{id}/owner` | Yes | `403 Forbidden` | No |
| `GET /api/vault-groups` | All Vault groups | Granted groups only | No |
| `POST /api/endpoints` | Any `vault_groups` | Granted `vault_groups` only | No |
| `GET /api/endpoints`, `PUT/DELETE /api/endpoints/{id}` | All endpoints | Own endpoints only | No |
| `GET /feed/v1/{token_secret}/list.txt` | Unauthenticated | Unauthenticated | Yes (URL secret + `bound_ips`) |

- **Real-time permission check:** On every feed request, `serve_feed` re-verifies that the endpoint owner still holds `vault_group_permissions` for all configured `vault_groups`; revoking a grant returns `403` immediately.
- **No privilege escalation:** `POST /api/keys` never accepts `is_master`; the sole Master identity is pinned at boot (`MasterPin`).

## Filtering, Retention & Aggregation Flags

Each endpoint (`POST /api/endpoints`, `PUT /api/endpoints/{id}`) supports:

- `vault_groups`: comma-separated Vault group names (e.g. `"Blacklist_Primary,Blacklist_Secondary"`).
- `ttl_seconds`: Vault sync interval in seconds (default `300`).
- `max_age_seconds`: feed-time retention window in seconds (`0` or omitted = unlimited). Evaluated at request time against each record's `last_seen_at`, so updates take effect on the next feed fetch without waiting for a resync.
- `bound_ips`: optional comma-separated CIDR/IP/hostname allowlist (e.g. `"192.0.2.10/32,2001:db8::/32"`).
- `filter_rfc1918` (`bool`): drops RFC 1918 private IPv4 ranges.
- `filter_bogons` (`bool`): drops reserved/bogon IPv4 and IPv6 ranges (including CGN, link-local, documentation, multicast).
- `filter_loopback` (`bool`): drops IPv4/IPv6 loopback addresses.
- **Aggregation:** Surviving networks are collapsed via `ipnet::IpNet::aggregate()` and sorted lexically, one CIDR per line.

## Export Cookbook

`GET /feed/v1/<token_secret>/list.txt` natively serves `text/plain; charset=utf-8` with `ETag` support (`If-None-Match` -> `304 Not Modified`) and a per-client-IP rate limit of 1 request per 2 minutes (`429 Too Many Requests` + `Retry-After`).

### 1. Plain Text (`curl` with `ETag`)

```bash
curl -fsS -H 'If-None-Match: "<previous-etag>"' \
  "https://exporter.example.test/feed/v1/<token_secret>/list.txt"
```

### 2. JSON (via `jq`)

```bash
curl -fsS "https://exporter.example.test/feed/v1/<token_secret>/list.txt" \
  | jq -R -s 'split("\n") | map(select(length > 0))'
```

### 3. Nginx (`geo` / `deny` include)

```bash
curl -fsS "https://exporter.example.test/feed/v1/<token_secret>/list.txt" \
  | awk '{print "deny " $1 ";"}' > /etc/nginx/conf.d/blocklist.inc
nginx -t && systemctl reload nginx
```

### 4. Caddy (`remote_ip` matcher)

```bash
{
  echo "@blocked {"
  curl -fsS "https://exporter.example.test/feed/v1/<token_secret>/list.txt" \
    | awk '{print "  remote_ip " $1}'
  echo "}"
} > /etc/caddy/blocklist.caddy
caddy reload --config /etc/caddy/Caddyfile
```

### 5. Apache (`Require not ip`)

```bash
{
  echo "<RequireAll>"
  echo "  Require all granted"
  curl -fsS "https://exporter.example.test/feed/v1/<token_secret>/list.txt" \
    | awk '{print "  Require not ip " $1}'
  echo "</RequireAll>"
} > /etc/apache2/conf-available/blocklist.conf
apache2ctl configtest && systemctl reload apache2
```

### 6. MikroTik RouterOS (`/ip firewall address-list`)

```bash
curl -fsS "https://exporter.example.test/feed/v1/<token_secret>/list.txt" \
  | awk '!/:/ {print "/ip firewall address-list add list=simply_block address=" $1}' \
  > blocklist.rsc
```

### 7. pfSense (`pfBlockerNG`)

- In **Firewall > pfBlockerNG > IP > IPv4** (or **IPv6**), add a new feed source:
  - **Format:** `Auto`
  - **State:** `ON`
  - **Source:** `https://exporter.example.test/feed/v1/<token_secret>/list.txt`
  - **Update Frequency:** Match or exceed `ttl_seconds` (respect the 1 req / 2 min feed rate limit).

### 8. OPNsense (`URL Table (IPs)`)

- In **Firewall > Aliases**, create an alias:
  - **Type:** `URL Table (IPs)`
  - **Refresh Frequency:** `>= 2 minutes` (to stay within the feed rate limit)
  - **Content:** `https://exporter.example.test/feed/v1/<token_secret>/list.txt`

## Safety Guardrails

- **Never disable `EXPORTER_ENCRYPTION_KEY` in production:** `SecretCipher` seals stored signing secrets at rest; starting against an existing DB with the wrong key aborts startup cleanly.
- **Honor `TRUSTED_PROXIES`:** Only list reverse proxies on `isolate` (e.g., `proxy.example.test` or `198.51.100.2/32`) so `X-Forwarded-For` cannot be spoofed to bypass `bound_ips` or rate limits.
- **Respect feed rate limits:** Poll `/feed/v1/<token_secret>/list.txt` no more than once every 2 minutes per source IP and send `If-None-Match` to receive `304 Not Modified` when unchanged.
- **Use placeholder-only examples:** Never commit real domains, production IPs, or live API keys/signing secrets.
