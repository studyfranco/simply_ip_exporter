# Simply IP Exporter goals

## Mission and architecture

Simply IP Exporter turns selected Vault groups into plain-text IP and CIDR feeds
for firewalls such as pfSense. It filters, deduplicates and aggregates records
in memory. A background worker uses differential refreshes and periodic full
refreshes. During a Vault outage, feeds continue serving the last successful
snapshot while the process stays up.

The exporter signs read-only `GET /api/ips` and `GET /api/groups` requests to
`https://vault.example.test` with `CANONICAL_V1` HMAC-SHA256. The signature
covers the method, path and query, UTC Unix timestamp, and raw body. The Vault
credential needs read access only to the selected groups. Clients fetch tokenized
`/feed/v1/*` paths from `https://exporter.example.test`.

The database persists configuration, local credentials and the administrative
audit trail. IP feeds and their source records stay in RAM, and the exporter
never writes to Vault or pulls external threat feeds directly.

## Network isolation

Attach the exporter strictly to the Docker `isolate` network, an internal
bridge with zero outbound Internet access. Vault pulls stay on that bridge.
Keep the exporter off `ext`, the external-facing network. A reverse proxy on
both `ext` and `isolate` can forward `/feed/v1/*` to the exporter. A firewall
on the Docker host or LAN can also fetch feeds through a host or LAN ingress
path without giving the exporter an `ext` route. Limit access to the admin API
separately from feed ingress.

## Security invariants

- Rust enforces `unsafe_code = "forbid"`. Database operations and migrations
  use SeaORM builders with zero raw application SQL.
- Set `EXPORTER_ENCRYPTION_KEY` in production so `SecretCipher` seals stored
  secrets at rest. `MasterPin` pins the boot-time Master identity. Administrative
  requests use HMAC with replay protection.
- The in-memory cache holds one snapshot per endpoint. Vault page fetches have
  a concurrency bound, and the in-memory feed rate-limit cache has a hard entry cap.
- `cargo audit --deny warnings` must pass with zero ignored advisories.

## Examples

Use only reserved placeholders in onboarding material. Use RFC 2606 names
such as `vault.example.test` and `exporter.example.test`, RFC 5737 IPv4 ranges
`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, or the RFC 3849 IPv6
range `2001:db8::/32`. RFC 1918 and loopback addresses are also permitted.

See [use-ip-exporter](.agents/skills/use-ip-exporter/SKILL.md) for the operational agent skill.
