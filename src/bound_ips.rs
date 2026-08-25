//! `bound_ips` parsing and enforcement for `api_keys` and `endpoints`.
//!
//! A comma-separated list whose entries may be a CIDR range, a bare IP address, or — since
//! 2026-08-25 — a hostname, resolved at request time through the exact same [`DnsResolver`] cache
//! `config::TrustedProxies` uses for `TRUSTED_PROXIES` (see `AGENT_NOTES.MD`: "Multi-Database &
//! Domain Resolution"). An empty list means unrestricted; this module's callers always filter that
//! case out before it reaches here (see `middleware::auth_middleware`, `feed::serve_feed`).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::dns_cache::{DnsResolver, hostname_rejection};

/// One parsed `bound_ips` entry: a fixed network, or a name resolved at request time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundIpEntry {
    /// A literal address or CIDR range, matched directly.
    Network(IpNet),
    /// A hostname resolved via DNS at request time — a client (or a `TRUSTED_PROXIES`-forwarded
    /// address) is allowed if it currently appears among this name's resolved addresses.
    Hostname(String),
}

/// Parses a `bound_ips` value into entries, or names the first entry that is neither an
/// address/CIDR nor a well-formed hostname.
///
/// Mirrors `config::parse_trusted_proxies`'s three-way parse (CIDR, then bare address, then
/// hostname via [`hostname_rejection`]) so the two settings accept exactly the same shapes.
/// Returns the first bad entry rather than collecting every one — unlike `TRUSTED_PROXIES` (a
/// once-at-boot setting worth reporting exhaustively), this runs on every key/endpoint write and a
/// single clear message is enough to fix a form field.
pub fn parse_bound_ips(raw: &str) -> Result<Vec<BoundIpEntry>, String> {
    let mut entries = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(net) = entry.parse::<IpNet>() {
            entries.push(BoundIpEntry::Network(net));
        } else if let Ok(addr) = entry.parse::<IpAddr>() {
            entries.push(BoundIpEntry::Network(IpNet::from(addr)));
        } else {
            match hostname_rejection(entry) {
                None => entries.push(BoundIpEntry::Hostname(entry.to_owned())),
                Some(reason) => {
                    return Err(format!(
                        "Invalid entry in bound_ips: {entry:?} is not a CIDR range, IP address, or \
                         valid hostname ({reason})"
                    ));
                }
            }
        }
    }
    Ok(entries)
}

/// Validates a `bound_ips` value without keeping the parsed result — the write-time check used by
/// `api::keys` and `api::endpoints`.
pub fn validate_bound_ips(raw: &str) -> Result<(), String> {
    parse_bound_ips(raw).map(|_| ())
}

/// Whether `client_ip` is permitted by `entries`, resolving any hostname entries through `dns`.
///
/// An empty list is the caller's responsibility to treat as unrestricted (checked before parsing,
/// per this module's own doc comment) — this function itself treats an empty list as "nothing
/// matches", so it must never be called with one.
pub async fn is_allowed(entries: &[BoundIpEntry], client_ip: IpAddr, dns: &DnsResolver) -> bool {
    for entry in entries {
        match entry {
            BoundIpEntry::Network(net) => {
                if net.contains(&client_ip) {
                    return true;
                }
            }
            BoundIpEntry::Hostname(name) => {
                if dns.resolve(name).await.iter().any(|net| net.contains(&client_ip)) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn accepts_cidrs_bare_addresses_and_hostnames() {
        let entries = parse_bound_ips("10.0.0.0/8, 192.168.1.1, vpn.internal").expect("parses");
        assert_eq!(
            entries,
            vec![
                BoundIpEntry::Network("10.0.0.0/8".parse().unwrap()),
                BoundIpEntry::Network("192.168.1.1".parse::<IpAddr>().unwrap().into()),
                BoundIpEntry::Hostname("vpn.internal".to_owned()),
            ]
        );
    }

    #[test]
    fn empty_and_whitespace_only_entries_are_skipped() {
        assert_eq!(parse_bound_ips("").expect("parses"), vec![]);
        assert_eq!(parse_bound_ips(" , ,").expect("parses"), vec![]);
    }

    #[test]
    fn a_malformed_entry_is_rejected_with_its_reason() {
        let err = parse_bound_ips("10.0.0.0/99").unwrap_err();
        assert!(err.contains("10.0.0.0/99"), "{err}");
    }

    #[test]
    fn digits_and_dots_only_is_rejected_as_a_malformed_address_not_a_hostname() {
        assert!(parse_bound_ips("10.0.0.256").is_err());
    }

    #[tokio::test]
    async fn a_client_matching_a_literal_network_is_allowed() {
        let entries = parse_bound_ips("10.0.0.0/8").unwrap();
        let dns = DnsResolver::new();
        assert!(is_allowed(&entries, "10.1.2.3".parse().unwrap(), &dns).await);
        assert!(!is_allowed(&entries, "9.9.9.9".parse().unwrap(), &dns).await);
    }

    #[tokio::test]
    async fn a_client_matching_a_resolved_hostname_is_allowed() {
        let entries = parse_bound_ips("localhost").unwrap();
        let dns = DnsResolver::new();
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_allowed(&entries, loopback_v4, &dns).await, "localhost should resolve to a loopback address");
        assert!(!is_allowed(&entries, "203.0.113.5".parse().unwrap(), &dns).await);
    }

    #[tokio::test]
    async fn an_unresolvable_hostname_allows_nobody() {
        let entries = parse_bound_ips("this-name-does-not-exist.invalid").unwrap();
        let dns = DnsResolver::with_ttls(Duration::from_secs(30), Duration::from_secs(30));
        assert!(!is_allowed(&entries, "203.0.113.5".parse().unwrap(), &dns).await);
    }
}
