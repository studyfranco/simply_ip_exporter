//! Shared, cached DNS resolution for hostname entries in trust/access-control lists.
//!
//! Extracted from `config::TrustedProxies` (2026-08-19) so `bound_ips` hostname support
//! (`AGENT_NOTES.MD`, 2026-08-25) resolves names through the exact same cache and TTL policy
//! rather than a second, drifting reimplementation. `TrustedProxies` and every `bound_ips` check
//! share one [`DnsResolver`] instance (`AppState::dns_resolver`, cloned from
//! `TrustedProxies::dns_resolver()`), so a name referenced by both resolves once.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use tokio::sync::RwLock;

/// How long a *successful* hostname resolution is trusted before being re-checked.
///
/// Short enough that a container restart which moves a trusted name to a new address is picked up
/// promptly, long enough that steady-state request handling essentially never pays for a DNS
/// lookup. 30s matches `example/simply_ip_vault`'s identical constant.
pub const POSITIVE_TTL: Duration = Duration::from_secs(30);

/// How long a *failed* resolution is remembered before being retried — negative caching.
///
/// Deliberately much shorter than [`POSITIVE_TTL`] (a name that is failing is usually being fixed),
/// but deliberately non-zero: without it, every request arriving while a configured hostname is
/// unresolvable triggers its own DNS lookup, turning a dead name behind a hot path into a
/// resolution amplifier against both the resolver and this process's own latency.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// One hostname's last resolution attempt.
#[derive(Clone)]
struct HostnameState {
    /// What the name resolved to, empty when the lookup failed.
    addresses: Vec<IpNet>,
    /// When the attempt ran.
    attempted_at: Instant,
    /// Whether it produced at least one address.
    resolved: bool,
}

impl HostnameState {
    /// Whether this attempt may still be reused, per the positive/negative TTL split.
    fn is_fresh(&self, positive: Duration, negative: Duration) -> bool {
        let ttl = if self.resolved { positive } else { negative };
        self.attempted_at.elapsed() < ttl
    }
}

/// A positive/negative-TTL cache mapping arbitrary hostnames to their currently-resolved
/// addresses.
///
/// Unlike `TrustedProxies` (which only ever resolves a fixed, startup-known set of names), this
/// cache accepts any hostname handed to [`resolve`](Self::resolve) at request time — the shape
/// `bound_ips` needs, since the set of hostnames in play is whatever operators have typed into
/// however many `api_keys`/`endpoints` rows exist, not something known at boot. Cloning shares the
/// cache (`Arc`-backed).
#[derive(Clone, Debug)]
pub struct DnsResolver {
    positive_ttl: Duration,
    negative_ttl: Duration,
    cache: Arc<RwLock<HashMap<String, HostnameState>>>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self { positive_ttl: POSITIVE_TTL, negative_ttl: NEGATIVE_TTL, cache: Arc::default() }
    }
}

impl std::fmt::Debug for HostnameState {
    /// Renders nothing of substance: a `{:?}` of application state should describe what the
    /// operator configured, not which addresses a name happened to resolve to a moment ago.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<hostname state>")
    }
}

impl DnsResolver {
    /// Builds a resolver with the default TTL policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides both DNS reuse windows. Test-facing: a suite cannot wait 30 seconds to observe
    /// that a re-resolution happened, nor 5 to observe that one was suppressed.
    #[cfg(test)]
    pub fn with_ttls(positive: Duration, negative: Duration) -> Self {
        Self { positive_ttl: positive, negative_ttl: negative, cache: Arc::default() }
    }

    /// Resolves `hostname`, reusing a cached attempt when it is still fresh.
    ///
    /// Never errors: an unresolvable name yields an empty list (the safe direction — "not
    /// currently trusted" / "does not currently match"), exactly like [`lookup_hostname`].
    pub async fn resolve(&self, hostname: &str) -> Vec<IpNet> {
        {
            let cache = self.cache.read().await;
            if let Some(state) = cache.get(hostname)
                && state.is_fresh(self.positive_ttl, self.negative_ttl)
            {
                return state.addresses.clone();
            }
        }

        // Re-check under the write lock: several requests can queue behind one expiry, and only
        // the first should pay for the lookup — bounding retries across concurrent requests at one
        // instant rather than only over time.
        let mut cache = self.cache.write().await;
        if let Some(state) = cache.get(hostname)
            && state.is_fresh(self.positive_ttl, self.negative_ttl)
        {
            return state.addresses.clone();
        }
        self.refresh_locked(&mut cache, hostname).await
    }

    /// Re-resolves `hostname` unconditionally, ignoring any cached attempt.
    ///
    /// Used at boot (`TrustedProxies::prime`) to force a real attempt rather than reusing whatever
    /// a concurrent request just cached.
    pub async fn force_resolve(&self, hostname: &str) -> Vec<IpNet> {
        let mut cache = self.cache.write().await;
        self.refresh_locked(&mut cache, hostname).await
    }

    async fn refresh_locked(
        &self,
        cache: &mut HashMap<String, HostnameState>,
        hostname: &str,
    ) -> Vec<IpNet> {
        let addresses = lookup_hostname(hostname).await;
        let resolved = !addresses.is_empty();
        cache.insert(hostname.to_owned(), HostnameState { addresses: addresses.clone(), attempted_at: Instant::now(), resolved });
        addresses
    }
}

/// Resolves one hostname to the addresses it currently names.
///
/// A failure yields nothing rather than propagating: an unresolvable name means "not currently
/// trusted"/"not currently matched", the safe direction to fail in. A DNS outage must never
/// *widen* what the daemon believes, and a container that is down should stop being trusted/bound
/// rather than keep a stale grant alive.
pub(crate) async fn lookup_hostname(hostname: &str) -> Vec<IpNet> {
    // Port 0: `lookup_host` wants a socket address, but only the address half is used.
    match tokio::net::lookup_host((hostname, 0u16)).await {
        Ok(addrs) => {
            let networks: Vec<IpNet> = addrs.map(|addr| IpNet::from(normalize_ip(addr.ip()))).collect();
            if networks.is_empty() {
                tracing::warn!("Hostname {hostname:?} resolved to no addresses; it is not trusted/matched until it does.");
            } else {
                tracing::debug!(
                    "Hostname {hostname:?} resolved to {}",
                    networks.iter().map(|n| n.addr().to_string()).collect::<Vec<_>>().join(", ")
                );
            }
            networks
        }
        Err(e) => {
            tracing::warn!("Could not resolve hostname {hostname:?}: {e}. It is not trusted/matched until resolution succeeds.");
            Vec::new()
        }
    }
}

/// Normalizes an IPv4-mapped IPv6 address (`::ffff:192.168.1.1`) down to its plain IPv4 form.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Why an entry is not a valid spelling of anything, and why.
///
/// Distinct from a hostname that merely fails to resolve *right now*: this is a value that can
/// never become usable no matter what DNS does, so it is a configuration error rather than a
/// transient one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidHostEntry {
    /// The entry exactly as written, so the operator can find it in their configuration.
    pub entry: String,
    /// Why it was refused, phrased to name the mistake rather than the rule.
    pub reason: &'static str,
}

/// Why `entry` cannot be a DNS name, or `None` when it is shaped like one.
///
/// Returns the *reason* rather than a bool because the reason is the entire value of this check to
/// an operator: "not a valid hostname" sends them to the manual, "made only of digits and dots"
/// sends them to the typo.
///
/// Deliberately strict about the two shapes that are *nearly* addresses. An entry reaching this
/// point already failed to parse as an address and as a CIDR, and the ways that happens are a typo
/// and a hostname:
///
/// - Anything containing `/` or `:` is refused, since those characters appear only in prefix and
///   IPv6 syntax — a near-miss CIDR like `10.0.0.0/99` surfaces as the configuration error it is
///   rather than a name that silently never matches.
/// - Anything made only of digits and dots is refused for the same reason: `10.0.0.256` is a
///   mistyped IPv4 literal, not a hostname, and treating it as one would hide the typo behind a
///   perfectly quiet non-match.
/// - The first and last characters must be alphanumeric — stricter than the RFC, which permits a
///   trailing `.` to mark a fully-qualified name; the strictness is the point, since a trailing
///   separator is far more often a stray comma-splice than a deliberate root anchor, and
///   `tokio::net::lookup_host` treats `proxy.` and `proxy` identically anyway. Byte-for-byte the
///   same rule `example/simply_ip_vault`'s and `example/simply_hook_executor`'s identical function
///   apply. Reused here for `bound_ips` so a hostname entry is refused/accepted by the identical
///   rule `TRUSTED_PROXIES` uses, not a second, potentially-drifting definition of "looks like a
///   hostname".
pub fn hostname_rejection(entry: &str) -> Option<&'static str> {
    if entry.is_empty() {
        return Some("empty");
    }
    if entry.len() > 253 {
        return Some("longer than the 253-character limit on a DNS name");
    }
    if entry.contains('/') || entry.contains(':') {
        return Some(
            "contains '/' or ':', which appear only in CIDR and IPv6 syntax, so this is a \
             malformed address rather than a hostname",
        );
    }
    let bytes = entry.as_bytes();
    let edges_are_alphanumeric = bytes
        .first()
        .zip(bytes.last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
    if !edges_are_alphanumeric {
        return Some("a hostname must begin and end with a letter or a digit");
    }
    if entry.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some("made only of digits and dots, so this is a malformed IPv4 literal");
    }
    if !entry.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return Some("contains characters that cannot appear in a DNS name");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_edge_cases() {
        assert_eq!(hostname_rejection(""), Some("empty"));
        assert_eq!(hostname_rejection("-leading-dash"), Some("a hostname must begin and end with a letter or a digit"));
        assert_eq!(hostname_rejection("trailing-dash-"), Some("a hostname must begin and end with a letter or a digit"));
        assert_eq!(hostname_rejection("has a space"), Some("contains characters that cannot appear in a DNS name"));
        assert_eq!(hostname_rejection(&"a".repeat(254)), Some("longer than the 253-character limit on a DNS name"));
        assert_eq!(hostname_rejection("traefik_tomidejetsu"), None);
        assert_eq!(hostname_rejection("proxy.internal"), None);
        assert_eq!(hostname_rejection("traefik-1"), None);
    }

    #[tokio::test]
    async fn a_resolvable_hostname_is_cached_and_returned() {
        let resolver = DnsResolver::new();
        let resolved = resolver.resolve("localhost").await;
        assert!(!resolved.is_empty(), "localhost must resolve to at least one address");
    }

    #[tokio::test]
    async fn an_unresolvable_hostname_yields_no_addresses_and_does_not_error() {
        let resolver = DnsResolver::new();
        let resolved = resolver.resolve("this-name-does-not-exist.invalid").await;
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn a_negative_cache_entry_expires_and_is_retried() {
        let resolver = DnsResolver::with_ttls(Duration::from_millis(500), Duration::from_millis(20));
        assert!(resolver.resolve("this-name-does-not-exist.invalid").await.is_empty());
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Past the (shortened) negative TTL: this must re-attempt rather than serve the stale
        // cached failure forever — the same property `config::TrustedProxies` relied on before
        // this cache was extracted out from under it.
        assert!(resolver.resolve("this-name-does-not-exist.invalid").await.is_empty());
    }

    #[tokio::test]
    async fn force_resolve_bypasses_a_fresh_cache_entry() {
        let resolver = DnsResolver::with_ttls(Duration::from_secs(300), Duration::from_secs(300));
        let _ = resolver.resolve("localhost").await;
        // Would normally be served from the (very long-lived) cache; force_resolve must still do a
        // real lookup rather than trusting it.
        let resolved = resolver.force_resolve("localhost").await;
        assert!(!resolved.is_empty());
    }
}
