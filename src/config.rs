//! Runtime configuration, read once from the environment at startup. Every field has a safe
//! default; a malformed override logs a warning and falls back, except `TRUSTED_PROXIES` and
//! `INITIAL_MASTER_KEY`, which are fatal misconfigurations of a trust boundary.
//!
//! `TRUSTED_PROXIES` hostname support (2026-08-19) is ported from `example/simply_ip_vault`'s
//! `TrustedProxies`/`ProxyMatcher` — see `AGENT_NOTES.MD` for why this crate now matches that
//! design (positive/negative DNS caching, a boot grace period, background retry) rather than the
//! simpler fail-hard-on-unresolvable-hostname scheme an earlier draft of this change used.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;

use crate::dns_cache::{DnsResolver, hostname_rejection, normalize_ip};

/// Default listen address: every interface.
const DEFAULT_BIND_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
/// Default listen port, per `AGENT.MD`.
const DEFAULT_BIND_PORT: u16 = 3002;
/// Default anti-replay window for signed `/api/*` requests, in seconds (±300s).
const DEFAULT_SIGNATURE_MAX_AGE_SECONDS: i64 = 300;

/// Environment variable name for the trusted-proxy list.
pub const TRUSTED_PROXIES_ENV: &str = "TRUSTED_PROXIES";

/// One entry of `TRUSTED_PROXIES`: a literal address or CIDR range.
pub type ProxySpec = IpNet;

/// How long after boot an initially-unresolvable hostname is given before the failure is reported
/// as persistent.
///
/// A daemon and its reverse proxy usually start together, and the proxy's DNS record (a Docker
/// container name, a Kubernetes service) may not exist for the first few seconds of the daemon's
/// life. Aborting startup over that would turn an ordinary boot race into a crash loop, which is
/// strictly worse than running with that one entry disabled: every other trusted entry, and every
/// caller not behind the affected proxy, is served correctly either way.
const BOOT_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// A `TRUSTED_PROXIES` entry: either a fixed network or a name resolved at request time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMatcher {
    /// A literal address or CIDR range, matched directly.
    Network(IpNet),
    /// A hostname (`traefik`, `traefik_tomidejetsu`, `proxy.internal`) resolved via DNS.
    ///
    /// Kept as a name rather than resolved once at startup because that is the entire point: in
    /// Docker and Kubernetes a service name outlives the address behind it, and a container
    /// restart that changes the IP must not silently stop the proxy from being trusted.
    Hostname(String),
}

impl std::fmt::Display for ProxyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(network) => write!(f, "{network}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

/// A `TRUSTED_PROXIES` entry that is not a valid spelling of anything, and why.
///
/// Distinct from a hostname that merely fails to resolve *right now*: this is a value that can
/// never become usable no matter what DNS does, so it is a configuration error rather than a
/// transient one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidProxyEntry {
    /// The entry exactly as written, so the operator can find it in their configuration.
    pub entry: String,
    /// Why it was refused, phrased to name the mistake rather than the rule.
    pub reason: &'static str,
}

/// Startup refusal: at least one `TRUSTED_PROXIES` entry was syntactically impossible.
///
/// # Why this aborts rather than dropping the entry
///
/// Every other malformed override in this module falls back to a default, because the fallback is
/// unambiguous and safe. This one is neither. `TRUSTED_PROXIES` is the list of peers permitted to
/// *rewrite the client address every `bound_ips` decision is made against*, and an entry that
/// cannot be parsed leaves that boundary in a state nobody has established — silently dropping it
/// fails closed for the entry itself, but every request through that proxy is then attributed to
/// the proxy's own address, turning a CIDR-bound key's traffic into an unmissable, unexplained
/// `403`. Refusing to start converts a typo into a loud, immediate failure at the only moment the
/// operator is watching.
///
/// It is safe to be this strict *because* the check is purely syntactic: a hostname that is
/// well-formed but currently unresolvable is not an error here at all — it keeps the
/// [`BOOT_GRACE_PERIOD`] path, because DNS being briefly down must not crash-loop the daemon. See
/// `main.rs`'s ordering: `TrustedProxies::from_env()` runs before the database is even opened;
/// `prime_with_grace()` (the part that actually does DNS) runs much later and never aborts startup.
#[derive(Debug, thiserror::Error)]
#[error(
    "{} invalid {TRUSTED_PROXIES_ENV} entr{}: {}",
    entries.len(),
    if entries.len() == 1 { "y" } else { "ies" },
    entries.iter().map(|e| format!("{:?} ({})", e.entry, e.reason)).collect::<Vec<_>>().join("; ")
)]
pub struct InvalidTrustedProxies {
    /// Every rejected entry, so one restart surfaces all of the typos rather than the first.
    pub entries: Vec<InvalidProxyEntry>,
}

/// The set of peers whose `X-Forwarded-For` / `X-Real-IP` headers are believed.
///
/// Holds the parsed `TRUSTED_PROXIES` specification plus a [`DnsResolver`] resolving its hostname
/// entries — the same cache/TTL machinery `bound_ips` hostname support shares (see
/// [`Self::dns_resolver`] and `dns_cache`'s module docs). Cloning shares the cache (every field is
/// `Arc`-backed), so every handler sees one resolution rather than each maintaining its own.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    /// The configuration exactly as written, for logging.
    matchers: Arc<Vec<ProxyMatcher>>,
    /// Literal entries, precomputed. Also the complete answer when no hostnames are configured —
    /// the common case, served for the cost of an `Arc` clone and no resolver call at all.
    networks: Arc<Vec<IpNet>>,
    /// Hostname entries awaiting resolution.
    hostnames: Arc<Vec<String>>,
    dns: DnsResolver,
}

impl TrustedProxies {
    /// Builds from an already-parsed matcher list.
    pub fn new(matchers: Vec<ProxyMatcher>) -> Self {
        let networks: Vec<IpNet> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(net) => Some(*net),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect();
        let hostnames: Vec<String> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Hostname(name) => Some(name.clone()),
                ProxyMatcher::Network(_) => None,
            })
            .collect();

        Self {
            matchers: Arc::new(matchers),
            networks: Arc::new(networks),
            hostnames: Arc::new(hostnames),
            dns: DnsResolver::new(),
        }
    }

    /// The shared DNS cache backing this instance's hostname entries — cloned into `AppState` so
    /// `bound_ips` hostname checks (`bound_ips::is_allowed`) resolve through the exact same
    /// cache/TTL policy, and so a name referenced by both `TRUSTED_PROXIES` and some key's/
    /// endpoint's `bound_ips` resolves once rather than twice.
    pub fn dns_resolver(&self) -> DnsResolver {
        self.dns.clone()
    }

    /// Reads and parses [`TRUSTED_PROXIES_ENV`], refusing to build if any entry is malformed.
    ///
    /// Every rejected entry is logged on its own `FATAL:` line before the error is returned, so an
    /// operator with three typos sees three lines naming three entries, not one line naming the
    /// first. This runs before any DNS resolution or grace-period logic — the check is syntactic,
    /// so there is nothing to wait for.
    ///
    /// An **unset** variable is not an error: the zero-configuration case means "trust nothing",
    /// the safe posture rather than an ambiguous one.
    pub fn from_env() -> Result<Self, InvalidTrustedProxies> {
        let Ok(raw) = std::env::var(TRUSTED_PROXIES_ENV) else {
            return Ok(Self::default());
        };

        match parse_trusted_proxies(&raw) {
            Ok(matchers) => Ok(Self::new(matchers)),
            Err(entries) => {
                for invalid in &entries {
                    tracing::error!(
                        "FATAL: {} entry '{}' is not a valid IP address, CIDR range, or hostname \
                         ({}). Refusing to start with an ambiguous trust boundary.",
                        TRUSTED_PROXIES_ENV,
                        invalid.entry,
                        invalid.reason
                    );
                }
                Err(InvalidTrustedProxies { entries })
            }
        }
    }

    /// Overrides both DNS reuse windows. Test-facing: a suite cannot wait 30 seconds to observe
    /// that a re-resolution happened, nor 5 to observe that one was suppressed.
    #[cfg(test)]
    pub fn with_ttls(mut self, positive: Duration, negative: Duration) -> Self {
        self.dns = DnsResolver::with_ttls(positive, negative);
        self
    }

    /// Whether nothing at all is trusted — the secure default.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// The configured matchers, for startup logging.
    pub fn matchers(&self) -> &[ProxyMatcher] {
        &self.matchers
    }

    /// The networks to match this request against, resolving hostnames through the shared
    /// [`DnsResolver`] (reusing its cache entry when still fresh).
    ///
    /// The no-hostname case — every deployment that names its proxies by address — never touches
    /// the resolver at all, just an `Arc` clone.
    ///
    /// Resolving the *whole set* into one flat list, rather than testing hostnames lazily per
    /// address, is what lets [`resolve_client_ip`] treat a hostname-identified proxy exactly like a
    /// CIDR one while walking the `X-Forwarded-For` chain.
    pub async fn resolved(&self) -> Arc<Vec<IpNet>> {
        if self.hostnames.is_empty() {
            return Arc::clone(&self.networks);
        }

        let mut merged = (*self.networks).clone();
        for name in self.hostnames.iter() {
            merged.extend(self.dns.resolve(name).await);
        }
        Arc::new(merged)
    }

    /// Resolves every configured hostname once at boot, reporting the names that failed.
    ///
    /// Never returns an error and never panics: a name that does not resolve is simply not
    /// trusted, the safe direction, and a per-entry outcome rather than a service-wide one.
    pub async fn prime(&self) -> Vec<String> {
        if self.hostnames.is_empty() {
            return Vec::new();
        }

        let mut failed = Vec::new();
        for name in self.hostnames.iter() {
            // Force a real attempt rather than reusing whatever a concurrent request just cached.
            if self.dns.force_resolve(name).await.is_empty() {
                failed.push(name.clone());
            }
        }
        failed
    }

    /// Primes the set at boot and, if anything failed to resolve, retries once after
    /// [`BOOT_GRACE_PERIOD`] on a detached task.
    ///
    /// The service is fully operational throughout — unresolved entries are simply untrusted until
    /// they resolve, and normal per-request refresh picks them up whenever they start working. The
    /// grace retry exists so the *logs* distinguish a boot race that healed itself from a genuine
    /// misconfiguration, without an operator having to correlate timestamps.
    pub fn prime_with_grace(&self) {
        let proxies = self.clone();
        tokio::spawn(async move {
            let failed = proxies.prime().await;
            if failed.is_empty() {
                if !proxies.hostnames.is_empty() {
                    tracing::info!(
                        "All {} {} hostname entr{} resolved at startup.",
                        proxies.hostnames.len(),
                        TRUSTED_PROXIES_ENV,
                        if proxies.hostnames.len() == 1 { "y" } else { "ies" }
                    );
                }
                return;
            }

            tracing::error!(
                "{} hostname entr{} did not resolve at startup: {:?}. Those peers are NOT trusted \
                 and their forwarding headers will be ignored; every other entry is unaffected and \
                 the service is serving normally. Retrying in {}s.",
                TRUSTED_PROXIES_ENV,
                if failed.len() == 1 { "y" } else { "ies" },
                failed,
                BOOT_GRACE_PERIOD.as_secs()
            );

            tokio::time::sleep(BOOT_GRACE_PERIOD).await;
            let still_failing = proxies.prime().await;
            if still_failing.is_empty() {
                tracing::info!(
                    "All {} hostname entries resolved after the {}s grace period; they are trusted \
                     from now on.",
                    TRUSTED_PROXIES_ENV,
                    BOOT_GRACE_PERIOD.as_secs()
                );
            } else {
                tracing::error!(
                    "{} hostname entr{} still unresolvable after the {}s grace period: {:?}. \
                     Continuing to serve with {} entr{} disabled — check the name and the \
                     resolver. Resolution is retried automatically; no restart is required.",
                    TRUSTED_PROXIES_ENV,
                    if still_failing.len() == 1 { "y" } else { "ies" },
                    BOOT_GRACE_PERIOD.as_secs(),
                    still_failing,
                    still_failing.len(),
                    if still_failing.len() == 1 { "y" } else { "ies" }
                );
            }
        });
    }
}

/// Parses a `TRUSTED_PROXIES` value into matchers, or reports every entry that is unusable.
///
/// Three spellings are accepted, tried in order: a CIDR range (`172.16.0.0/12`), a bare address
/// (`127.0.0.1`, promoted to a single-host network so nobody has to remember `/32`), and otherwise
/// a hostname (`traefik`, `traefik_tomidejetsu`) resolved at request time.
///
/// Anything else is a **hard error** rather than a dropped entry — see [`InvalidTrustedProxies`]
/// for why a trust boundary is the one setting in this module that must not degrade quietly. Every
/// bad entry is collected rather than just the first, so an operator fixing a mistyped list needs
/// one restart, not one per typo.
///
/// The check is purely syntactic and does no I/O: a well-formed hostname is accepted here whether
/// or not it currently resolves, which is what keeps a DNS outage from becoming a refusal to boot.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<ProxyMatcher>, Vec<InvalidProxyEntry>> {
    let mut matchers = Vec::new();
    let mut invalid = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Ok(net) = entry.parse::<IpNet>() {
            matchers.push(ProxyMatcher::Network(net));
        } else if let Ok(addr) = entry.parse::<IpAddr>() {
            matchers.push(ProxyMatcher::Network(IpNet::from(addr)));
        } else {
            match hostname_rejection(entry) {
                None => matchers.push(ProxyMatcher::Hostname(entry.to_owned())),
                Some(reason) => invalid.push(InvalidProxyEntry { entry: entry.to_owned(), reason }),
            }
        }
    }

    if invalid.is_empty() { Ok(matchers) } else { Err(invalid) }
}

// `hostname_rejection` — the syntactic check backing the `else` branch above — now lives in
// `dns_cache` (imported at the top of this module) so `bound_ips` hostname validation is
// refused/accepted by the identical rule rather than a second, potentially-drifting definition of
// "looks like a hostname". See its doc comment there for the full rationale.

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

/// Determines the client address to authorize `bound_ips` against.
///
/// Forwarding headers are consulted only when the TCP peer is itself a trusted proxy. When
/// trusted, `X-Forwarded-For` is walked right-to-left, skipping addresses that are themselves
/// trusted proxies, so the first remaining address is the real client. `X-Real-IP` is a fallback
/// when `X-Forwarded-For` is absent or yields nothing.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[IpNet],
) -> IpAddr {
    let peer = normalize_ip(peer);
    if !is_trusted(peer, trusted) {
        return peer;
    }

    if let Some(forwarded) = headers.get("X-Forwarded-For").and_then(|h| h.to_str().ok()) {
        let client = forwarded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(normalize_ip)
            .rev()
            .find(|ip| !is_trusted(*ip, trusted));
        if let Some(client) = client {
            return client;
        }
    }

    if let Some(real_ip) = headers
        .get("X-Real-IP")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return normalize_ip(real_ip);
    }

    peer
}

/// Immutable runtime configuration shared by every handler and background worker.
///
/// No longer `PartialEq` (2026-08-19): `TrustedProxies`' DNS resolution cache holds a
/// `tokio::sync::RwLock`, which has none — nothing in this crate ever compared two whole
/// `RuntimeConfig`s for equality.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Peers whose forwarding headers are believed. Empty (the default) means "believe none".
    pub trusted_proxies: TrustedProxies,
    /// How far a request's `X-Timestamp` may be from the server's clock, in seconds, before the
    /// signature is rejected. Overridden by `SIGNATURE_MAX_AGE_SECONDS`.
    pub signature_max_age_seconds: i64,
    /// Base URL of the `simply_ip_vault` instance to sync from (e.g. `http://vault:3000`).
    pub vault_base_url: Option<String>,
    /// `X-API-Key` used to authenticate to `simply_ip_vault`.
    pub vault_api_key: Option<String>,
    /// HMAC-SHA256 signing secret shared with `simply_ip_vault`.
    pub vault_signing_secret: Option<String>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: TrustedProxies::default(),
            signature_max_age_seconds: DEFAULT_SIGNATURE_MAX_AGE_SECONDS,
            vault_base_url: None,
            vault_api_key: None,
            vault_signing_secret: None,
        }
    }
}

impl RuntimeConfig {
    /// Builds the configuration from the process environment, falling back to defaults. Fails
    /// only on a syntactically malformed `TRUSTED_PROXIES` entry — a well-formed hostname that
    /// merely doesn't resolve yet is not an error here; see [`TrustedProxies::from_env`].
    pub fn from_env() -> Result<Self, InvalidTrustedProxies> {
        let defaults = Self::default();

        let trusted_proxies = TrustedProxies::from_env()?;
        if trusted_proxies.is_empty() {
            tracing::info!(
                "TRUSTED_PROXIES is unset: X-Forwarded-For and X-Real-IP are ignored; bound_ips is \
                 evaluated against the direct TCP peer."
            );
        } else {
            tracing::info!(
                "TRUSTED_PROXIES is set: forwarding headers are honoured from {} matcher(s): {:?}",
                trusted_proxies.matchers().len(),
                trusted_proxies.matchers()
            );
        }

        Ok(Self {
            trusted_proxies,
            signature_max_age_seconds: parse_or_warn(
                "SIGNATURE_MAX_AGE_SECONDS",
                defaults.signature_max_age_seconds,
            )
            .max(1),
            vault_base_url: std::env::var("VAULT_BASE_URL")
                .ok()
                .map(|s| s.trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty()),
            vault_api_key: std::env::var("VAULT_API_KEY").ok().filter(|s| !s.is_empty()),
            vault_signing_secret: std::env::var("VAULT_SIGNING_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

/// Resolves the socket address the HTTP server binds to, from `BIND_HOST`/`HOST` and `PORT`.
pub fn resolve_bind_addr() -> SocketAddr {
    let host = std::env::var("BIND_HOST").or_else(|_| std::env::var("HOST")).ok();
    let port = std::env::var("PORT").ok();
    parse_bind_addr(host.as_deref(), port.as_deref())
}

/// Builds a listen address from optional raw `host`/`port` strings, parsed leniently.
pub fn parse_bind_addr(host: Option<&str>, port: Option<&str>) -> SocketAddr {
    let ip = match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(raw) => raw.parse::<IpAddr>().unwrap_or_else(|_| {
            tracing::warn!("Invalid bind host {raw:?} — falling back to {DEFAULT_BIND_HOST}");
            DEFAULT_BIND_HOST
        }),
        None => DEFAULT_BIND_HOST,
    };
    let port = match port.map(str::trim).filter(|p| !p.is_empty()) {
        Some(raw) => raw.parse::<u16>().unwrap_or_else(|_| {
            tracing::warn!("Invalid PORT {raw:?} — falling back to {DEFAULT_BIND_PORT}");
            DEFAULT_BIND_PORT
        }),
        None => DEFAULT_BIND_PORT,
    };
    SocketAddr::new(ip, port)
}

/// Required width of `INITIAL_MASTER_KEY`, in hex characters.
pub const INITIAL_MASTER_KEY_HEX_LEN: usize = 64;

/// Why an `INITIAL_MASTER_KEY` was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InitialMasterKeyError {
    /// The variable was set to an empty or whitespace-only value.
    #[error(
        "INITIAL_MASTER_KEY is set but empty. Unset it to generate a random master key, or set it \
         to {INITIAL_MASTER_KEY_HEX_LEN} hex characters (`openssl rand -hex 32`)."
    )]
    Empty,
    /// The value was the wrong width.
    #[error(
        "INITIAL_MASTER_KEY must be exactly {INITIAL_MASTER_KEY_HEX_LEN} hex characters; got {0}."
    )]
    BadLength(usize),
    /// The value contained a non-hex character.
    #[error("INITIAL_MASTER_KEY must be hexadecimal; found {0:?} at position {1}.")]
    NonHex(char, usize),
}

/// Validates the `INITIAL_MASTER_KEY` bootstrap override. Absence is the documented zero-config
/// path and is not an error; a set-but-invalid value is fatal.
pub fn validate_initial_master_key(
    raw: Option<&str>,
) -> Result<Option<String>, InitialMasterKeyError> {
    let Some(raw) = raw else { return Ok(None) };
    let candidate = raw.trim();
    if candidate.is_empty() {
        return Err(InitialMasterKeyError::Empty);
    }
    if let Some((index, found)) = candidate.char_indices().find(|(_, c)| !c.is_ascii_hexdigit()) {
        return Err(InitialMasterKeyError::NonHex(found, index));
    }
    let width = candidate.chars().count();
    if width != INITIAL_MASTER_KEY_HEX_LEN {
        return Err(InitialMasterKeyError::BadLength(width));
    }
    Ok(Some(candidate.to_owned()))
}

/// Reads and parses an environment variable, warning and falling back on a malformed value.
fn parse_or_warn<T: std::str::FromStr + std::fmt::Display>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(raw) => raw.trim().parse::<T>().unwrap_or_else(|_| {
            tracing::warn!("Invalid value for {name}: {raw:?} — falling back to {default}");
            default
        }),
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidrs_and_bare_addresses_as_network_matchers() {
        let matchers = parse_trusted_proxies("127.0.0.1, 10.0.0.0/8 ,::1").expect("parses");
        assert_eq!(matchers.len(), 3);
        assert!(matchers.iter().all(|m| matches!(m, ProxyMatcher::Network(_))));
    }

    /// The motivating case (`AGENT_NOTES.MD`, 2026-08-19): a Docker container name like
    /// `traefik_tomidejetsu` is shaped like neither an address nor a CIDR, but is a well-formed
    /// hostname — accepted as a [`ProxyMatcher::Hostname`], not a startup failure.
    #[test]
    fn a_docker_container_name_parses_as_a_hostname_matcher() {
        let matchers = parse_trusted_proxies("traefik_tomidejetsu").expect("a hostname parses");
        assert_eq!(matchers, vec![ProxyMatcher::Hostname("traefik_tomidejetsu".to_owned())]);
    }

    #[test]
    fn a_mixed_list_parses_each_entry_as_its_own_kind() {
        let matchers = parse_trusted_proxies("10.0.0.0/8, traefik, 127.0.0.1").expect("parses");
        assert_eq!(
            matchers,
            vec![
                ProxyMatcher::Network("10.0.0.0/8".parse().unwrap()),
                ProxyMatcher::Hostname("traefik".to_owned()),
                ProxyMatcher::Network("127.0.0.1".parse::<IpAddr>().unwrap().into()),
            ]
        );
    }

    /// A genuinely malformed entry — not an address, not a CIDR, and not shaped like a hostname
    /// either — is still fatal. This is the property `TrustedProxies::from_env` still enforces:
    /// hostname support widens what's *accepted*, it does not remove the syntax check.
    #[test]
    fn a_syntax_error_is_still_fatal() {
        let err = parse_trusted_proxies("not/a:valid thing").unwrap_err();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].entry, "not/a:valid thing");
    }

    /// `10.0.0.256` looks like a typo'd IPv4 literal, not a hostname — accepting it as a hostname
    /// would hide the typo behind a permanently-non-matching entry instead of a loud startup error.
    #[test]
    fn digits_and_dots_only_is_rejected_as_a_malformed_address_not_accepted_as_a_hostname() {
        let err = parse_trusted_proxies("10.0.0.256").unwrap_err();
        assert_eq!(err[0].reason, "made only of digits and dots, so this is a malformed IPv4 literal");
    }

    /// `10.0.0.0/99` is a near-miss CIDR (contains `/`), not a hostname — must surface as the
    /// configuration error it is rather than a name that silently never matches.
    #[test]
    fn a_near_miss_cidr_is_rejected_rather_than_treated_as_a_hostname() {
        let err = parse_trusted_proxies("10.0.0.0/99").unwrap_err();
        assert!(err[0].reason.contains("CIDR"), "reason: {}", err[0].reason);
    }

    #[test]
    fn multiple_bad_entries_are_all_reported_not_just_the_first() {
        let err = parse_trusted_proxies("not/valid, also:bad").unwrap_err();
        assert_eq!(err.len(), 2, "an operator with two typos should see both in one restart");
    }

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

    #[test]
    fn trusted_proxies_from_env_defaults_to_empty_when_unset() {
        // No env var mutation needed: `from_env` treats an absent variable as "trust nothing"
        // regardless of whatever the test process's real environment happens to hold, as long as
        // this suite doesn't run with TRUSTED_PROXIES actually set — which CI/local dev never does
        // for a `cargo test` invocation of this crate.
        if std::env::var(TRUSTED_PROXIES_ENV).is_err() {
            let proxies = TrustedProxies::from_env().expect("unset is not an error");
            assert!(proxies.is_empty());
        }
    }

    /// `resolved()` on a literal-only set must be usable without an async runtime doing anything
    /// beyond returning the precomputed list — this is the common-case fast path every request
    /// without a configured hostname takes.
    #[tokio::test]
    async fn resolving_a_literal_only_set_returns_the_precomputed_networks() {
        let matchers = parse_trusted_proxies("10.0.0.0/8, 127.0.0.1").expect("parses");
        let proxies = TrustedProxies::new(matchers);
        let resolved = proxies.resolved().await;
        assert_eq!(resolved.len(), 2);
    }

    /// A real DNS resolution, exercised against `localhost` — resolvable via `/etc/hosts` on every
    /// sandboxed test environment, with no real network round-trip required, unlike an arbitrary
    /// external hostname would need.
    #[tokio::test]
    async fn a_resolvable_hostname_becomes_trusted() {
        let proxies = TrustedProxies::new(vec![ProxyMatcher::Hostname("localhost".to_owned())]);
        let resolved = proxies.resolved().await;
        assert!(!resolved.is_empty(), "localhost must resolve to at least one address");
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let loopback_v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert!(
            resolved.iter().any(|n| n.addr() == loopback || n.addr() == loopback_v6),
            "expected a loopback address among {resolved:?}"
        );
    }

    /// An unresolvable hostname must fail closed — no addresses, no panic, no propagated error —
    /// exactly the property `resolve_hostname`'s own doc comment describes.
    #[tokio::test]
    async fn an_unresolvable_hostname_yields_no_addresses_and_does_not_error() {
        let proxies =
            TrustedProxies::new(vec![ProxyMatcher::Hostname("this-name-does-not-exist.invalid".to_owned())]);
        let resolved = proxies.resolved().await;
        assert!(resolved.is_empty());
    }

    /// [`TrustedProxies::prime`] names exactly the hostnames that failed to resolve, which is what
    /// `prime_with_grace`'s logging depends on to tell an operator *which* entry is the problem.
    #[tokio::test]
    async fn prime_reports_the_specific_hostnames_that_failed() {
        let proxies = TrustedProxies::new(vec![
            ProxyMatcher::Hostname("localhost".to_owned()),
            ProxyMatcher::Hostname("this-name-does-not-exist.invalid".to_owned()),
        ]);
        let failed = proxies.prime().await;
        assert_eq!(failed, vec!["this-name-does-not-exist.invalid".to_owned()]);
    }

    /// End-to-end: a hostname-based trust entry, once resolved, is indistinguishable from a literal
    /// CIDR as far as `resolve_client_ip`'s forwarding-header logic is concerned — proving the two
    /// halves (async resolution, sync matching) actually compose correctly.
    #[tokio::test]
    async fn a_resolved_hostname_is_honoured_exactly_like_a_literal_cidr_by_resolve_client_ip() {
        let proxies = TrustedProxies::new(vec![ProxyMatcher::Hostname("localhost".to_owned())]);
        let resolved = proxies.resolved().await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.7".parse().unwrap());
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            resolve_client_ip(peer, &headers, &resolved),
            "203.0.113.7".parse::<IpAddr>().unwrap(),
            "a request from the resolved (trusted) loopback peer should have its forwarded-for header honoured"
        );
    }

    /// A cached negative result eventually expires and a later attempt reflects current reality —
    /// the property that lets a hostname which starts unresolvable (a boot race) later become
    /// trusted without a restart. Uses `with_ttls` to shrink the wait from
    /// [`NEGATIVE_TTL`]'s real 5s to something a test suite can afford.
    #[tokio::test]
    async fn a_negative_cache_entry_expires_and_is_retried() {
        let proxies = TrustedProxies::new(vec![ProxyMatcher::Hostname("this-name-does-not-exist.invalid".to_owned())])
            .with_ttls(Duration::from_millis(500), Duration::from_millis(20));

        assert!(proxies.resolved().await.is_empty(), "first attempt: still unresolvable");
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Past the (shortened) negative TTL: this must re-attempt rather than serve the stale
        // cached failure forever. The hostname is still bogus, so the observable outcome is the
        // same — what this proves is that the second call didn't just trust an expired cache entry
        // (which `is_fresh` gates and `refresh_locked` re-populates either way).
        assert!(proxies.resolved().await.is_empty(), "second attempt after TTL expiry: still correctly empty");
    }

    #[test]
    fn forwarding_headers_are_ignored_from_an_untrusted_peer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(resolve_client_ip(peer, &headers, &[]), peer);
    }

    #[test]
    fn forwarding_headers_are_honoured_from_a_trusted_peer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4, 10.0.0.5".parse().unwrap());
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve_client_ip(peer, &headers, &trusted), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn bind_addr_falls_back_on_malformed_input() {
        assert_eq!(parse_bind_addr(Some("not-an-ip"), Some("abc")).port(), DEFAULT_BIND_PORT);
        assert_eq!(parse_bind_addr(Some("0.0.0.0"), Some("9999")), "0.0.0.0:9999".parse().unwrap());
    }

    #[test]
    fn initial_master_key_validation() {
        assert_eq!(validate_initial_master_key(None), Ok(None));
        assert_eq!(validate_initial_master_key(Some("")), Err(InitialMasterKeyError::Empty));
        assert_eq!(
            validate_initial_master_key(Some(&"a".repeat(64))),
            Ok(Some("a".repeat(64)))
        );
        assert_eq!(
            validate_initial_master_key(Some(&"a".repeat(63))),
            Err(InitialMasterKeyError::BadLength(63))
        );
        assert_eq!(
            validate_initial_master_key(Some("zzzz")),
            Err(InitialMasterKeyError::NonHex('z', 0))
        );
    }
}
