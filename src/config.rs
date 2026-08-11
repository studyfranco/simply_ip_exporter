//! Runtime configuration, read once from the environment at startup. Every field has a safe
//! default; a malformed override logs a warning and falls back, except `TRUSTED_PROXIES` and
//! `INITIAL_MASTER_KEY`, which are fatal misconfigurations of a trust boundary.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnet::IpNet;

/// Default listen address: every interface.
const DEFAULT_BIND_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
/// Default listen port, per `AGENT.MD`.
const DEFAULT_BIND_PORT: u16 = 3002;
/// Default anti-replay window for signed `/api/*` requests, in seconds (±300s).
const DEFAULT_SIGNATURE_MAX_AGE_SECONDS: i64 = 300;

/// One entry of `TRUSTED_PROXIES`: a literal address or CIDR range.
pub type ProxySpec = IpNet;

/// The set of peers whose `X-Forwarded-For` / `X-Real-IP` headers are believed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    /// Whether nothing at all is trusted — the secure default.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The configured networks.
    pub fn networks(&self) -> &[IpNet] {
        &self.0
    }
}

/// Why a `TRUSTED_PROXIES` entry could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("FATAL: TRUSTED_PROXIES entry '{entry}' is not a valid IP address or CIDR range")]
pub struct TrustedProxyError {
    /// The offending entry, exactly as written.
    pub entry: String,
}

/// Parses `TRUSTED_PROXIES` (comma-separated CIDRs or bare addresses, widened to a host route).
/// A syntax error is fatal: silently dropping an unparseable entry would leave an operator
/// believing a proxy is trusted when it is not, letting `bound_ips` be evaluated against the
/// wrong address.
pub fn parse_trusted_proxies(raw: &str) -> Result<TrustedProxies, TrustedProxyError> {
    let networks = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| match entry.parse::<IpNet>() {
            Ok(net) => Ok(net),
            Err(_) => entry
                .parse::<IpAddr>()
                .map(IpNet::from)
                .map_err(|_| TrustedProxyError { entry: entry.to_owned() }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TrustedProxies(networks))
}

/// Normalizes an IPv4-mapped IPv6 address (`::ffff:192.168.1.1`) down to its plain IPv4 form.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

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
#[derive(Clone, Debug, PartialEq)]
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
    /// only on a malformed `TRUSTED_PROXIES` entry.
    pub fn from_env() -> Result<Self, TrustedProxyError> {
        let defaults = Self::default();

        let trusted_proxies =
            parse_trusted_proxies(std::env::var("TRUSTED_PROXIES").ok().as_deref().unwrap_or(""))?;
        if trusted_proxies.is_empty() {
            tracing::info!(
                "TRUSTED_PROXIES is unset: X-Forwarded-For and X-Real-IP are ignored; bound_ips is \
                 evaluated against the direct TCP peer."
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
    fn parses_cidrs_and_bare_addresses() {
        let proxies = parse_trusted_proxies("127.0.0.1, 10.0.0.0/8 ,::1").expect("parses");
        assert_eq!(proxies.networks().len(), 3);
    }

    #[test]
    fn a_syntax_error_is_fatal() {
        assert!(parse_trusted_proxies("not-an-ip").is_err());
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
