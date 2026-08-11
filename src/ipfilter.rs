//! Output sanitization pipeline: RFC 1918 / bogon / loopback filtering, followed by
//! `ipnet::IpNet::aggregate()` to collapse contiguous blocks and overlapping subnets.

use std::sync::LazyLock;

use ipnet::IpNet;

/// Parses every literal in `raw`, silently dropping anything that fails to parse.
///
/// A malformed literal here would otherwise have to `.expect()` at process startup — a compile-time
/// constant that can never actually fail in a correctly-written list, but a panic in production code
/// all the same if a future edit introduced a typo. Parsing leniently instead means a bad entry is
/// simply missing from the filter rather than crashing the daemon; [`tests::every_filter_list_has_no_silently_dropped_entries`]
/// is what actually catches the typo, by asserting each list's length against its literal count.
fn nets(raw: &[&str]) -> Vec<IpNet> {
    raw.iter().filter_map(|s| s.parse().ok()).collect()
}

/// RFC 1918 private IPv4 ranges.
const RFC1918_LITERALS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
static RFC1918: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(RFC1918_LITERALS));

/// Loopback ranges (IPv4 and IPv6).
const LOOPBACK_LITERALS: &[&str] = &["127.0.0.0/8", "::1/128"];
static LOOPBACK: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(LOOPBACK_LITERALS));

/// Bogon / reserved / unallocated ranges, excluding RFC 1918 and loopback (governed by their own
/// flags). Not exhaustive of every IANA special-purpose registry entry, but covers the ranges that
/// matter for a public firewall feed.
const BOGON_LITERALS: &[&str] = &[
    "0.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::ffff:0:0/96",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];
static BOGONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| nets(BOGON_LITERALS));

/// Whether `candidate` falls (fully or partially) inside any of `excluded`.
fn overlaps_any(candidate: &IpNet, excluded: &[IpNet]) -> bool {
    excluded.iter().any(|ex| ex.contains(&candidate.network()) || candidate.contains(&ex.network()))
}

/// Applies the configured filters, then aggregates the survivors into the smallest equivalent set
/// of CIDR blocks.
pub fn filter_and_aggregate(
    networks: &[IpNet],
    filter_rfc1918: bool,
    filter_bogons: bool,
    filter_loopback: bool,
) -> Vec<IpNet> {
    let filtered: Vec<IpNet> = networks
        .iter()
        .copied()
        .filter(|net| !filter_rfc1918 || !overlaps_any(net, &RFC1918))
        .filter(|net| !filter_bogons || !overlaps_any(net, &BOGONS))
        .filter(|net| !filter_loopback || !overlaps_any(net, &LOOPBACK))
        .collect();
    IpNet::aggregate(&filtered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only convenience: production code never parses a literal it cannot statically know is
    /// valid CIDR notation without a fallback (see [`nets`]), but a test asserting on a malformed
    /// fixture string should fail loudly rather than silently comparing against an empty list.
    fn net(s: &str) -> IpNet {
        s.parse().expect("test fixture is a valid CIDR literal")
    }

    #[test]
    fn every_filter_list_has_no_silently_dropped_entries() {
        // `nets()` parses leniently so a malformed literal can never panic at startup; this is what
        // actually catches a typo — a bad entry would otherwise just be silently absent from the
        // list, quietly weakening the filter it was meant to strengthen.
        assert_eq!(RFC1918.len(), RFC1918_LITERALS.len(), "an RFC1918 literal failed to parse");
        assert_eq!(LOOPBACK.len(), LOOPBACK_LITERALS.len(), "a loopback literal failed to parse");
        assert_eq!(BOGONS.len(), BOGON_LITERALS.len(), "a bogon literal failed to parse");
    }

    #[test]
    fn aggregates_contiguous_and_overlapping_subnets() {
        let networks = vec![net("10.0.0.0/24"), net("10.0.0.1/32")];
        let out = filter_and_aggregate(&networks, false, false, false);
        assert_eq!(out, vec![net("10.0.0.0/24")]);
    }

    #[test]
    fn filters_rfc1918() {
        let networks = vec![net("10.0.0.5/32"), net("8.8.8.8/32")];
        let out = filter_and_aggregate(&networks, true, false, false);
        assert_eq!(out, vec![net("8.8.8.8/32")]);
    }

    #[test]
    fn filters_loopback() {
        let networks = vec![net("127.0.0.1/32"), net("::1/128"), net("8.8.8.8/32")];
        let out = filter_and_aggregate(&networks, false, false, true);
        assert_eq!(out, vec![net("8.8.8.8/32")]);
    }

    #[test]
    fn filters_bogons() {
        let networks = vec![net("169.254.1.1/32"), net("8.8.8.8/32")];
        let out = filter_and_aggregate(&networks, false, true, false);
        assert_eq!(out, vec![net("8.8.8.8/32")]);
    }

    #[test]
    fn no_filters_keeps_everything_but_still_aggregates() {
        let networks = vec![net("10.0.0.0/25"), net("10.0.0.128/25")];
        let out = filter_and_aggregate(&networks, false, false, false);
        assert_eq!(out, vec![net("10.0.0.0/24")]);
    }

    // ── Boundary conditions on individual bogon sub-ranges ──────────────────

    /// Carrier-Grade NAT (RFC 6598, `100.64.0.0/10`): the first and last addresses of the range
    /// are filtered, and the addresses immediately outside either edge are not — pinning the exact
    /// boundary rather than trusting the middle of the range to stand in for it.
    #[test]
    fn filters_cgn_at_its_exact_boundaries() {
        let inside = vec![net("100.64.0.0/32"), net("100.127.255.255/32")];
        assert_eq!(filter_and_aggregate(&inside, false, true, false), Vec::<IpNet>::new());

        let outside = vec![net("100.63.255.255/32"), net("100.128.0.0/32")];
        let out = filter_and_aggregate(&outside, false, true, false);
        assert_eq!(out.len(), 2, "addresses one step outside /10 on either edge must survive");
    }

    /// Multicast (`224.0.0.0/4`): the well-known all-hosts address, the top of the range, and the
    /// unicast address immediately below the range.
    #[test]
    fn filters_multicast_at_its_exact_boundaries() {
        let inside = vec![net("224.0.0.1/32"), net("239.255.255.255/32")];
        assert_eq!(filter_and_aggregate(&inside, false, true, false), Vec::<IpNet>::new());

        let outside = vec![net("223.255.255.255/32")];
        assert_eq!(filter_and_aggregate(&outside, false, true, false), outside);
    }

    /// APIPA / link-local (`169.254.0.0/16`).
    #[test]
    fn filters_apipa_at_its_exact_boundaries() {
        let inside = vec![net("169.254.0.0/32"), net("169.254.255.255/32")];
        assert_eq!(filter_and_aggregate(&inside, false, true, false), Vec::<IpNet>::new());

        let outside = vec![net("169.253.255.255/32"), net("169.255.0.0/32")];
        let out = filter_and_aggregate(&outside, false, true, false);
        assert_eq!(out.len(), 2, "addresses one step outside /16 on either edge must survive");
    }

    /// With every filter off, CGN/multicast/APIPA addresses pass straight through unfiltered —
    /// confirms the boundary tests above are exercising `filter_bogons`, not some other rejection.
    #[test]
    fn cgn_multicast_and_apipa_survive_when_no_filters_are_enabled() {
        let networks =
            vec![net("100.64.0.1/32"), net("224.0.0.1/32"), net("169.254.1.1/32")];
        let out = filter_and_aggregate(&networks, false, false, false);
        assert_eq!(out.len(), 3);
    }

    // ── IPv6 filtering ───────────────────────────────────────────────────────

    #[test]
    fn filters_ipv6_link_local_ula_and_multicast_as_bogons() {
        let networks = vec![
            net("fe80::1/128"),   // link-local
            net("fc00::1/128"),   // unique local
            net("ff02::1/128"),   // multicast
            net("2001:db8::1/128"), // documentation range
            net("2001:4860:4860::8888/128"), // a real public IPv6 address (Google DNS)
        ];
        let out = filter_and_aggregate(&networks, false, true, false);
        assert_eq!(out, vec![net("2001:4860:4860::8888/128")]);
    }

    #[test]
    fn filters_ipv6_loopback_independently_of_ipv4_loopback() {
        let networks = vec![net("::1/128"), net("127.0.0.1/32"), net("2001:4860:4860::8888/128")];
        let out = filter_and_aggregate(&networks, false, false, true);
        assert_eq!(out, vec![net("2001:4860:4860::8888/128")]);
    }

    // ── Mixed IPv4/IPv6 feeds ────────────────────────────────────────────────

    /// A feed mixing address families must filter and aggregate each family independently: an
    /// IPv4 bogon must never suppress an unrelated IPv6 survivor (or vice versa), and aggregation
    /// must never attempt to merge across families.
    #[test]
    fn mixed_ipv4_and_ipv6_feed_is_filtered_and_aggregated_independently() {
        let networks = vec![
            net("10.0.0.0/24"),           // RFC1918 v4 — filtered
            net("192.168.1.1/32"),        // RFC1918 v4 — filtered
            net("2001:db8::1/128"),       // documentation v6 (bogon) — filtered
            net("8.8.8.0/24"),            // public v4 — survives
            net("8.8.8.1/32"),            // public v4, contained in the above — aggregates away
            net("2001:4860:4860::8888/128"), // public v6 — survives
        ];
        let mut out = filter_and_aggregate(&networks, true, true, false);
        out.sort_by_key(|n| n.to_string());
        let mut expected = vec![net("8.8.8.0/24"), net("2001:4860:4860::8888/128")];
        expected.sort_by_key(|n| n.to_string());
        assert_eq!(out, expected);
    }

    /// Without any filters, a mixed-family feed still aggregates each family on its own terms and
    /// never cross-contaminates: an IPv4 supernet must not appear to "swallow" an IPv6 address
    /// with a numerically similar textual representation, nor the reverse.
    #[test]
    fn mixed_family_aggregation_never_merges_across_families() {
        let networks = vec![net("10.0.0.0/24"), net("2001:db8:1::/48"), net("2001:db8:2::/48")];
        let out = filter_and_aggregate(&networks, false, false, false);
        assert_eq!(out.len(), 3, "a v4 network and two non-contiguous v6 networks stay distinct");
        assert!(out.contains(&net("10.0.0.0/24")));
    }

    // ── `overlaps_any` semantics on a supernet that only partially overlaps ─

    /// A candidate supernet that only *partially* overlaps a bogon sub-range is dropped in full,
    /// not narrowed to the non-bogon portion — `overlaps_any` is deliberately "any overlap drops
    /// the whole candidate", the conservative direction for a security filter. This pins that
    /// documented behavior so it cannot silently change to a narrowing (or fail-open) later.
    #[test]
    fn a_supernet_only_partially_overlapping_a_bogon_is_dropped_entirely() {
        // 100.0.0.0/8 contains the CGN range 100.64.0.0/10 as a strict sub-range, but also covers
        // plenty of address space that is not CGN at all.
        let networks = vec![net("100.0.0.0/8")];
        let out = filter_and_aggregate(&networks, false, true, false);
        assert!(out.is_empty(), "any overlap with a bogon range drops the whole candidate");
    }
}
