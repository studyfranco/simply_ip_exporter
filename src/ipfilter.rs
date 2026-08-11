//! Output sanitization pipeline: RFC 1918 / bogon / loopback filtering, followed by
//! `ipnet::IpNet::aggregate()` to collapse contiguous blocks and overlapping subnets.

use std::sync::LazyLock;

use ipnet::IpNet;

fn net(s: &str) -> IpNet {
    s.parse().expect("constant is a valid CIDR literal")
}

/// RFC 1918 private IPv4 ranges.
static RFC1918: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| vec![net("10.0.0.0/8"), net("172.16.0.0/12"), net("192.168.0.0/16")]);

/// Loopback ranges (IPv4 and IPv6).
static LOOPBACK: LazyLock<Vec<IpNet>> = LazyLock::new(|| vec![net("127.0.0.0/8"), net("::1/128")]);

/// Bogon / reserved / unallocated ranges, excluding RFC 1918 and loopback (governed by their own
/// flags). Not exhaustive of every IANA special-purpose registry entry, but covers the ranges that
/// matter for a public firewall feed.
static BOGONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    vec![
        net("0.0.0.0/8"),
        net("100.64.0.0/10"),
        net("169.254.0.0/16"),
        net("192.0.0.0/24"),
        net("192.0.2.0/24"),
        net("192.88.99.0/24"),
        net("198.18.0.0/15"),
        net("198.51.100.0/24"),
        net("203.0.113.0/24"),
        net("224.0.0.0/4"),
        net("240.0.0.0/4"),
        net("255.255.255.255/32"),
        net("::/128"),
        net("::ffff:0:0/96"),
        net("100::/64"),
        net("2001:db8::/32"),
        net("fc00::/7"),
        net("fe80::/10"),
        net("ff00::/8"),
    ]
});

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
}
