//! Canonical host forms shared by every egress check.
//!
//! Domain matching, network classification, rate-limit keys and the proxy all
//! need the same answer to "which host is this?". Keeping the rules in one
//! place means a respelling that is understood by one layer cannot slip past
//! another.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse an IP literal into the address a connection would really reach.
///
/// Accepts URI brackets (`[::1]`) and IPv6 zone identifiers, raw or
/// percent-encoded (`fe80::1%eth0`, `[fe80::1%25eth0]`). The zone is dropped:
/// a scoped address is classified by its address alone.
///
/// IPv6 forms that embed an IPv4 address are folded to that IPv4 address so
/// they are classified exactly like it:
///
/// - IPv4-mapped `::ffff:a.b.c.d`
/// - NAT64 `64:ff9b::/96` (RFC 6052)
/// - IPv4-compatible `::a.b.c.d` (deprecated, but still accepted by stacks)
///
/// `::` and `::1` keep their IPv6 meaning. 6to4 (`2002::/16`) is deliberately
/// not folded here, because the embedded address names a gateway rather than
/// the destination; see [`six_to_four_gateway`].
///
/// Returns `None` for anything that is not an IP literal.
pub(crate) fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let ip = match host.split_once('%') {
        // A zone identifier only exists on IPv6 addresses.
        Some((address, _zone)) => IpAddr::V6(address.parse::<Ipv6Addr>().ok()?),
        None => host.parse::<IpAddr>().ok()?,
    };
    Some(match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    })
}

/// The IPv4 address a mapped, NAT64 or IPv4-compatible IPv6 address stands for.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = v6.segments();
    let (high, low) = (segments[6], segments[7]);
    let v4 = Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8);
    match segments[..6] {
        [0, 0, 0, 0, 0, 0xffff] => Some(v4),
        [0x64, 0xff9b, 0, 0, 0, 0] => Some(v4),
        // `::` and `::1` are the unspecified and loopback addresses.
        [0, 0, 0, 0, 0, 0] if high != 0 || low > 1 => Some(v4),
        _ => None,
    }
}

/// The IPv4 gateway embedded in a 6to4 address (`2002:WWXX:YYZZ::/48`).
///
/// 6to4 traffic is tunnelled to that gateway, so an address whose gateway is
/// internal is treated as internal too. The reverse does not hold, so this is
/// a second classification input, not a canonical form.
pub(crate) fn six_to_four_gateway(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else { return None };
    let segments = v6.segments();
    (segments[0] == 0x2002).then(|| {
        let (high, low) = (segments[1], segments[2]);
        Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_is_dropped_but_only_from_ipv6() {
        assert_eq!(parse_ip_literal("fe80::1%eth0"), "fe80::1".parse().ok());
        assert_eq!(parse_ip_literal("[fe80::1%25eth0]"), "fe80::1".parse().ok());
        assert_eq!(parse_ip_literal("127.0.0.1%eth0"), None);
    }

    #[test]
    fn embedded_forms_fold_to_ipv4() {
        let loopback: Option<IpAddr> = "127.0.0.1".parse().ok();
        assert_eq!(parse_ip_literal("[::FFFF:127.0.0.1]"), loopback);
        assert_eq!(parse_ip_literal("64:ff9b::7f00:1"), loopback);
        assert_eq!(parse_ip_literal("::127.0.0.1"), loopback);
        assert_eq!(parse_ip_literal("::1"), "::1".parse().ok());
        assert_eq!(parse_ip_literal("::"), "::".parse().ok());
    }

    #[test]
    fn six_to_four_gateway_is_exposed_but_not_folded() {
        let ip = parse_ip_literal("2002:7f00:1::").unwrap();
        assert!(matches!(ip, IpAddr::V6(_)));
        assert_eq!(six_to_four_gateway(ip), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(six_to_four_gateway("::1".parse().unwrap()), None);
    }
}
