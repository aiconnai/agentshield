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

/// Canonical form of a host name or pattern body, used for every comparison.
///
/// - IP literals become the canonical text of [`parse_ip_literal`].
/// - DNS names are mapped through IDNA (UTS #46, non-strict so names such as
///   `_dmarc.example.com` survive), which lowercases ASCII and turns Unicode
///   labels into punycode: `Bücher.example` and `xn--bcher-kva.example`
///   normalize to the same string.
/// - One trailing root dot is dropped; surrounding whitespace is trimmed.
///
/// Returns `None` when the input has no usable form: empty, an empty label
/// (`a..b`, `.`), or invalid IDNA (for example a malformed `xn--` label).
/// Callers must treat `None` as "does not match" for allow rules and as
/// "blocked" for requests, so unparseable input fails closed.
pub(crate) fn normalize_host(host: &str) -> Option<String> {
    let trimmed = host.trim();
    if let Some(ip) = parse_ip_literal(trimmed) {
        return Some(ip.to_string());
    }
    let ascii = idna::domain_to_ascii(trimmed).ok()?;
    // IDNA mapping can turn lookalike digits into an IP literal.
    if let Some(ip) = parse_ip_literal(&ascii) {
        return Some(ip.to_string());
    }
    let name = ascii.strip_suffix('.').unwrap_or(&ascii);
    if name.is_empty() || name.split('.').any(str::is_empty) {
        return None;
    }
    Some(name.to_string())
}

/// [`normalize_host`] with a lossy fallback, for keys that must never be
/// dropped (rate-limit buckets and merged rate maps).
pub(crate) fn normalize_key(host: &str) -> String {
    normalize_host(host).unwrap_or_else(|| host.trim().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_trims_and_drops_one_root_dot() {
        assert_eq!(
            normalize_host("  API.GitHub.com. "),
            Some("api.github.com".into())
        );
        assert_eq!(normalize_host("a..b"), None);
        assert_eq!(normalize_host("example.com.."), None);
        assert_eq!(normalize_host("."), None);
        assert_eq!(normalize_host(""), None);
    }

    #[test]
    fn normalize_unicode_and_punycode_agree() {
        let unicode = normalize_host("bücher.example");
        assert_eq!(unicode, Some("xn--bcher-kva.example".into()));
        assert_eq!(normalize_host("XN--BCHER-KVA.example"), unicode);
        assert_eq!(normalize_host("BÜCHER.example."), unicode);
        // Ideographic full stop is a label separator under UTS #46.
        assert_eq!(normalize_host("bücher。example"), unicode);
    }

    #[test]
    fn normalize_rejects_invalid_idna() {
        assert_eq!(normalize_host("xn--.example"), None);
        assert_eq!(normalize_host("xn--a-.example"), None);
    }

    #[test]
    fn normalize_keeps_non_hostname_ascii_names() {
        assert_eq!(
            normalize_host("_dmarc.example.com"),
            Some("_dmarc.example.com".into())
        );
        assert_eq!(
            normalize_host("*.example.com"),
            Some("*.example.com".into())
        );
    }

    #[test]
    fn normalize_ip_literals_to_canonical_text() {
        assert_eq!(
            normalize_host("[::FFFF:127.0.0.1]"),
            Some("127.0.0.1".into())
        );
        assert_eq!(normalize_host("64:ff9b::7f00:1"), Some("127.0.0.1".into()));
        assert_eq!(
            normalize_host("[2001:DB8:0:0::1]"),
            Some("2001:db8::1".into())
        );
        // Fullwidth digits map to ASCII digits under UTS #46.
        assert_eq!(normalize_host("１２７.０.０.１"), Some("127.0.0.1".into()));
    }

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
