use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::host::{parse_ip_literal, six_to_four_gateway};

/// Network-level IP range blocking policy.
///
/// Every check classifies the address a connection would really reach, so
/// IPv6 forms that embed an IPv4 address (`::ffff:a.b.c.d`, NAT64
/// `64:ff9b::/96`, IPv4-compatible `::a.b.c.d`) are judged as that IPv4
/// address, and a 6to4 address (`2002::/16`) is also judged as its embedded
/// gateway. Zone identifiers (`fe80::1%eth0`) are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Block private ranges: RFC 1918 (10/8, 172.16/12, 192.168/16), carrier-grade
    /// NAT (100.64/10) and IPv6 unique-local (fc00::/7). Default: true.
    #[serde(default = "default_true")]
    pub block_private: bool,
    /// Block link-local addresses (169.254/16, fe80::/10). Default: true.
    #[serde(default = "default_true")]
    pub block_link_local: bool,
    /// Block localhost: 127/8, `::1`, all of 0.0.0.0/8, `::`, and the names
    /// `localhost` and `*.localhost`. Default: true.
    #[serde(default = "default_true")]
    pub block_localhost: bool,
    /// Block cloud metadata endpoints (169.254.169.254, 168.63.129.16,
    /// 100.100.100.200, ...). Default: true.
    #[serde(default = "default_true")]
    pub block_metadata: bool,
}

fn default_true() -> bool {
    true
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            block_private: true,
            block_link_local: true,
            block_localhost: true,
            block_metadata: true,
        }
    }
}

impl NetworkPolicy {
    /// Check if a host (IP literal or hostname) is blocked by network policy.
    ///
    /// IP literals are parsed and classified by address range, so alternate
    /// spellings such as `[::ffff:127.0.0.1]` cannot slip past the policy and
    /// hostnames that merely look like a prefix (`fd-cdn.example`) are not
    /// mistaken for addresses.
    pub(super) fn is_ip_blocked(&self, host: &str) -> bool {
        (self.block_localhost && is_localhost(host))
            || (self.block_private && is_private_ip(host))
            || (self.block_link_local && is_link_local(host))
            || (self.block_metadata && is_metadata_ip(host))
    }
}

/// Every address a literal must be judged as: itself, plus the gateway
/// embedded in a 6to4 address. Empty for hostnames.
fn addresses(host: &str) -> Vec<IpAddr> {
    let Some(ip) = parse_ip_literal(host) else {
        return Vec::new();
    };
    let mut all = vec![ip];
    all.extend(six_to_four_gateway(ip).map(IpAddr::V4));
    all
}

fn normalized_hostname(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub(super) fn is_localhost(host: &str) -> bool {
    let addrs = addresses(host);
    if addrs.is_empty() {
        let name = normalized_hostname(host);
        return name == "localhost" || name.ends_with(".localhost");
    }
    addrs.into_iter().any(|ip| match ip {
        // 0.0.0.0/8 is "this network": connecting to it reaches the local host.
        IpAddr::V4(v4) => v4.is_loopback() || v4.octets()[0] == 0,
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    })
}

pub(super) fn is_private_ip(host: &str) -> bool {
    addresses(host).into_iter().any(|ip| match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            // RFC 1918 plus RFC 6598 carrier-grade NAT (100.64.0.0/10)
            v4.is_private() || (a == 100 && (64..=127).contains(&b))
        }
        // IPv6 unique local addresses: fc00::/7
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    })
}

pub(super) fn is_link_local(host: &str) -> bool {
    addresses(host).into_iter().any(|ip| match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    })
}

pub(super) fn is_metadata_ip(host: &str) -> bool {
    const METADATA_V4: [Ipv4Addr; 4] = [
        Ipv4Addr::new(169, 254, 169, 254), // AWS, GCP, Azure IMDS, OCI, DigitalOcean
        Ipv4Addr::new(169, 254, 170, 2),   // AWS ECS
        Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
        Ipv4Addr::new(168, 63, 129, 16),   // Azure WireServer / host agent
    ];
    // AWS IMDS over IPv6
    const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);

    let addrs = addresses(host);
    if addrs.is_empty() {
        return normalized_hostname(host).contains("metadata.google.internal");
    }
    addrs.into_iter().any(|ip| match ip {
        IpAddr::V4(v4) => METADATA_V4.contains(&v4),
        IpAddr::V6(v6) => v6 == METADATA_V6,
    })
}
