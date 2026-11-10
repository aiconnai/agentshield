use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Network-level IP range blocking policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Block private IP ranges (10.x, 172.16-31.x, 192.168.x). Default: true.
    #[serde(default = "default_true")]
    pub block_private: bool,
    /// Block link-local addresses (169.254.x). Default: true.
    #[serde(default = "default_true")]
    pub block_link_local: bool,
    /// Block localhost (127.x, ::1). Default: true.
    #[serde(default = "default_true")]
    pub block_localhost: bool,
    /// Block cloud metadata endpoints (169.254.169.254, etc.). Default: true.
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

/// Parse an IP literal, accepting URI brackets and folding IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`) to its IPv4 address. Returns `None` for hostnames.
fn parse_ip(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

fn normalized_hostname(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub(super) fn is_localhost(host: &str) -> bool {
    match parse_ip(host) {
        Some(ip) => ip.is_loopback() || ip.is_unspecified(),
        None => {
            let name = normalized_hostname(host);
            name == "localhost" || name.ends_with(".localhost")
        }
    }
}

pub(super) fn is_private_ip(host: &str) -> bool {
    match parse_ip(host) {
        Some(IpAddr::V4(v4)) => {
            let [a, b, ..] = v4.octets();
            // RFC 1918 plus RFC 6598 carrier-grade NAT (100.64.0.0/10)
            v4.is_private() || (a == 100 && (64..=127).contains(&b))
        }
        // IPv6 unique local addresses: fc00::/7
        Some(IpAddr::V6(v6)) => (v6.segments()[0] & 0xfe00) == 0xfc00,
        None => false,
    }
}

pub(super) fn is_link_local(host: &str) -> bool {
    match parse_ip(host) {
        Some(IpAddr::V4(v4)) => v4.is_link_local(),
        // fe80::/10
        Some(IpAddr::V6(v6)) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        None => false,
    }
}

pub(super) fn is_metadata_ip(host: &str) -> bool {
    const METADATA_V4: [Ipv4Addr; 3] = [
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
        Ipv4Addr::new(169, 254, 170, 2),   // AWS ECS
    ];
    match parse_ip(host) {
        Some(IpAddr::V4(v4)) => METADATA_V4.contains(&v4),
        // AWS IMDS over IPv6
        Some(IpAddr::V6(v6)) => v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
        None => normalized_hostname(host).contains("metadata.google.internal"),
    }
}
