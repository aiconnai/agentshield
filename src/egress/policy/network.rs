use serde::{Deserialize, Serialize};

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
    /// Check if an IP address is blocked by network policy.
    pub(crate) fn is_ip_blocked(&self, ip: &str) -> bool {
        if self.block_localhost && is_localhost(ip) {
            return true;
        }
        if self.block_private && is_private_ip(ip) {
            return true;
        }
        if self.block_link_local && is_link_local(ip) {
            return true;
        }
        if self.block_metadata && is_metadata_ip(ip) {
            return true;
        }
        false
    }
}

pub(crate) fn is_localhost(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "::1" || ip == "localhost"
}

pub(crate) fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || (ip.starts_with("172.") && is_172_private(ip))
        || ip.starts_with("192.168.")
        || ip.starts_with("fd") // IPv6 ULA
}

pub(crate) fn is_172_private(ip: &str) -> bool {
    if let Some(second_octet) = ip
        .strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
    {
        if let Ok(n) = second_octet.parse::<u8>() {
            return (16..=31).contains(&n);
        }
    }
    false
}

pub(crate) fn is_link_local(ip: &str) -> bool {
    ip.starts_with("169.254.") || ip.starts_with("fe80:")
}

pub(crate) fn is_metadata_ip(ip: &str) -> bool {
    ip == "169.254.169.254"
        || ip.contains("metadata.google.internal")
        || ip == "100.100.100.200" // Alibaba Cloud
        || ip == "169.254.170.2" // AWS ECS
}
