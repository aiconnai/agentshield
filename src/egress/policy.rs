//! Egress policy schema and validation.
//!
//! Parses `agentshield.egress.toml` files that define which domains,
//! IPs, and rate limits are enforced by the `wrap` command proxy.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::ShieldError;

const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Top-level egress policy loaded from `agentshield.egress.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// Schema version for forward compatibility checks.
    pub schema_version: u32,
    /// Domain allow/deny rules.
    pub domains: DomainPolicy,
    /// Network-level IP blocking rules.
    #[serde(default)]
    pub networks: NetworkPolicy,
    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limits: RateLimitPolicy,
    /// Audit logging configuration.
    #[serde(default)]
    pub audit: AuditPolicy,
}

/// Domain-level allow/deny policy using glob-style patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPolicy {
    /// Allowed domain patterns (glob-style: `"*.example.com"`, `"api.github.com"`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicitly denied domain patterns (takes precedence over allow).
    #[serde(default)]
    pub deny: Vec<String>,
}

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

/// Rate limiting configuration for outbound requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Maximum requests per minute per domain. 0 = unlimited.
    #[serde(default = "default_rate_limit")]
    pub max_requests_per_minute: u32,
    /// Per-domain overrides (domain string -> requests per minute).
    #[serde(default)]
    pub per_domain: HashMap<String, u32>,
}

fn default_rate_limit() -> u32 {
    60
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_requests_per_minute: default_rate_limit(),
            per_domain: HashMap::new(),
        }
    }
}

/// Audit logging configuration for egress events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// Path to write audit log.
    #[serde(default)]
    pub log_path: Option<PathBuf>,
    /// Log format: `"json"` or `"text"`.
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Log allowed requests too (not just blocked). Default: false.
    #[serde(default)]
    pub log_allowed: bool,
}

fn default_log_format() -> String {
    "json".to_string()
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            log_path: None,
            log_format: default_log_format(),
            log_allowed: false,
        }
    }
}

impl EgressPolicy {
    /// Load an egress policy from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ShieldError> {
        let content = std::fs::read_to_string(path).map_err(ShieldError::Io)?;
        let policy: Self = toml::from_str(&content)?;
        if policy.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(ShieldError::Config(format!(
                "Egress policy schema version {} is newer than supported version {}",
                policy.schema_version, CURRENT_SCHEMA_VERSION
            )));
        }
        Ok(policy)
    }

    /// Save an egress policy to a TOML file.
    pub fn save(&self, path: &Path) -> Result<(), ShieldError> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content).map_err(ShieldError::Io)?;
        Ok(())
    }

    /// Check if a domain is allowed by this policy.
    ///
    /// Deny rules take precedence over allow rules. If the allow list is
    /// empty, all domains not explicitly denied are allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        // Deny takes precedence
        if self
            .domains
            .deny
            .iter()
            .any(|pattern| domain_matches(domain, pattern))
        {
            return false;
        }
        // If allow list is empty, allow all (that aren't denied)
        if self.domains.allow.is_empty() {
            return true;
        }
        // Must match at least one allow pattern
        self.domains
            .allow
            .iter()
            .any(|pattern| domain_matches(domain, pattern))
    }

    /// Check if an IP address is blocked by network policy.
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        if self.networks.block_localhost && is_localhost(ip) {
            return true;
        }
        if self.networks.block_private && is_private_ip(ip) {
            return true;
        }
        if self.networks.block_link_local && is_link_local(ip) {
            return true;
        }
        if self.networks.block_metadata && is_metadata_ip(ip) {
            return true;
        }
        false
    }

    /// Get rate limit for a domain (requests per minute).
    ///
    /// Returns the per-domain override if one exists, otherwise the global default.
    pub fn rate_limit_for(&self, domain: &str) -> u32 {
        self.rate_limits
            .per_domain
            .get(domain)
            .copied()
            .unwrap_or(self.rate_limits.max_requests_per_minute)
    }

    /// Generate a starter policy TOML string for `agentshield init --egress`.
    pub fn starter_toml() -> &'static str {
        r#"# AgentShield Egress Policy
# See: https://github.com/limaronaldo/agentshield

schema_version = 1

[domains]
# Allowed domain patterns (glob-style)
allow = ["*.example.com", "api.github.com"]
# Explicitly denied (takes precedence over allow)
deny = []

[networks]
block_private = true      # 10.x, 172.16-31.x, 192.168.x
block_link_local = true   # 169.254.x
block_localhost = true     # 127.x, ::1
block_metadata = true     # 169.254.169.254, metadata.google.internal

[rate_limits]
max_requests_per_minute = 60

[audit]
# log_path = "agentshield-audit.jsonl"
log_format = "json"
log_allowed = false
"#
    }
}

/// Simple glob matching for domain patterns.
///
/// Supports `*.example.com` (matches `sub.example.com` and `example.com`)
/// and exact matches like `api.github.com`.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix('*') {
        // "*.example.com" matches "sub.example.com" and "example.com"
        domain.ends_with(suffix) || domain == &suffix[1..]
    } else {
        domain == pattern
    }
}

fn is_localhost(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "::1" || ip == "localhost"
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || (ip.starts_with("172.") && is_172_private(ip))
        || ip.starts_with("192.168.")
        || ip.starts_with("fd") // IPv6 ULA
}

fn is_172_private(ip: &str) -> bool {
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

fn is_link_local(ip: &str) -> bool {
    ip.starts_with("169.254.") || ip.starts_with("fe80:")
}

fn is_metadata_ip(ip: &str) -> bool {
    ip == "169.254.169.254"
        || ip.contains("metadata.google.internal")
        || ip == "100.100.100.200" // Alibaba Cloud
        || ip == "169.254.170.2" // AWS ECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_policy() -> EgressPolicy {
        EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec!["*.example.com".into(), "api.github.com".into()],
                deny: vec!["evil.example.com".into()],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy {
                max_requests_per_minute: 60,
                per_domain: {
                    let mut m = HashMap::new();
                    m.insert("api.github.com".into(), 30);
                    m
                },
            },
            audit: AuditPolicy::default(),
        }
    }

    #[test]
    fn test_load_and_save_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("egress.toml");

        let original = sample_policy();
        original.save(&path).unwrap();

        let loaded = EgressPolicy::load(&path).unwrap();

        assert_eq!(loaded.schema_version, original.schema_version);
        assert_eq!(loaded.domains.allow, original.domains.allow);
        assert_eq!(loaded.domains.deny, original.domains.deny);
        assert_eq!(
            loaded.networks.block_private,
            original.networks.block_private
        );
        assert_eq!(
            loaded.networks.block_localhost,
            original.networks.block_localhost
        );
        assert_eq!(
            loaded.networks.block_link_local,
            original.networks.block_link_local
        );
        assert_eq!(
            loaded.networks.block_metadata,
            original.networks.block_metadata
        );
        assert_eq!(
            loaded.rate_limits.max_requests_per_minute,
            original.rate_limits.max_requests_per_minute
        );
        assert_eq!(
            loaded.rate_limits.per_domain,
            original.rate_limits.per_domain
        );
        assert_eq!(loaded.audit.log_format, original.audit.log_format);
        assert_eq!(loaded.audit.log_allowed, original.audit.log_allowed);
        assert_eq!(loaded.audit.log_path, original.audit.log_path);
    }

    #[test]
    fn test_domain_allowed() {
        let policy = sample_policy();

        // Exact match
        assert!(policy.is_domain_allowed("api.github.com"));
        // Glob match
        assert!(policy.is_domain_allowed("sub.example.com"));
        // Base domain matches *.example.com
        assert!(policy.is_domain_allowed("example.com"));
        // Not in allow list
        assert!(!policy.is_domain_allowed("random.org"));
    }

    #[test]
    fn test_domain_denied_takes_precedence() {
        let policy = sample_policy();

        // evil.example.com matches *.example.com (allow) but also deny list
        assert!(
            !policy.is_domain_allowed("evil.example.com"),
            "deny should take precedence over allow"
        );
    }

    #[test]
    fn test_empty_allow_list_allows_all() {
        let policy = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![],
                deny: vec!["blocked.com".into()],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        };

        assert!(policy.is_domain_allowed("anything.com"));
        assert!(policy.is_domain_allowed("whatever.org"));
        assert!(
            !policy.is_domain_allowed("blocked.com"),
            "deny should still block even with empty allow"
        );
    }

    #[test]
    fn test_ip_blocking() {
        let policy = sample_policy();

        // Localhost
        assert!(policy.is_ip_blocked("127.0.0.1"));
        assert!(policy.is_ip_blocked("127.0.0.2"));
        assert!(policy.is_ip_blocked("::1"));
        assert!(policy.is_ip_blocked("localhost"));

        // Private ranges
        assert!(policy.is_ip_blocked("10.0.0.1"));
        assert!(policy.is_ip_blocked("172.16.0.1"));
        assert!(policy.is_ip_blocked("172.31.255.255"));
        assert!(policy.is_ip_blocked("192.168.1.1"));

        // Not private (172.15.x is outside the private range)
        assert!(!policy.is_ip_blocked("172.15.0.1"));
        assert!(!policy.is_ip_blocked("172.32.0.1"));

        // Link-local
        assert!(policy.is_ip_blocked("169.254.1.1"));
        assert!(policy.is_ip_blocked("fe80::1"));

        // Metadata endpoints
        assert!(policy.is_ip_blocked("169.254.169.254"));
        assert!(policy.is_ip_blocked("metadata.google.internal"));
        assert!(policy.is_ip_blocked("100.100.100.200"));
        assert!(policy.is_ip_blocked("169.254.170.2"));

        // Public IP should not be blocked
        assert!(!policy.is_ip_blocked("8.8.8.8"));
        assert!(!policy.is_ip_blocked("1.1.1.1"));
    }

    #[test]
    fn test_rate_limit_per_domain() {
        let policy = sample_policy();
        assert_eq!(policy.rate_limit_for("api.github.com"), 30);
    }

    #[test]
    fn test_rate_limit_default() {
        let policy = sample_policy();
        assert_eq!(policy.rate_limit_for("unknown.com"), 60);
    }

    #[test]
    fn test_future_schema_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("future.toml");

        let content = r#"
schema_version = 99

[domains]
allow = []
deny = []
"#;
        std::fs::write(&path, content).unwrap();

        let result = EgressPolicy::load(&path);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("99") && err_msg.contains("newer"),
            "Error should mention unsupported schema version, got: {err_msg}"
        );
    }

    #[test]
    fn test_starter_toml_parses() {
        let toml_str = EgressPolicy::starter_toml();
        let policy: EgressPolicy =
            toml::from_str(toml_str).expect("starter_toml() should produce valid TOML");
        assert_eq!(policy.schema_version, 1);
        assert!(!policy.domains.allow.is_empty());
        assert!(policy.networks.block_private);
        assert!(policy.networks.block_metadata);
        assert_eq!(policy.rate_limits.max_requests_per_minute, 60);
        assert_eq!(policy.audit.log_format, "json");
    }
}
