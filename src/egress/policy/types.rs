use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::ShieldError;
use crate::ir::ScanTarget;

use super::domain::DomainPolicy;
use super::merge::{self, AuditPolicy, RateLimitPolicy};
use super::network::NetworkPolicy;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 1;

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
        self.domains.is_domain_allowed(domain)
    }

    /// Check if an IP address is blocked by network policy.
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.networks.is_ip_blocked(ip)
    }

    /// Get rate limit for a domain (requests per minute).
    ///
    /// Returns the per-domain override if one exists, otherwise the global default.
    pub fn rate_limit_for(&self, domain: &str) -> u32 {
        self.rate_limits.rate_limit_for(domain)
    }

    /// Build a starter egress policy by analyzing all `ScanTarget`s.
    pub fn from_scan_targets(targets: &[ScanTarget]) -> Self {
        super::infer::from_scan_targets(targets)
    }

    /// Merge with an operator override policy. The override can only restrict, never expand.
    pub fn merge_override(&self, operator: &EgressPolicy) -> EgressPolicy {
        merge::merge_override(self, operator)
    }

    /// Generate a starter policy TOML string for `agentshield init --egress`.
    pub fn starter_toml() -> &'static str {
        r#"# AgentShield Egress Policy
# See: https://github.com/aiconnai/agentshield

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
