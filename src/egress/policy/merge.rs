use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::domain::domain_matches;
use super::{DomainPolicy, EgressPolicy, NetworkPolicy};

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

impl RateLimitPolicy {
    /// Get rate limit for a domain (requests per minute).
    ///
    /// Returns the per-domain override if one exists, otherwise the global default.
    pub(super) fn rate_limit_for(&self, domain: &str) -> u32 {
        self.per_domain
            .get(domain)
            .copied()
            .unwrap_or(self.max_requests_per_minute)
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

/// Merge with an operator override policy. The override can only restrict, never expand.
///
/// Merge rules:
/// - `domains.allow` = intersection(base.allow, override.allow)
///   If override.allow is empty, base.allow is kept (empty means "no restriction").
///   If base.allow is empty (allow all), operator's allow list becomes the effective list.
/// - `domains.deny` = union(base.deny, override.deny)
/// - `networks`: if either policy blocks a range, it is blocked in the result
/// - `rate_limits.max_requests_per_minute` = min(self, override)
/// - `rate_limits.per_domain`: min rate per domain; missing entries inherit the global min
/// - `audit`: operator override wins (operator controls where logs go)
pub(super) fn merge_override(base: &EgressPolicy, operator: &EgressPolicy) -> EgressPolicy {
    // Allow list: intersection when both are non-empty; operator restricts further
    let allow = if operator.domains.allow.is_empty() {
        // Empty override allow = "no additional restriction on allow"
        base.domains.allow.clone()
    } else if base.domains.allow.is_empty() {
        // Self allows all; operator restricts to its list
        operator.domains.allow.clone()
    } else {
        // Both have allow lists: intersection (only domains in BOTH lists)
        base.domains
            .allow
            .iter()
            .filter(|d| {
                operator
                    .domains
                    .allow
                    .iter()
                    .any(|o| domain_matches(d, o) || domain_matches(o, d))
            })
            .cloned()
            .collect()
    };

    // Deny list: union (operator can only add more denials)
    let mut deny = base.domains.deny.clone();
    for d in &operator.domains.deny {
        if !deny.contains(d) {
            deny.push(d.clone());
        }
    }

    // Rate limits: take the minimum (more restrictive wins)
    let global_min = base
        .rate_limits
        .max_requests_per_minute
        .min(operator.rate_limits.max_requests_per_minute);

    let mut per_domain = base.rate_limits.per_domain.clone();
    for (domain, &op_rate) in &operator.rate_limits.per_domain {
        let entry = per_domain
            .entry(domain.clone())
            .or_insert(base.rate_limits.max_requests_per_minute);
        *entry = (*entry).min(op_rate);
    }

    EgressPolicy {
        schema_version: base.schema_version,
        domains: DomainPolicy { allow, deny },
        networks: NetworkPolicy {
            block_private: base.networks.block_private || operator.networks.block_private,
            block_link_local: base.networks.block_link_local || operator.networks.block_link_local,
            block_localhost: base.networks.block_localhost || operator.networks.block_localhost,
            block_metadata: base.networks.block_metadata || operator.networks.block_metadata,
        },
        rate_limits: RateLimitPolicy {
            max_requests_per_minute: global_min,
            per_domain,
        },
        audit: operator.audit.clone(),
    }
}
