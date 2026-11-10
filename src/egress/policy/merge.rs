use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::domain::{domain_matches, normalize_domain};
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
    /// Keys match ignoring ASCII case and a trailing root dot; when several keys
    /// name the same host, the stricter rate applies.
    pub(super) fn rate_limit_for(&self, domain: &str) -> u32 {
        let domain = normalize_domain(domain);
        self.per_domain
            .iter()
            .filter(|(key, _)| normalize_domain(key) == domain)
            .map(|(_, &rate)| rate)
            .reduce(stricter_rate)
            .unwrap_or(self.max_requests_per_minute)
    }
}

/// The more restrictive of two rate limits, where `0` means "unlimited".
fn stricter_rate(a: u32, b: u32) -> u32 {
    match (a, b) {
        (0, other) | (other, 0) => other,
        (a, b) => a.min(b),
    }
}

/// Pattern that matches every host; used to express "deny all".
const DENY_ALL_PATTERN: &str = "*";

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
/// - `domains.allow` = intersection(base.allow, override.allow), keeping the narrower
///   pattern of each overlapping pair. Disjoint lists add a deny-all (`*`) rule.
///   If override.allow is empty, base.allow is kept (empty means "no restriction").
///   If base.allow is empty (allow all), operator's allow list becomes the effective list.
/// - `domains.deny` = union(base.deny, override.deny)
/// - `networks`: if either policy blocks a range, it is blocked in the result
/// - `rate_limits.max_requests_per_minute` = stricter of the two (`0` means unlimited)
/// - `rate_limits.per_domain`: stricter effective rate of both policies per domain
/// - `audit`: operator override wins (operator controls where logs go)
pub(super) fn merge_override(base: &EgressPolicy, operator: &EgressPolicy) -> EgressPolicy {
    // Deny list: union (operator can only add more denials)
    let mut deny = base.domains.deny.clone();
    for d in &operator.domains.deny {
        if !deny.contains(d) {
            deny.push(d.clone());
        }
    }

    // Allow list: intersection when both are non-empty; operator restricts further
    let allow = if operator.domains.allow.is_empty() {
        // Empty override allow = "no additional restriction on allow"
        base.domains.allow.clone()
    } else if base.domains.allow.is_empty() {
        // Self allows all; operator restricts to its list
        operator.domains.allow.clone()
    } else {
        // Both have allow lists: keep, for every overlapping pair, the
        // NARROWER pattern so a broad glob never survives a narrow entry.
        let mut intersection: Vec<String> = Vec::new();
        for b in &base.domains.allow {
            for o in &operator.domains.allow {
                let narrower = if domain_matches(b, o) {
                    b
                } else if domain_matches(o, b) {
                    o
                } else {
                    continue;
                };
                if !intersection.contains(narrower) {
                    intersection.push(narrower.clone());
                }
            }
        }
        if intersection.is_empty() && !deny.iter().any(|d| d == DENY_ALL_PATTERN) {
            // Disjoint lists mean nothing is allowed. An empty allow list
            // means "allow all", so the empty intersection must be expressed
            // as an explicit deny-all rather than silently widening.
            deny.push(DENY_ALL_PATTERN.to_string());
        }
        intersection
    };

    // Rate limits: the more restrictive wins (0 = unlimited)
    let global_min = stricter_rate(
        base.rate_limits.max_requests_per_minute,
        operator.rate_limits.max_requests_per_minute,
    );

    let domains: std::collections::BTreeSet<String> = base
        .rate_limits
        .per_domain
        .keys()
        .chain(operator.rate_limits.per_domain.keys())
        .map(|domain| normalize_domain(domain))
        .collect();
    let per_domain: HashMap<String, u32> = domains
        .into_iter()
        .map(|domain| {
            let rate = stricter_rate(
                base.rate_limits.rate_limit_for(&domain),
                operator.rate_limits.rate_limit_for(&domain),
            );
            (domain, rate)
        })
        .collect();

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
