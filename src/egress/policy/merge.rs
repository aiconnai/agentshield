use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::ShieldError;

use super::domain::domain_matches;
use super::host::{normalize_host, normalize_key};
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
    /// Reject per-domain keys that are not usable host names.
    pub(super) fn validate(&self) -> Result<(), ShieldError> {
        match self
            .per_domain
            .keys()
            .find(|key| normalize_host(key).is_none())
        {
            Some(key) => Err(ShieldError::Config(format!(
                "Egress policy: rate_limits.per_domain key {key:?} is invalid: \
                 it is not a valid host name (empty label or invalid internationalized name)"
            ))),
            None => Ok(()),
        }
    }

    /// Get rate limit for a domain (requests per minute).
    ///
    /// Returns the per-domain override if one exists, otherwise the global default.
    /// Keys match after host normalization (ASCII case, a trailing root dot,
    /// Unicode versus punycode spelling); when several keys
    /// name the same host, the stricter rate applies.
    pub(super) fn rate_limit_for(&self, domain: &str) -> u32 {
        let domain = normalize_key(domain);
        self.per_domain
            .iter()
            .filter(|(key, _)| normalize_key(key) == domain)
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
    let mut deny = merge_deny(&base.domains.deny, &operator.domains.deny);
    let allow = merge_allow(&base.domains.allow, &operator.domains.allow, &mut deny);

    EgressPolicy {
        schema_version: base.schema_version,
        domains: DomainPolicy { allow, deny },
        networks: merge_networks(&base.networks, &operator.networks),
        rate_limits: merge_rate_limits(&base.rate_limits, &operator.rate_limits),
        audit: operator.audit.clone(),
    }
}

/// Deny list: union (operator can only add more denials).
fn merge_deny(base: &[String], operator: &[String]) -> Vec<String> {
    let mut deny = base.to_vec();
    for pattern in operator {
        if !deny.contains(pattern) {
            deny.push(pattern.clone());
        }
    }
    deny
}

/// Allow list: intersection when both are non-empty; operator restricts further.
///
/// An empty intersection is recorded as a deny-all rule pushed onto `deny`,
/// because an empty allow list would otherwise mean "allow everything".
fn merge_allow(base: &[String], operator: &[String], deny: &mut Vec<String>) -> Vec<String> {
    if operator.is_empty() {
        // Empty override allow = "no additional restriction on allow"
        return base.to_vec();
    }
    if base.is_empty() {
        // Base allows all; operator restricts to its list
        return operator.to_vec();
    }
    let intersection = intersect_allow(base, operator);
    if intersection.is_empty() && !deny.iter().any(|d| d == DENY_ALL_PATTERN) {
        // Disjoint lists mean nothing is allowed. An empty allow list
        // means "allow all", so the empty intersection must be expressed
        // as an explicit deny-all rather than silently widening.
        deny.push(DENY_ALL_PATTERN.to_string());
    }
    intersection
}

/// Both sides have allow lists: keep, for every overlapping pair, the
/// NARROWER pattern so a broad glob never survives a narrow entry.
fn intersect_allow(base: &[String], operator: &[String]) -> Vec<String> {
    let mut intersection: Vec<String> = Vec::new();
    for b in base {
        for o in operator {
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
    intersection
}

/// A range stays blocked if either policy blocks it.
fn merge_networks(base: &NetworkPolicy, operator: &NetworkPolicy) -> NetworkPolicy {
    NetworkPolicy {
        block_private: base.block_private || operator.block_private,
        block_link_local: base.block_link_local || operator.block_link_local,
        block_localhost: base.block_localhost || operator.block_localhost,
        block_metadata: base.block_metadata || operator.block_metadata,
    }
}

/// Rate limits: the more restrictive wins (`0` = unlimited), globally and for
/// every domain either policy names.
fn merge_rate_limits(base: &RateLimitPolicy, operator: &RateLimitPolicy) -> RateLimitPolicy {
    let domains: std::collections::BTreeSet<String> = base
        .per_domain
        .keys()
        .chain(operator.per_domain.keys())
        .map(|domain| normalize_key(domain))
        .collect();
    let per_domain: HashMap<String, u32> = domains
        .into_iter()
        .map(|domain| {
            let rate = stricter_rate(
                base.rate_limit_for(&domain),
                operator.rate_limit_for(&domain),
            );
            (domain, rate)
        })
        .collect();

    RateLimitPolicy {
        max_requests_per_minute: stricter_rate(
            base.max_requests_per_minute,
            operator.max_requests_per_minute,
        ),
        per_domain,
    }
}
