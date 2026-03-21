//! Egress policy schema and validation.
//!
//! Parses `agentshield.egress.toml` files that define which domains,
//! IPs, and rate limits are enforced by the `wrap` command proxy.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::ShieldError;
use crate::ir::tool_surface::PermissionType;
use crate::ir::{ArgumentSource, ScanTarget};

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

    /// Build a starter egress policy by analyzing all `ScanTarget`s.
    ///
    /// Extracts domains from:
    /// - Literal URL arguments in `NetworkOperation` entries
    /// - `NetworkAccess` declared permissions with a scope/target URL or domain
    ///
    /// The resulting policy allows all discovered domains and uses safe defaults
    /// for network-level blocking and rate limiting.
    pub fn from_scan_targets(targets: &[ScanTarget]) -> Self {
        let mut domains = std::collections::HashSet::new();

        for target in targets {
            // Extract domains from network operations with literal URLs
            for net_op in &target.execution.network_operations {
                if let ArgumentSource::Literal(ref url) = net_op.url_arg {
                    if let Some(domain) = extract_domain(url) {
                        domains.insert(domain);
                    }
                }
            }

            // Extract domains from tool declared permissions (NetworkAccess)
            for tool in &target.tools {
                for perm in &tool.declared_permissions {
                    if matches!(perm.permission_type, PermissionType::NetworkAccess) {
                        if let Some(ref scope) = perm.target {
                            if let Some(domain) = extract_domain(scope) {
                                domains.insert(domain);
                            }
                        }
                    }
                }
            }
        }

        let mut allow: Vec<String> = domains.into_iter().collect();
        allow.sort();

        EgressPolicy {
            schema_version: CURRENT_SCHEMA_VERSION,
            domains: DomainPolicy {
                allow,
                deny: vec![],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        }
    }

    /// Merge with an operator override policy. The override can only restrict, never expand.
    ///
    /// Merge rules:
    /// - `domains.allow` = intersection(self.allow, override.allow)
    ///   If override.allow is empty, self.allow is kept (empty means "no restriction").
    ///   If self.allow is empty (allow all), operator's allow list becomes the effective list.
    /// - `domains.deny` = union(self.deny, override.deny)
    /// - `networks`: if either policy blocks a range, it is blocked in the result
    /// - `rate_limits.max_requests_per_minute` = min(self, override)
    /// - `rate_limits.per_domain`: min rate per domain; missing entries inherit the global min
    /// - `audit`: operator override wins (operator controls where logs go)
    pub fn merge_override(&self, operator: &EgressPolicy) -> EgressPolicy {
        // Allow list: intersection when both are non-empty; operator restricts further
        let allow = if operator.domains.allow.is_empty() {
            // Empty override allow = "no additional restriction on allow"
            self.domains.allow.clone()
        } else if self.domains.allow.is_empty() {
            // Self allows all; operator restricts to its list
            operator.domains.allow.clone()
        } else {
            // Both have allow lists: intersection (only domains in BOTH lists)
            self.domains
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
        let mut deny = self.domains.deny.clone();
        for d in &operator.domains.deny {
            if !deny.contains(d) {
                deny.push(d.clone());
            }
        }

        // Rate limits: take the minimum (more restrictive wins)
        let global_min = self
            .rate_limits
            .max_requests_per_minute
            .min(operator.rate_limits.max_requests_per_minute);

        let mut per_domain = self.rate_limits.per_domain.clone();
        for (domain, &op_rate) in &operator.rate_limits.per_domain {
            let entry = per_domain
                .entry(domain.clone())
                .or_insert(self.rate_limits.max_requests_per_minute);
            *entry = (*entry).min(op_rate);
        }

        EgressPolicy {
            schema_version: self.schema_version,
            domains: DomainPolicy { allow, deny },
            networks: NetworkPolicy {
                block_private: self.networks.block_private || operator.networks.block_private,
                block_link_local: self.networks.block_link_local
                    || operator.networks.block_link_local,
                block_localhost: self.networks.block_localhost || operator.networks.block_localhost,
                block_metadata: self.networks.block_metadata || operator.networks.block_metadata,
            },
            rate_limits: RateLimitPolicy {
                max_requests_per_minute: global_min,
                per_domain,
            },
            audit: operator.audit.clone(),
        }
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

/// Extract the hostname from a URL string or bare domain.
///
/// Handles `http://`, `https://` URLs (strips scheme, path, port) and bare
/// domain names (e.g., `"api.example.com"`). Returns `None` for strings that
/// cannot be mapped to a useful hostname (e.g., paths, IP-like without dot).
pub fn extract_domain(url_or_domain: &str) -> Option<String> {
    // Try stripping http:// or https://
    let rest = if let Some(r) = url_or_domain.strip_prefix("https://") {
        r
    } else if let Some(r) = url_or_domain.strip_prefix("http://") {
        r
    } else {
        // Bare domain: must contain a dot and no slashes
        if url_or_domain.contains('.') && !url_or_domain.contains('/') {
            return Some(url_or_domain.to_string());
        }
        return None;
    };

    // Take the host portion (before first '/')
    let host = rest.split('/').next()?;
    // Strip port if present
    let host = host.split(':').next()?;

    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
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

    // ── from_scan_targets tests ─────────────────────────────────────────────

    #[test]
    fn test_extract_domain_from_url() {
        // Full URLs with scheme
        assert_eq!(
            extract_domain("https://api.example.com/v1/items"),
            Some("api.example.com".into())
        );
        assert_eq!(
            extract_domain("http://api.example.com:8080/path"),
            Some("api.example.com".into())
        );
        assert_eq!(
            extract_domain("https://api.github.com"),
            Some("api.github.com".into())
        );
        // Bare domain
        assert_eq!(
            extract_domain("api.example.com"),
            Some("api.example.com".into())
        );
        // No dot, no scheme → None
        assert_eq!(extract_domain("localhost"), None);
        // Path without scheme → None (has slash)
        assert_eq!(extract_domain("/some/path"), None);
        // Empty string → None
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn test_from_scan_targets_extracts_domains() {
        use crate::ir::execution_surface::{ExecutionSurface, NetworkOperation};
        use crate::ir::tool_surface::{DeclaredPermission, PermissionType, ToolSurface};
        use crate::ir::{
            ArgumentSource, DataSurface, DependencySurface, Framework, ProvenanceSurface,
            ScanTarget, SourceLocation,
        };
        use std::path::PathBuf;

        let make_loc = || SourceLocation {
            file: PathBuf::from("server.py"),
            line: 1,
            column: 0,
            end_line: None,
            end_column: None,
        };

        let target = ScanTarget {
            name: "test-server".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/tmp/test"),
            tools: vec![ToolSurface {
                name: "fetch_data".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                declared_permissions: vec![DeclaredPermission {
                    permission_type: PermissionType::NetworkAccess,
                    target: Some("https://api.stripe.com/v1".into()),
                    description: None,
                }],
                defined_at: None,
            }],
            execution: ExecutionSurface {
                network_operations: vec![
                    NetworkOperation {
                        function: "requests.get".into(),
                        url_arg: ArgumentSource::Literal("https://api.openai.com/v1/chat".into()),
                        method: Some("GET".into()),
                        sends_data: false,
                        location: make_loc(),
                    },
                    NetworkOperation {
                        function: "requests.post".into(),
                        // Non-literal: should be skipped
                        url_arg: ArgumentSource::Parameter { name: "url".into() },
                        method: Some("POST".into()),
                        sends_data: true,
                        location: make_loc(),
                    },
                ],
                ..ExecutionSurface::default()
            },
            data: DataSurface::default(),
            dependencies: DependencySurface::default(),
            provenance: ProvenanceSurface::default(),
            source_files: vec![],
        };

        let policy = EgressPolicy::from_scan_targets(&[target]);

        // schema_version must be 1
        assert_eq!(policy.schema_version, 1);
        // deny list must be empty (starter policy)
        assert!(policy.domains.deny.is_empty());
        // allow list must contain both discovered domains, sorted
        assert!(
            policy.domains.allow.contains(&"api.openai.com".to_string()),
            "Expected api.openai.com in allow list, got: {:?}",
            policy.domains.allow
        );
        assert!(
            policy.domains.allow.contains(&"api.stripe.com".to_string()),
            "Expected api.stripe.com in allow list, got: {:?}",
            policy.domains.allow
        );
        // Allow list should be sorted
        assert_eq!(
            policy.domains.allow,
            {
                let mut sorted = policy.domains.allow.clone();
                sorted.sort();
                sorted
            },
            "Allow list should be sorted"
        );
        // Network defaults must be secure
        assert!(policy.networks.block_private);
        assert!(policy.networks.block_localhost);
        assert!(policy.networks.block_link_local);
        assert!(policy.networks.block_metadata);
        // Rate limit default
        assert_eq!(policy.rate_limits.max_requests_per_minute, 60);
    }

    // ── merge_override tests ─────────────────────────────────────────────────

    fn base_policy() -> EgressPolicy {
        EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![
                    "api.example.com".into(),
                    "api.github.com".into(),
                    "api.openai.com".into(),
                ],
                deny: vec!["evil.com".into()],
            },
            networks: NetworkPolicy {
                block_private: false,
                block_link_local: true,
                block_localhost: true,
                block_metadata: false,
            },
            rate_limits: RateLimitPolicy {
                max_requests_per_minute: 60,
                per_domain: {
                    let mut m = HashMap::new();
                    m.insert("api.openai.com".into(), 20);
                    m
                },
            },
            audit: AuditPolicy {
                log_path: Some(PathBuf::from("/tmp/base-audit.jsonl")),
                log_format: "json".into(),
                log_allowed: false,
            },
        }
    }

    #[test]
    fn test_merge_deny_union() {
        let base = base_policy();
        let operator = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![],
                deny: vec!["extra-bad.com".into()],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        };

        let merged = base.merge_override(&operator);

        assert!(
            merged.domains.deny.contains(&"evil.com".to_string()),
            "base deny entry must be preserved"
        );
        assert!(
            merged.domains.deny.contains(&"extra-bad.com".to_string()),
            "operator deny entry must be added"
        );
        assert_eq!(merged.domains.deny.len(), 2);
    }

    #[test]
    fn test_merge_allow_intersection() {
        let base = base_policy();
        let operator = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                // B and C overlap with base; D is operator-only (not in base → excluded)
                allow: vec![
                    "api.github.com".into(),
                    "api.openai.com".into(),
                    "api.stripe.com".into(),
                ],
                deny: vec![],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        };

        let merged = base.merge_override(&operator);

        assert!(
            merged.domains.allow.contains(&"api.github.com".to_string()),
            "intersection: api.github.com must be in result"
        );
        assert!(
            merged.domains.allow.contains(&"api.openai.com".to_string()),
            "intersection: api.openai.com must be in result"
        );
        assert!(
            !merged
                .domains
                .allow
                .contains(&"api.example.com".to_string()),
            "api.example.com not in operator allow → must be excluded"
        );
        assert!(
            !merged.domains.allow.contains(&"api.stripe.com".to_string()),
            "api.stripe.com not in base allow → must be excluded"
        );
    }

    #[test]
    fn test_merge_rate_limits_min() {
        let base = base_policy(); // global = 60, openai = 20
        let operator = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![],
                deny: vec![],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy {
                max_requests_per_minute: 30,
                per_domain: {
                    let mut m = HashMap::new();
                    m.insert("api.openai.com".into(), 10);
                    m.insert("api.github.com".into(), 5);
                    m
                },
            },
            audit: AuditPolicy::default(),
        };

        let merged = base.merge_override(&operator);

        assert_eq!(
            merged.rate_limits.max_requests_per_minute, 30,
            "global rate: min(60, 30) = 30"
        );
        assert_eq!(
            merged.rate_limits.per_domain["api.openai.com"], 10,
            "per-domain rate: min(20, 10) = 10"
        );
        assert_eq!(
            merged.rate_limits.per_domain["api.github.com"], 5,
            "operator-only per-domain: min(60, 5) = 5"
        );
    }

    #[test]
    fn test_merge_network_blocks_or() {
        let base = base_policy(); // block_private=false, block_metadata=false
        let operator = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![],
                deny: vec![],
            },
            networks: NetworkPolicy {
                block_private: true,
                block_link_local: false,
                block_localhost: false,
                block_metadata: true,
            },
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        };

        let merged = base.merge_override(&operator);

        assert!(merged.networks.block_private, "false || true = true");
        assert!(
            merged.networks.block_link_local,
            "true || false = true (base had it)"
        );
        assert!(
            merged.networks.block_localhost,
            "true || false = true (base had it)"
        );
        assert!(merged.networks.block_metadata, "false || true = true");
    }

    #[test]
    fn test_merge_empty_override_allow_keeps_base() {
        let base = base_policy(); // has 3 allow entries
        let operator = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![], // empty = no restriction on allow
                deny: vec![],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        };

        let merged = base.merge_override(&operator);

        assert_eq!(
            merged.domains.allow, base.domains.allow,
            "empty operator allow must not restrict base allow list"
        );
    }

    #[test]
    fn test_merge_audit_override_wins() {
        let base = base_policy(); // log_path = /tmp/base-audit.jsonl
        let operator = EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![],
                deny: vec![],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy {
                log_path: Some(PathBuf::from("/var/log/agentshield/operator.jsonl")),
                log_format: "text".into(),
                log_allowed: true,
            },
        };

        let merged = base.merge_override(&operator);

        assert_eq!(
            merged.audit.log_path,
            Some(PathBuf::from("/var/log/agentshield/operator.jsonl")),
            "operator audit log_path must win"
        );
        assert_eq!(
            merged.audit.log_format, "text",
            "operator audit log_format must win"
        );
        assert!(
            merged.audit.log_allowed,
            "operator audit log_allowed must win"
        );
    }

    #[test]
    fn test_emit_egress_policy_integration() {
        // Scan the vuln_ssrf fixture — it has literal HTTP requests.
        // Build the policy from targets embedded in the report and round-trip it.
        use crate::{scan, ScanOptions};
        use std::path::Path;

        let opts = ScanOptions::default();
        let report = scan(Path::new("tests/fixtures/mcp_servers/vuln_ssrf"), &opts)
            .expect("scan should succeed");

        let policy = EgressPolicy::from_scan_targets(&report.targets);

        // Policy must be valid (round-trip save/load)
        let tmp = TempDir::new().unwrap();
        let policy_path = tmp.path().join("agentshield.egress.toml");
        policy.save(&policy_path).unwrap();

        let loaded = EgressPolicy::load(&policy_path).unwrap();
        assert_eq!(loaded.schema_version, 1);
        assert!(loaded.networks.block_private);
        assert!(loaded.networks.block_metadata);
        // deny list must be empty in a generated starter policy
        assert!(loaded.domains.deny.is_empty());
    }
}
