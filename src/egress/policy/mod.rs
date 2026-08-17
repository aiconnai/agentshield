//! Egress policy schema and validation.
//!
//! Parses `agentshield.egress.toml` files that define which domains,
//! IPs, and rate limits are enforced by the `wrap` command proxy.

mod domain;
pub(crate) mod infer;
mod merge;
mod network;
pub(crate) mod types;

pub use domain::DomainPolicy;
pub use merge::{AuditPolicy, RateLimitPolicy};
pub use network::NetworkPolicy;
pub use types::EgressPolicy;

#[cfg(test)]
mod tests {
    use super::domain::extract_domain;
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
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

        // Private
        assert!(policy.is_ip_blocked("10.0.0.1"));
        assert!(policy.is_ip_blocked("192.168.1.1"));
        assert!(policy.is_ip_blocked("172.16.0.1"));
        assert!(policy.is_ip_blocked("172.31.255.255"));

        // Link-local
        assert!(policy.is_ip_blocked("169.254.1.1"));

        // Metadata service
        assert!(policy.is_ip_blocked("169.254.169.254"));

        // Public IPs should NOT be blocked
        assert!(!policy.is_ip_blocked("8.8.8.8"));
        assert!(!policy.is_ip_blocked("1.1.1.1"));
        assert!(!policy.is_ip_blocked("142.250.80.46"));
    }

    #[test]
    fn test_rate_limits() {
        let policy = sample_policy();

        // Specific domain override
        assert_eq!(policy.rate_limit_for("api.github.com"), 30);
        // Default for unlisted domain
        assert_eq!(policy.rate_limit_for("example.com"), 60);
    }

    #[test]
    fn test_from_scan_targets() {
        use crate::ir::execution_surface::{ExecutionSurface, NetworkOperation};
        use crate::ir::tool_surface::{DeclaredPermission, PermissionType, ToolSurface};
        use crate::ir::{ArgumentSource, Framework, ScanTarget};

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
                declared_capabilities: Default::default(),
                capability_declarations: vec![],
                observed_capabilities: Default::default(),
                capability_observation_complete: false,
                capability_evidence: vec![],
            }],
            execution: ExecutionSurface {
                network_operations: vec![
                    NetworkOperation {
                        function: "fetch".into(),
                        url_arg: ArgumentSource::Literal("https://api.github.com/repos".into()),
                        method: None,
                        sends_data: false,
                        location: crate::ir::SourceLocation {
                            file: PathBuf::from("index.ts"),
                            line: 1,
                            column: 1,
                            end_line: None,
                            end_column: None,
                        },
                    },
                    // Non-literal URL should be ignored
                    NetworkOperation {
                        function: "fetch".into(),
                        url_arg: ArgumentSource::Parameter { name: "url".into() },
                        method: None,
                        sends_data: false,
                        location: crate::ir::SourceLocation {
                            file: PathBuf::from("index.ts"),
                            line: 2,
                            column: 1,
                            end_line: None,
                            end_column: None,
                        },
                    },
                ],
                commands: vec![],
                file_operations: vec![],
                env_accesses: vec![],
                dynamic_exec: vec![],
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let policy = EgressPolicy::from_scan_targets(&[target]);

        assert_eq!(policy.schema_version, 1);
        assert_eq!(
            policy.domains.allow,
            vec!["api.github.com".to_string(), "api.stripe.com".to_string()]
        );
        assert!(policy.domains.deny.is_empty());
        assert!(policy.networks.block_private);
        assert!(policy.networks.block_localhost);
    }

    #[test]
    fn test_extract_domain_helper() {
        assert_eq!(
            extract_domain("https://api.github.com/repos"),
            Some("api.github.com".into())
        );
        assert_eq!(
            extract_domain("http://example.com:8080/path"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_domain("api.github.com"),
            Some("api.github.com".into())
        );
        assert_eq!(
            extract_domain("*.example.com"),
            Some("*.example.com".into())
        );
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn test_starter_toml_is_valid() {
        let toml_str = EgressPolicy::starter_toml();
        let policy: EgressPolicy = toml::from_str(toml_str).unwrap();
        assert_eq!(policy.schema_version, 1);
        assert_eq!(
            policy.domains.allow,
            vec!["*.example.com".to_string(), "api.github.com".to_string()]
        );
        assert!(policy.networks.block_private);
        assert_eq!(policy.rate_limits.max_requests_per_minute, 60);
    }

    #[test]
    fn test_reject_future_schema_version() {
        let toml_str = r#"
schema_version = 999
[domains]
allow = ["*"]
"#;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("future.toml");
        std::fs::write(&path, toml_str).unwrap();

        let result = EgressPolicy::load(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("newer than supported version"));
    }
}
