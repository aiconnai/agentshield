//! Egress policy schema and validation.
//!
//! Parses `agentshield.egress.toml` files that define which domains,
//! IPs, and rate limits are enforced by the `wrap` command proxy.

mod domain;
mod host;
pub(crate) mod infer;
mod merge;
mod network;
pub(crate) mod types;

pub use domain::DomainPolicy;
#[cfg(feature = "runtime")]
pub(crate) use host::normalize_host;
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

    fn open_policy() -> EgressPolicy {
        EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec![],
                deny: vec![],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy::default(),
            audit: AuditPolicy::default(),
        }
    }

    fn policy_with_allow(allow: &[&str]) -> EgressPolicy {
        EgressPolicy {
            domains: DomainPolicy {
                allow: allow.iter().map(|d| d.to_string()).collect(),
                deny: vec![],
            },
            ..open_policy()
        }
    }

    #[test]
    fn merge_disjoint_allow_lists_denies_everything() {
        let merged =
            policy_with_allow(&["a.example"]).merge_override(&policy_with_allow(&["b.example"]));
        assert!(!merged.is_domain_allowed("a.example"));
        assert!(!merged.is_domain_allowed("b.example"));
        assert!(!merged.is_domain_allowed("anything.else"));
    }

    #[test]
    fn merge_keeps_narrower_allow_pattern() {
        let merged = policy_with_allow(&["*.example.com"])
            .merge_override(&policy_with_allow(&["api.example.com"]));
        assert!(merged.is_domain_allowed("api.example.com"));
        assert!(!merged.is_domain_allowed("evil.example.com"));
    }

    #[test]
    fn merge_rate_limit_zero_is_unlimited_not_strictest() {
        let mut base = open_policy();
        base.rate_limits.max_requests_per_minute = 30;
        base.rate_limits
            .per_domain
            .insert("slow.example".into(), 100);
        let mut operator = open_policy();
        operator.rate_limits.max_requests_per_minute = 0;
        let merged = base.merge_override(&operator);
        assert_eq!(merged.rate_limit_for("any.example"), 30);

        operator.rate_limits.max_requests_per_minute = 10;
        let merged = base.merge_override(&operator);
        assert_eq!(merged.rate_limit_for("slow.example"), 10);
    }

    #[test]
    fn domain_matching_ignores_case_and_trailing_dot() {
        let policy = EgressPolicy {
            domains: DomainPolicy {
                allow: vec![],
                deny: vec!["evil.invalid".into(), "*.Bad.invalid".into()],
            },
            ..open_policy()
        };
        assert!(!policy.is_domain_allowed("EVIL.invalid"));
        assert!(!policy.is_domain_allowed("evil.invalid."));
        assert!(!policy.is_domain_allowed("x.bad.INVALID."));
        assert!(policy.is_domain_allowed("good.invalid"));
    }

    #[test]
    fn ip_blocking_parses_addresses_instead_of_prefixes() {
        let policy = open_policy();
        // Alternate spellings of blocked ranges
        assert!(policy.is_ip_blocked("::ffff:127.0.0.1"));
        assert!(policy.is_ip_blocked("[::ffff:127.0.0.1]"));
        assert!(policy.is_ip_blocked("[::1]"));
        assert!(policy.is_ip_blocked("0.0.0.0"));
        assert!(policy.is_ip_blocked("::ffff:169.254.169.254"));
        assert!(policy.is_ip_blocked("fc00::1"));
        assert!(policy.is_ip_blocked("fd12:3456::1"));
        assert!(policy.is_ip_blocked("fe80::1"));
        assert!(policy.is_ip_blocked("100.64.0.1"));
        assert!(policy.is_ip_blocked("LOCALHOST."));
        // Hostnames that only look like a blocked prefix
        assert!(!policy.is_ip_blocked("fd-cdn.example.com"));
        assert!(!policy.is_ip_blocked("fdroid.example.org"));
        assert!(!policy.is_ip_blocked("10.example.com"));
        assert!(!policy.is_ip_blocked("172.16.example.com"));
        assert!(!policy.is_ip_blocked("2606:4700:4700::1111"));
    }

    fn policy_with_domain_rates(rates: &[(&str, u32)]) -> EgressPolicy {
        EgressPolicy {
            rate_limits: RateLimitPolicy {
                max_requests_per_minute: 0,
                per_domain: rates.iter().map(|(d, r)| (d.to_string(), *r)).collect(),
            },
            ..open_policy()
        }
    }

    #[test]
    fn per_domain_rate_limit_ignores_case_and_trailing_dot() {
        let policy = policy_with_domain_rates(&[("API.GitHub.com.", 5)]);
        assert_eq!(policy.rate_limit_for("api.github.com"), 5);
    }

    #[test]
    fn merge_keeps_stricter_rate_across_differently_spelled_keys() {
        let base = policy_with_domain_rates(&[("api.github.com", 30)]);
        let operator = policy_with_domain_rates(&[("API.github.com", 10)]);
        let merged = base.merge_override(&operator);
        assert_eq!(merged.rate_limit_for("api.github.com"), 10);
        assert_eq!(merged.rate_limits.per_domain.len(), 1);
    }

    /// A policy that blocks exactly one network category, so a test proves
    /// which category an address is classified into.
    fn only_blocking(category: &str) -> EgressPolicy {
        EgressPolicy {
            networks: NetworkPolicy {
                block_private: category == "private",
                block_link_local: category == "link_local",
                block_localhost: category == "localhost",
                block_metadata: category == "metadata",
            },
            ..open_policy()
        }
    }

    /// A policy that blocks nothing at the network layer.
    fn no_network_blocks() -> EgressPolicy {
        only_blocking("none")
    }

    #[test]
    fn nat64_embedded_ipv4_is_classified_as_that_ipv4() {
        // 64:ff9b::/96 (RFC 6052): the low 32 bits are the IPv4 destination.
        assert!(only_blocking("localhost").is_ip_blocked("64:ff9b::7f00:1"));
        assert!(only_blocking("localhost").is_ip_blocked("[64:ff9b::7f00:1]"));
        assert!(only_blocking("localhost").is_ip_blocked("64:ff9b::127.0.0.1"));
        assert!(only_blocking("metadata").is_ip_blocked("64:ff9b::a9fe:a9fe"));
        assert!(only_blocking("link_local").is_ip_blocked("64:ff9b::a9fe:a9fe"));
        assert!(only_blocking("private").is_ip_blocked("64:ff9b::a00:1"));
        assert!(only_blocking("private").is_ip_blocked("64:ff9b::c0a8:101"));
        // A public IPv4 behind NAT64 stays reachable.
        assert!(!open_policy().is_ip_blocked("64:ff9b::808:808"));
    }

    #[test]
    fn ipv4_compatible_ipv6_is_classified_as_that_ipv4() {
        assert!(only_blocking("localhost").is_ip_blocked("::127.0.0.1"));
        assert!(only_blocking("localhost").is_ip_blocked("::7f00:1"));
        assert!(only_blocking("metadata").is_ip_blocked("::169.254.169.254"));
        assert!(only_blocking("private").is_ip_blocked("::10.0.0.1"));
        assert!(!open_policy().is_ip_blocked("::8.8.8.8"));
        // `::1` and `::` keep their IPv6 meaning.
        assert!(only_blocking("localhost").is_ip_blocked("::1"));
        assert!(only_blocking("localhost").is_ip_blocked("::"));
    }

    #[test]
    fn six_to_four_embedded_ipv4_is_classified_conservatively() {
        // 2002::/16: bits 16..48 are the 6to4 gateway's IPv4 address.
        assert!(only_blocking("localhost").is_ip_blocked("2002:7f00:1::"));
        assert!(only_blocking("metadata").is_ip_blocked("2002:a9fe:a9fe::1"));
        assert!(only_blocking("private").is_ip_blocked("2002:c0a8:101::1"));
        assert!(!open_policy().is_ip_blocked("2002:808:808::1"));
    }

    #[test]
    fn whole_this_network_block_counts_as_localhost() {
        assert!(only_blocking("localhost").is_ip_blocked("0.0.0.0"));
        assert!(only_blocking("localhost").is_ip_blocked("0.0.0.1"));
        assert!(only_blocking("localhost").is_ip_blocked("0.255.255.255"));
        assert!(only_blocking("localhost").is_ip_blocked("::ffff:0.1.2.3"));
        assert!(!open_policy().is_ip_blocked("1.0.0.0"));
        assert!(!no_network_blocks().is_ip_blocked("0.0.0.1"));
    }

    #[test]
    fn ipv6_zone_identifiers_do_not_hide_the_address() {
        // Raw, bracketed and percent-encoded (`%25`) zone separators.
        assert!(only_blocking("link_local").is_ip_blocked("fe80::1%eth0"));
        assert!(only_blocking("link_local").is_ip_blocked("[fe80::1%eth0]"));
        assert!(only_blocking("link_local").is_ip_blocked("[fe80::1%25eth0]"));
        assert!(only_blocking("link_local").is_ip_blocked("fe80::1%25eth0"));
        assert!(only_blocking("localhost").is_ip_blocked("::1%lo"));
        assert!(!open_policy().is_ip_blocked("2606:4700:4700::1111%eth0"));
    }

    fn policy_with_deny(deny: &[&str]) -> EgressPolicy {
        EgressPolicy {
            domains: DomainPolicy {
                allow: vec![],
                deny: deny.iter().map(|d| d.to_string()).collect(),
            },
            ..open_policy()
        }
    }

    #[test]
    fn unicode_deny_rule_matches_punycode_host_and_vice_versa() {
        let unicode_rule = policy_with_deny(&["bücher.example", "*.Stra\u{df}e.example"]);
        assert!(!unicode_rule.is_domain_allowed("xn--bcher-kva.example"));
        assert!(!unicode_rule.is_domain_allowed("XN--BCHER-KVA.example."));
        assert!(!unicode_rule.is_domain_allowed("BÜCHER.example"));
        assert!(!unicode_rule.is_domain_allowed("www.xn--strae-oqa.example"));
        assert!(unicode_rule.is_domain_allowed("bucher.example"));

        let punycode_rule = policy_with_deny(&["xn--bcher-kva.example", "*.xn--strae-oqa.example"]);
        assert!(!punycode_rule.is_domain_allowed("bücher.example"));
        assert!(!punycode_rule.is_domain_allowed("www.Stra\u{df}e.example"));
    }

    #[test]
    fn unicode_and_punycode_allow_rules_are_interchangeable() {
        assert!(policy_with_allow(&["bücher.example"]).is_domain_allowed("xn--bcher-kva.example"));
        assert!(policy_with_allow(&["xn--bcher-kva.example"]).is_domain_allowed("bücher.example"));
        assert!(
            policy_with_allow(&["*.bücher.example"])
                .is_domain_allowed("shop.xn--bcher-kva.example")
        );
        assert!(!policy_with_allow(&["bücher.example"]).is_domain_allowed("bucher.example"));
    }

    #[test]
    fn invalid_idna_fails_closed() {
        // A host that is not valid IDNA is never allowed, even by an open policy.
        assert!(!open_policy().is_domain_allowed("xn--.example"));
        assert!(!open_policy().is_domain_allowed("a..example"));
        // A rule that is not valid IDNA grants nothing.
        let broken_allow = policy_with_allow(&["xn--.example"]);
        assert!(!broken_allow.is_domain_allowed("xn--.example"));
        assert!(!broken_allow.is_domain_allowed("anything.example"));
        let with_broken_deny = EgressPolicy {
            domains: DomainPolicy {
                allow: vec!["good.example".into()],
                deny: vec!["xn--.example".into()],
            },
            ..open_policy()
        };
        assert!(!with_broken_deny.is_domain_allowed("good.example"));
    }

    #[test]
    fn rate_limit_keys_and_hosts_share_one_normalization() {
        let policy = policy_with_domain_rates(&[("bücher.example", 7)]);
        assert_eq!(policy.rate_limit_for("xn--bcher-kva.example."), 7);
        assert_eq!(policy.rate_limit_for("  BÜCHER.example "), 7);
        let merged =
            policy.merge_override(&policy_with_domain_rates(&[("XN--BCHER-KVA.example", 3)]));
        assert_eq!(merged.rate_limit_for("bücher.example"), 3);
        assert_eq!(merged.rate_limits.per_domain.len(), 1);
    }

    #[test]
    fn hostname_classification_uses_the_shared_normalization() {
        let policy = open_policy();
        assert!(policy.is_ip_blocked("  LOCALHOST.  "));
        assert!(policy.is_ip_blocked("api.LocalHost."));
        // Fullwidth letters fold to ASCII under IDNA.
        assert!(policy.is_ip_blocked("ｌｏｃａｌｈｏｓｔ"));
        assert!(policy.is_ip_blocked("Metadata.Google.Internal."));
        assert!(!policy.is_ip_blocked("localhost.example.com"));
    }

    #[test]
    fn extracted_domains_are_normalized() {
        assert_eq!(
            extract_domain("https://API.Stripe.com/v1"),
            Some("api.stripe.com".into())
        );
        assert_eq!(
            extract_domain("https://bücher.example/x"),
            Some("xn--bcher-kva.example".into())
        );
        assert_eq!(extract_domain("http://xn--.example/"), None);
    }

    #[test]
    fn azure_wireserver_is_a_metadata_endpoint() {
        assert!(only_blocking("metadata").is_ip_blocked("168.63.129.16"));
        assert!(only_blocking("metadata").is_ip_blocked("::ffff:168.63.129.16"));
        assert!(!open_policy().is_ip_blocked("168.63.129.17"));
    }
}
