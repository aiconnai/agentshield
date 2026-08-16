use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
use crate::ir::{ArgumentSource, ScanTarget};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-013: Metadata SSRF
///
/// Detects when tool arguments flow to HTTP requests that could target
/// cloud metadata endpoints (169.254.169.254, etc.) or private IP ranges.
/// This is a more dangerous variant of general SSRF (SHIELD-003).
pub struct MetadataSsrfDetector;

/// Cloud metadata endpoints that should never be accessible via user input.
/// Shared with the runtime guard so static and runtime detection stay aligned.
pub(crate) const METADATA_ENDPOINTS: &[&str] = &[
    "169.254.169.254",          // AWS/Azure/GCP
    "metadata.google.internal", // GCP
    "metadata.google",          // GCP alternate
    "100.100.100.200",          // Alibaba Cloud
    "169.254.170.2",            // AWS ECS task metadata
];

/// Private/reserved IP patterns that indicate internal network access.
const PRIVATE_PATTERNS: &[&str] = &[
    "10.",     // Class A private
    "172.16.", // Class B private (172.16-31.x)
    "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", // Class C private
    "127.",     // Loopback
    "0.",       // This network
    "[::1]",    // IPv6 loopback
    "[fd",      // IPv6 private (fd00::/8)
    "[fe80:",   // IPv6 link-local
];

/// Whether `text` references a known cloud metadata endpoint (case-insensitive).
/// Shared with the runtime guard so both surfaces use the same endpoint list.
#[cfg(feature = "runtime-guard")]
pub(crate) fn references_metadata_endpoint(text: &str) -> bool {
    let lower = text.to_lowercase();
    METADATA_ENDPOINTS.iter().any(|ep| lower.contains(ep))
}

/// Returns true if the URL string targets a metadata endpoint or private network.
fn is_metadata_or_private(url: &str) -> Option<&'static str> {
    let url_lower = url.to_lowercase();
    if METADATA_ENDPOINTS.iter().any(|ep| url_lower.contains(ep)) {
        return Some("cloud metadata endpoint");
    }

    // Extract authority/host before checking private IP prefixes.
    // Strip userinfo (user:pass@) to prevent bypass via basic auth URLs.
    let after_scheme = url_lower.split("://").nth(1).unwrap_or(&url_lower);
    let authority = after_scheme.split('/').next().unwrap_or("");
    let after_userinfo = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if after_userinfo.starts_with('[') {
        if let Some(bracket_end) = after_userinfo.find(']') {
            &after_userinfo[..=bracket_end]
        } else {
            after_userinfo
        }
    } else {
        after_userinfo.split([':', '?', '#']).next().unwrap_or("")
    };

    if host == "localhost" || PRIVATE_PATTERNS.iter().any(|pat| host.starts_with(pat)) {
        return Some("private network");
    }
    None
}

impl Detector for MetadataSsrfDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-013".into(),
            name: "Metadata SSRF".into(),
            description: "Tool arguments flow to HTTP requests that could target \
                          cloud metadata endpoints or private networks"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::Ssrf,
            cwe_id: Some("CWE-918".into()),
            owasp_mcp: Some(OwaspMcp::InsecureCommunication),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut sink_urls = std::collections::HashMap::new();
        for op in &target.execution.network_operations {
            if let ArgumentSource::Literal(url) = &op.url_arg {
                sink_urls.insert(&op.location, url.as_str());
            }
        }

        // Phase 1: Check taint paths from ToolArgument -> HttpRequest
        for path in &target.data.taint_paths {
            if matches!(path.source.source_type, TaintSourceType::ToolArgument)
                && matches!(path.sink.sink_type, TaintSinkType::HttpRequest)
            {
                let target_type = sink_urls
                    .get(&path.sink.location)
                    .and_then(|url| is_metadata_or_private(url));
                if has_finding_at_location(&findings, &path.sink.location) {
                    continue;
                }
                findings.push(Finding {
                    rule_id: "SHIELD-013".into(),
                    rule_name: "Metadata SSRF".into(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::Ssrf,
                    message: format!(
                        "Tool parameter '{}' flows to HTTP request '{}' without URL \
                         validation — could target cloud metadata or private networks",
                        path.source.description, path.sink.description
                    ),
                    location: Some(path.sink.location.clone()),
                    evidence: vec![
                        Evidence {
                            description: format!(
                                "Source: tool parameter '{}'",
                                path.source.description
                            ),
                            location: Some(path.source.location.clone()),
                            snippet: None,
                        },
                        Evidence {
                            description: format!(
                                "Sink: HTTP request{} via '{}'",
                                target_type
                                    .map(|kind| format!(" to {kind}"))
                                    .unwrap_or_default(),
                                path.sink.description,
                            ),
                            location: Some(path.sink.location.clone()),
                            snippet: None,
                        },
                    ],
                    taint_path: Some(path.clone()),
                    remediation: Some(
                        "Validate URLs against an allowlist before making requests. \
                         Block private IP ranges (10.x, 172.16-31.x, 192.168.x), \
                         link-local (169.254.x), and cloud metadata endpoints \
                         (169.254.169.254)."
                            .into(),
                    ),
                    cwe_id: Some("CWE-918".into()),
                });
            }
        }

        // Phase 2: Check NetworkOperations for literal URLs pointing to metadata/private
        for net_op in &target.execution.network_operations {
            if let ArgumentSource::Literal(ref url) = net_op.url_arg {
                if let Some(target_type) = is_metadata_or_private(url) {
                    if has_finding_at_location(&findings, &net_op.location) {
                        continue;
                    }
                    findings.push(Finding {
                        rule_id: "SHIELD-013".into(),
                        rule_name: "Metadata SSRF".into(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::Ssrf,
                        message: format!(
                            "'{}' makes request to {} ({})",
                            net_op.function, target_type, url
                        ),
                        location: Some(net_op.location.clone()),
                        evidence: vec![Evidence {
                            description: format!("Hardcoded {} URL: {}", target_type, url),
                            location: Some(net_op.location.clone()),
                            snippet: None,
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Remove direct access to metadata endpoints and private \
                             networks. Use cloud provider SDKs for metadata access."
                                .into(),
                        ),
                        cwe_id: Some("CWE-918".into()),
                    });
                }
            }
        }

        findings
    }
}

fn has_finding_at_location(findings: &[Finding], location: &crate::ir::SourceLocation) -> bool {
    findings.iter().any(|finding| {
        if finding.rule_id != "SHIELD-013" {
            return false;
        }
        finding
            .location
            .as_ref()
            .is_some_and(|finding_location| finding_location == location)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::data_surface::*;
    use crate::ir::execution_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn loc() -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("test.py"),
            line: 5,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn empty_target() -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface::default(),
            data: DataSurface::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    #[test]
    fn detects_taint_path_to_http_metadata_url() {
        let mut target = empty_target();
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::ToolArgument,
                description: "url".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::HttpRequest,
                description: "requests.get".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("http://169.254.169.254/latest/meta-data/".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-013");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].taint_path.is_some());
    }

    #[test]
    fn detects_taint_path_to_http_without_literal_url() {
        let mut target = empty_target();
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::ToolArgument,
                description: "url".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::HttpRequest,
                description: "requests.get".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-013");
        assert!(findings[0].taint_path.is_some());
    }

    #[test]
    fn detects_literal_metadata_url() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("http://169.254.169.254/latest/meta-data/".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-013");
        assert!(findings[0].message.contains("cloud metadata endpoint"));
    }

    #[test]
    fn detects_literal_private_ip() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "fetch".into(),
            url_arg: ArgumentSource::Literal("http://192.168.1.1/admin".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-013");
        assert!(findings[0].message.contains("private network"));
    }

    #[test]
    fn no_finding_for_public_url() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("https://api.example.com/data".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_for_sanitized_arg() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Sanitized {
                sanitizer: "validate_url".into(),
            },
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_alibaba_metadata() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "urllib.request.urlopen".into(),
            url_arg: ArgumentSource::Literal("http://100.100.100.200/latest/meta-data/".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("cloud metadata endpoint"));
    }

    #[test]
    fn detects_gcp_metadata() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal(
                "http://metadata.google.internal/computeMetadata/v1/".into(),
            ),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("cloud metadata endpoint"));
    }

    #[test]
    fn no_overlap_with_parameter_url() {
        // SHIELD-013 should NOT fire on Parameter sources in network_operations —
        // that's SHIELD-003's domain. SHIELD-013 Phase 2 only checks Literal URLs.
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Parameter { name: "url".into() },
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert!(
            findings.is_empty(),
            "Phase 2 should not fire on Parameter sources (that's SHIELD-003)"
        );
    }

    #[test]
    fn detects_ipv6_metadata_and_private_patterns() {
        let mut target = empty_target();
        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("http://[fd00:ec2::254]/latest/meta-data/".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });
        target.execution.network_operations.push(NetworkOperation {
            function: "fetch".into(),
            url_arg: ArgumentSource::Literal("http://169.254.170.2/v2/metadata".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: SourceLocation {
                file: PathBuf::from("test.py"),
                line: 20,
                column: 0,
                end_line: None,
                end_column: None,
            },
        });
        target.execution.network_operations.push(NetworkOperation {
            function: "axios.get".into(),
            url_arg: ArgumentSource::Literal("http://[::1]:8080/admin".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: SourceLocation {
                file: PathBuf::from("test.py"),
                line: 30,
                column: 0,
                end_line: None,
                end_column: None,
            },
        });

        let findings = MetadataSsrfDetector.run(&target);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].rule_id, "SHIELD-013");
        assert_eq!(findings[1].rule_id, "SHIELD-013");
        assert_eq!(findings[2].rule_id, "SHIELD-013");
    }
}
