use crate::ir::{ArgumentSource, ScanTarget, SinkClass};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-003: Server-Side Request Forgery (SSRF)
///
/// Flags URL-consuming network calls where the URL argument source is
/// Parameter, Interpolated, or Unknown and no allowlist validator is found.
pub struct SsrfDetector;

impl Detector for SsrfDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-003".into(),
            name: "SSRF".into(),
            description: "Fetches URL from tool parameter without allowlist validation".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::Ssrf,
            cwe_id: Some("CWE-918".into()),
            owasp_mcp: Some(OwaspMcp::CommandExecution),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for net_op in &target.execution.network_operations {
            let (should_flag, confidence) = match &net_op.url_arg {
                ArgumentSource::Parameter { .. } => (true, Confidence::High),
                ArgumentSource::Interpolated => (true, Confidence::Medium),
                ArgumentSource::Unknown => (true, Confidence::Medium),
                ArgumentSource::Literal(_) | ArgumentSource::EnvVar { .. } => {
                    (false, Confidence::Low)
                }
                // A sanitizer only clears taint when it actually guards a
                // network sink (an allowlist validator). A path/type/redaction
                // sanitizer on a URL sink does not, so it stays flagged.
                ArgumentSource::Sanitized { .. } => (
                    net_op.url_arg.is_tainted_for_sink(SinkClass::NetworkUrl),
                    Confidence::Medium,
                ),
            };

            if should_flag {
                let source_desc = match &net_op.url_arg {
                    ArgumentSource::Parameter { name } => format!("parameter '{name}'"),
                    ArgumentSource::Interpolated => "interpolated string".into(),
                    ArgumentSource::Unknown => "unknown source".into(),
                    _ => "other".into(),
                };

                findings.push(Finding {
                    rule_id: "SHIELD-003".into(),
                    rule_name: "SSRF".into(),
                    severity: Severity::High,
                    confidence,
                    attack_category: AttackCategory::Ssrf,
                    message: format!(
                        "'{}' fetches URL from {} without allowlist",
                        net_op.function, source_desc
                    ),
                    location: Some(net_op.location.clone()),
                    evidence: vec![Evidence {
                        description: format!(
                            "{} flows into URL argument of '{}'",
                            source_desc, net_op.function
                        ),
                        location: Some(net_op.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Validate URLs against an allowlist of permitted domains. \
                         Block requests to internal/private IP ranges."
                            .into(),
                    ),
                    cwe_id: Some("CWE-918".into()),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn flags_url_from_parameter() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Parameter { name: "url".into() },
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = SsrfDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-003");
    }

    #[test]
    fn passes_hardcoded_url() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = SsrfDetector.run(&target);
        assert!(findings.is_empty());
    }
}
