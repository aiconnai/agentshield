use crate::ir::{ArgumentSource, ScanTarget, SinkClass};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-004: Arbitrary File Access
///
/// Flags file read/write/delete where path comes from untrusted argument
/// source and no canonicalization/allowlist guard detected.
pub struct ArbitraryFileAccessDetector;

impl Detector for ArbitraryFileAccessDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-004".into(),
            name: "Arbitrary File Access".into(),
            description: "File read/write with path from untrusted input".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::ArbitraryFileAccess,
            cwe_id: Some("CWE-22".into()),
            owasp_mcp: Some(OwaspMcp::ExcessiveScope),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file_op in &target.execution.file_operations {
            if file_op.path_arg.is_tainted_for_sink(SinkClass::FilePath) {
                let source_desc = match &file_op.path_arg {
                    ArgumentSource::Parameter { name } => format!("parameter '{name}'"),
                    ArgumentSource::Interpolated => "interpolated string".into(),
                    ArgumentSource::Unknown => "unknown source".into(),
                    ArgumentSource::EnvVar { name } => format!("env var '{name}'"),
                    // A sanitizer that reached here cleared the FilePath gate
                    // check only by being the wrong category (e.g. a URL
                    // validator guarding a file path).
                    ArgumentSource::Sanitized { sanitizer } => {
                        format!("value from wrong-category sanitizer '{sanitizer}'")
                    }
                    ArgumentSource::Literal(_) => continue,
                };

                let confidence = match &file_op.path_arg {
                    ArgumentSource::Parameter { .. } => Confidence::High,
                    _ => Confidence::Medium,
                };

                findings.push(Finding {
                    rule_id: "SHIELD-004".into(),
                    rule_name: "Arbitrary File Access".into(),
                    severity: Severity::High,
                    confidence,
                    attack_category: AttackCategory::ArbitraryFileAccess,
                    message: format!(
                        "File {:?} with path from {}",
                        file_op.operation, source_desc
                    ),
                    location: Some(file_op.location.clone()),
                    evidence: vec![Evidence {
                        description: format!("{} flows into file path", source_desc),
                        location: Some(file_op.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Canonicalize paths and validate against an allowlist of \
                         permitted directories. Reject paths with '..' traversal."
                            .into(),
                    ),
                    cwe_id: Some("CWE-22".into()),
                });
            }
        }

        findings
    }
}
