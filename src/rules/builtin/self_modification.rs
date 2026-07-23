use crate::ir::execution_surface::FileOpType;
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-006: Self-Modification
///
/// Flags writes targeting repository root source files or known executable
/// scripts. Code that modifies its own source is a rug pull / persistence risk.
///
/// - Literal path matching a source file → High confidence
/// - Dynamic/interpolated/unknown path in a write → Medium confidence
///   (evasive self-modification often uses dynamic paths)
pub struct SelfModificationDetector;

impl Detector for SelfModificationDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-006".into(),
            name: "Self-Modification".into(),
            description: "Code that writes to its own source files or scripts".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::SelfModification,
            cwe_id: Some("CWE-506".into()),
            owasp_mcp: Some(OwaspMcp::MaliciousUpdate),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        let source_paths: Vec<_> = target.source_files.iter().map(|f| f.path.clone()).collect();

        for file_op in &target.execution.file_operations {
            if !matches!(file_op.operation, FileOpType::Write) {
                continue;
            }

            match &file_op.path_arg {
                crate::ir::ArgumentSource::Literal(path) => {
                    let write_path = std::path::Path::new(path);
                    let is_self_write = source_paths.iter().any(|sp| {
                        sp.ends_with(write_path) || write_path.ends_with(sp) || sp == write_path
                    });
                    if is_self_write {
                        findings.push(self_mod_finding(
                            format!("Writes to own source file: {}", path),
                            Confidence::High,
                            &file_op.location,
                        ));
                    }
                }
                // Dynamic/interpolated/unknown paths used in file writes are suspicious
                // — evasive self-modification deliberately avoids literal paths
                crate::ir::ArgumentSource::Parameter { name } => {
                    findings.push(self_mod_finding(
                        format!(
                            "Writes to file path from parameter '{}' — may target own source",
                            name
                        ),
                        Confidence::Medium,
                        &file_op.location,
                    ));
                }
                crate::ir::ArgumentSource::Interpolated => {
                    findings.push(self_mod_finding(
                        "Writes to dynamically constructed file path — may target own source"
                            .into(),
                        Confidence::Medium,
                        &file_op.location,
                    ));
                }
                crate::ir::ArgumentSource::Unknown => {
                    findings.push(self_mod_finding(
                        "Writes to file with unresolved path — may target own source".into(),
                        Confidence::Low,
                        &file_op.location,
                    ));
                }
                crate::ir::ArgumentSource::EnvVar { name } => {
                    findings.push(self_mod_finding(
                        format!(
                            "Writes to file path from env var '{}' — may target own source",
                            name
                        ),
                        Confidence::Low,
                        &file_op.location,
                    ));
                }
                crate::ir::ArgumentSource::Sanitized { .. } => {
                    // Sanitized paths have been validated — skip
                }
            }
        }

        findings
    }
}

fn self_mod_finding(
    message: String,
    confidence: Confidence,
    location: &crate::ir::SourceLocation,
) -> Finding {
    Finding {
        rule_id: "SHIELD-006".into(),
        rule_name: "Self-Modification".into(),
        severity: Severity::High,
        confidence,
        attack_category: AttackCategory::SelfModification,
        message,
        location: Some(location.clone()),
        evidence: vec![Evidence {
            description: "Code writes to files at runtime".into(),
            location: Some(location.clone()),
            snippet: None,
        }],
        taint_path: None,
        remediation: Some(
            "Code should not modify its own source files at runtime. \
             This pattern enables rug-pull attacks and persistence."
                .into(),
        ),
        cwe_id: Some("CWE-506".into()),
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
            file: PathBuf::from("server.py"),
            line: 10,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn base_target() -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from("server.py"),
                language: Language::Python,
                content: String::new(),
                size_bytes: 0,
                content_hash: String::new(),
            }],
        }
    }

    #[test]
    fn flags_literal_self_write() {
        let mut target = base_target();
        target.execution.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Literal("server.py".into()),
            operation: FileOpType::Write,
            location: loc(),
        });
        let findings = SelfModificationDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn flags_dynamic_path_medium_confidence() {
        let mut target = base_target();
        target.execution.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Interpolated,
            operation: FileOpType::Write,
            location: loc(),
        });
        let findings = SelfModificationDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn flags_parameter_path_medium_confidence() {
        let mut target = base_target();
        target.execution.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "output_file".into(),
            },
            operation: FileOpType::Write,
            location: loc(),
        });
        let findings = SelfModificationDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn ignores_reads() {
        let mut target = base_target();
        target.execution.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Literal("server.py".into()),
            operation: FileOpType::Read,
            location: loc(),
        });
        let findings = SelfModificationDetector.run(&target);
        assert!(findings.is_empty());
    }
}
