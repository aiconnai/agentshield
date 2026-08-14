use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-015: Overbroad Filesystem Scope
///
/// Detects file operations with overly permissive paths (root, home, broad globs,
/// parent traversal) that could allow access to sensitive system areas (CWE-552).
pub struct OverbroadFsDetector;

/// Paths that grant overly broad filesystem access.
const OVERBROAD_PATHS: &[&str] = &["/", "~", "$HOME", "C:\\", "C:/", "*", "**/*", "**\\*"];

/// Patterns indicating path traversal attempts.
const TRAVERSAL_PATTERNS: &[&str] = &["../", "..\\", "%2e%2e/", "%2e%2e\\"];

/// Home directory expansion functions.
const HOME_EXPAND_PATTERNS: &[&str] = &["os.path.expanduser", "Path.home()", "os.homedir()"];

/// Returns a description if the path is overbroad, or None if it's acceptable.
fn check_overbroad(path_str: &str) -> Option<&'static str> {
    let trimmed = path_str.trim().trim_matches('"').trim_matches('\'');

    for overbroad in OVERBROAD_PATHS {
        if trimmed == *overbroad {
            return Some("root or home directory path");
        }
    }

    for traversal in TRAVERSAL_PATTERNS {
        if trimmed.contains(traversal) {
            return Some("path traversal pattern");
        }
    }

    for home_fn in HOME_EXPAND_PATTERNS {
        if trimmed.contains(home_fn) {
            return Some("home directory expansion");
        }
    }

    None
}

impl Detector for OverbroadFsDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-015".into(),
            name: "Overbroad Filesystem Scope".into(),
            description: "File operations with overly permissive paths that could allow \
                          access to sensitive system areas"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::ArbitraryFileAccess,
            cwe_id: Some("CWE-552".into()),
            owasp_mcp: Some(OwaspMcp::ExcessiveScope),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Check taint paths from ToolArgument -> FileWrite
        for path in &target.data.taint_paths {
            if matches!(
                path.source.source_type,
                crate::ir::data_surface::TaintSourceType::ToolArgument
            ) && matches!(
                path.sink.sink_type,
                crate::ir::data_surface::TaintSinkType::FileWrite
            ) {
                findings.push(Finding {
                    rule_id: "SHIELD-015".into(),
                    rule_name: "Overbroad Filesystem Scope".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::ArbitraryFileAccess,
                    message: format!(
                        "Tool parameter '{}' flows to file write '{}' without scope restriction",
                        path.source.description, path.sink.description
                    ),
                    location: Some(path.sink.location.clone()),
                    evidence: vec![
                        Evidence {
                            description: format!("Source: {}", path.source.description),
                            location: Some(path.source.location.clone()),
                            snippet: None,
                        },
                        Evidence {
                            description: format!("Sink: {}", path.sink.description),
                            location: Some(path.sink.location.clone()),
                            snippet: None,
                        },
                    ],
                    taint_path: Some(path.clone()),
                    remediation: Some(
                        "Validate the path parameter against an allowlist of permitted \
                         directories. Use path canonicalization and check that the \
                         resolved path stays within the allowed scope."
                            .into(),
                    ),
                    cwe_id: Some("CWE-552".into()),
                });
            }
        }

        for file_op in &target.execution.file_operations {
            match &file_op.path_arg {
                crate::ir::ArgumentSource::Literal(path_str) => {
                    if let Some(reason) = check_overbroad(path_str) {
                        findings.push(Finding {
                            rule_id: "SHIELD-015".into(),
                            rule_name: "Overbroad Filesystem Scope".into(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            attack_category: AttackCategory::ArbitraryFileAccess,
                            message: format!(
                                "File {:?} operation uses {} '{}' — grants overly broad access",
                                file_op.operation, reason, path_str
                            ),
                            location: Some(file_op.location.clone()),
                            evidence: vec![Evidence {
                                description: format!("Overbroad path '{}' ({reason})", path_str),
                                location: Some(file_op.location.clone()),
                                snippet: None,
                            }],
                            taint_path: None,
                            remediation: Some(
                                "Restrict file operations to a specific directory. Use an \
                                 allowlist of permitted paths and validate all paths against \
                                 it. Never allow root, home directory, or glob-all patterns."
                                    .into(),
                            ),
                            cwe_id: Some("CWE-552".into()),
                        });
                    }
                }
                crate::ir::ArgumentSource::Parameter { name } => {
                    findings.push(Finding {
                        rule_id: "SHIELD-015".into(),
                        rule_name: "Overbroad Filesystem Scope".into(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::ArbitraryFileAccess,
                        message: format!(
                            "File {:?} operation uses unvalidated parameter '{}' as path \
                             — could access any location",
                            file_op.operation, name
                        ),
                        location: Some(file_op.location.clone()),
                        evidence: vec![Evidence {
                            description: format!(
                                "Parameter '{name}' used as file path without scope restriction"
                            ),
                            location: Some(file_op.location.clone()),
                            snippet: None,
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Validate the path parameter against an allowlist of permitted \
                             directories. Use path canonicalization and check that the \
                             resolved path stays within the allowed scope."
                                .into(),
                        ),
                        cwe_id: Some("CWE-552".into()),
                    });
                }
                crate::ir::ArgumentSource::Interpolated => {
                    findings.push(Finding {
                        rule_id: "SHIELD-015".into(),
                        rule_name: "Overbroad Filesystem Scope".into(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::ArbitraryFileAccess,
                        message: format!(
                            "File {:?} operation uses interpolated path — could access \
                             any location",
                            file_op.operation
                        ),
                        location: Some(file_op.location.clone()),
                        evidence: vec![Evidence {
                            description: "Interpolated string used as file path".into(),
                            location: Some(file_op.location.clone()),
                            snippet: None,
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Validate the constructed path against an allowlist of permitted \
                             directories before performing file operations."
                                .into(),
                        ),
                        cwe_id: Some("CWE-552".into()),
                    });
                }
                // Sanitized and Literal(safe) and EnvVar are not flagged
                _ => {}
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
            line: 10,
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
    fn detects_root_path() {
        let mut target = empty_target();
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Read,
            path_arg: ArgumentSource::Literal("/".into()),
            location: loc(),
        });

        let findings = OverbroadFsDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-015");
        assert!(findings[0].message.contains("root or home directory path"));
    }

    #[test]
    fn detects_traversal_pattern() {
        let mut target = empty_target();
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Read,
            path_arg: ArgumentSource::Literal("../../etc/passwd".into()),
            location: loc(),
        });

        let findings = OverbroadFsDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("path traversal pattern"));
    }

    #[test]
    fn no_finding_for_scoped_literal_path() {
        let mut target = empty_target();
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Read,
            path_arg: ArgumentSource::Literal("/app/data/config.json".into()),
            location: loc(),
        });

        let findings = OverbroadFsDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unvalidated_parameter_path() {
        let mut target = empty_target();
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Write,
            path_arg: ArgumentSource::Parameter {
                name: "file_path".into(),
            },
            location: loc(),
        });

        let findings = OverbroadFsDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("unvalidated parameter"));
    }

    #[test]
    fn no_finding_for_sanitized_path() {
        let mut target = empty_target();
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Read,
            path_arg: ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            },
            location: loc(),
        });

        let findings = OverbroadFsDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_home_expansion_and_windows_drive_roots() {
        let mut target = empty_target();
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Read,
            path_arg: ArgumentSource::Literal("os.path.expanduser('~')".into()),
            location: loc(),
        });
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Write,
            path_arg: ArgumentSource::Literal("C:\\".into()),
            location: SourceLocation {
                file: PathBuf::from("win.py"),
                line: 15,
                column: 0,
                end_line: None,
                end_column: None,
            },
        });

        let findings = OverbroadFsDetector.run(&target);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].message.contains("home directory expansion"));
        assert!(findings[1].message.contains("root or home directory path"));
    }

    #[test]
    fn detects_taint_path_to_file_write() {
        use crate::ir::data_surface::{
            TaintPath, TaintSink, TaintSinkType, TaintSource, TaintSourceType,
        };

        let mut target = empty_target();
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::ToolArgument,
                description: "dest_path".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::FileWrite,
                description: "open(dest_path, 'w')".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });

        let findings = OverbroadFsDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-015");
        assert!(findings[0].taint_path.is_some());
    }
}
