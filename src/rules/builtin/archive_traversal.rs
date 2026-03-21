use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-017: Archive Traversal (Zip Slip)
///
/// Detects extraction of archives without path validation, which can allow
/// writing files to arbitrary locations via crafted archive entries (CWE-22).
pub struct ArchiveTraversalDetector;

/// Archive extraction functions that are vulnerable without path validation.
const ARCHIVE_EXTRACT_FUNCTIONS: &[&str] = &[
    // Python
    "extractall",
    "extract_all",
    "unpack_archive",
    "ZipFile.extract",
    "TarFile.extract",
    // Node.js
    "unzipper",
    "adm-zip",
    "tar.extract",
    "decompress",
];

/// Content patterns to search for in source files.
const ARCHIVE_SOURCE_PATTERNS: &[&str] = &[
    ".extractall(",
    ".extract_all(",
    "unpack_archive(",
    "ZipFile.extract(",
    "TarFile.extract(",
    "tar.extract(",
];

/// Safe patterns that indicate proper path validation before extraction.
const SAFE_PATTERNS: &[&str] = &[
    "os.path.abspath",
    "os.path.realpath",
    "os.path.commonpath",
    "startswith(",
    "path.resolve",
    "path.normalize",
    "sanitize",
    "validate",
];

/// Check if a function name matches an archive extraction function.
fn is_archive_extract(function: &str) -> bool {
    let func_lower = function.to_lowercase();
    ARCHIVE_EXTRACT_FUNCTIONS
        .iter()
        .any(|f| func_lower.contains(&f.to_lowercase()))
}

impl Detector for ArchiveTraversalDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-017".into(),
            name: "Archive Traversal (Zip Slip)".into(),
            description: "Archive extraction without path validation could allow writing \
                          files to arbitrary locations via crafted archive entries"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::ArbitraryFileAccess,
            cwe_id: Some("CWE-22".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Check dynamic_exec and commands for archive extraction functions
        for dyn_exec in &target.execution.dynamic_exec {
            if is_archive_extract(&dyn_exec.function) && dyn_exec.code_arg.is_tainted() {
                findings.push(Finding {
                    rule_id: "SHIELD-017".into(),
                    rule_name: "Archive Traversal (Zip Slip)".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::ArbitraryFileAccess,
                    message: format!(
                        "'{}' extracts archive with untrusted input — vulnerable to \
                         Zip Slip path traversal",
                        dyn_exec.function
                    ),
                    location: Some(dyn_exec.location.clone()),
                    evidence: vec![Evidence {
                        description: format!(
                            "Archive extraction via '{}' with tainted argument",
                            dyn_exec.function
                        ),
                        location: Some(dyn_exec.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Validate each extracted file's path before writing. Check that \
                         the resolved destination stays within the intended directory \
                         using `os.path.commonpath()` or equivalent. Reject entries with \
                         '..' or absolute paths."
                            .into(),
                    ),
                    cwe_id: Some("CWE-22".into()),
                });
            }
        }

        for cmd in &target.execution.commands {
            if is_archive_extract(&cmd.function) && cmd.command_arg.is_tainted() {
                findings.push(Finding {
                    rule_id: "SHIELD-017".into(),
                    rule_name: "Archive Traversal (Zip Slip)".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::ArbitraryFileAccess,
                    message: format!(
                        "'{}' extracts archive with untrusted input — vulnerable to \
                         Zip Slip path traversal",
                        cmd.function
                    ),
                    location: Some(cmd.location.clone()),
                    evidence: vec![Evidence {
                        description: format!(
                            "Archive extraction via '{}' with tainted argument",
                            cmd.function
                        ),
                        location: Some(cmd.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Validate each extracted file's path before writing. Check that \
                         the resolved destination stays within the intended directory. \
                         Reject entries with '..' or absolute paths."
                            .into(),
                    ),
                    cwe_id: Some("CWE-22".into()),
                });
            }
        }

        // Phase 2: Scan source files for archive extraction patterns without
        // nearby path validation.
        for source_file in &target.source_files {
            let lines: Vec<&str> = source_file.content.lines().collect();

            for (line_idx, line) in lines.iter().enumerate() {
                let has_extract = ARCHIVE_SOURCE_PATTERNS.iter().any(|p| line.contains(p));

                if !has_extract {
                    continue;
                }

                // Check surrounding context (5 lines before and after) for
                // path validation.
                let start = line_idx.saturating_sub(5);
                let end = (line_idx + 6).min(lines.len());
                let context = &lines[start..end];

                let has_validation = context
                    .iter()
                    .any(|l| SAFE_PATTERNS.iter().any(|p| l.contains(p)));

                if !has_validation {
                    findings.push(Finding {
                        rule_id: "SHIELD-017".into(),
                        rule_name: "Archive Traversal (Zip Slip)".into(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::ArbitraryFileAccess,
                        message: format!(
                            "Archive extraction without path validation in {} — \
                             vulnerable to Zip Slip",
                            source_file.path.display()
                        ),
                        location: Some(crate::ir::SourceLocation {
                            file: source_file.path.clone(),
                            line: line_idx + 1,
                            column: 0,
                            end_line: None,
                            end_column: None,
                        }),
                        evidence: vec![Evidence {
                            description: "Archive extraction without path validation".into(),
                            location: Some(crate::ir::SourceLocation {
                                file: source_file.path.clone(),
                                line: line_idx + 1,
                                column: 0,
                                end_line: None,
                                end_column: None,
                            }),
                            snippet: Some(line.trim().to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Validate each extracted file's destination path using \
                             `os.path.commonpath()` or `os.path.realpath()`. Reject \
                             entries containing '..' or absolute paths."
                                .into(),
                        ),
                        cwe_id: Some("CWE-22".into()),
                    });
                }
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
    fn detects_extractall_in_source() {
        let mut target = empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("extract.py"),
            language: Language::Python,
            content: "import zipfile\nz = zipfile.ZipFile(path)\nz.extractall('/tmp')\n".into(),
            size_bytes: 60,
            content_hash: "abc".into(),
        });

        let findings = ArchiveTraversalDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-017");
        assert!(findings[0].message.contains("Zip Slip"));
    }

    #[test]
    fn no_finding_when_path_validated() {
        let mut target = empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("safe_extract.py"),
            language: Language::Python,
            content: "import zipfile, os\n\
                z = zipfile.ZipFile(path)\n\
                dest = os.path.realpath(target_dir)\n\
                z.extractall(dest)\n"
                .into(),
            size_bytes: 80,
            content_hash: "abc".into(),
        });

        let findings = ArchiveTraversalDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_tainted_extract_in_dynamic_exec() {
        let mut target = empty_target();
        target.execution.dynamic_exec.push(DynamicExec {
            function: "zipfile.extractall".into(),
            code_arg: ArgumentSource::Parameter {
                name: "archive_path".into(),
            },
            location: loc(),
        });

        let findings = ArchiveTraversalDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn no_finding_for_sanitized_extract() {
        let mut target = empty_target();
        target.execution.dynamic_exec.push(DynamicExec {
            function: "zipfile.extractall".into(),
            code_arg: ArgumentSource::Sanitized {
                sanitizer: "validate_path".into(),
            },
            location: loc(),
        });

        let findings = ArchiveTraversalDetector.run(&target);
        assert!(findings.is_empty());
    }
}
