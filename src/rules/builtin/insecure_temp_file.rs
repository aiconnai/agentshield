use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-025: Insecure Temporary File Creation
///
/// Detects insecure temporary file creation in shared system directories (/tmp, /var/tmp)
/// and use of deprecated/insecure APIs like `tempfile.mktemp()` subject to race conditions
/// and symlink attacks (CWE-377 / CWE-378).
pub struct InsecureTempFileDetector;

// Regex matching Python insecure temporary file usage
static PY_INSECURE_TEMP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # Deprecated and insecure mktemp()
            tempfile\.mktemp\s*\(|

            # Hardcoded or formatted paths directly into /tmp or /var/tmp
            (?:open|Path|pathlib\.Path)\s*\(\s*(?:f?["']/(?:tmp|var/tmp)/|os\.path\.join\s*\(\s*["']/(?:tmp|var/tmp)["'])
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

// Regex matching TypeScript / JavaScript insecure temporary file usage
static TS_INSECURE_TEMP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # fs write or stream directly targeting /tmp/ or /var/tmp/
            (?:fs\.(?:writeFileSync|writeFile|createWriteStream|appendFileSync))\s*\(\s*["'`]/(?:tmp|var/tmp)/|

            # path.join or path.resolve targeting /tmp
            path\.(?:join|resolve)\s*\(\s*["']/(?:tmp|var/tmp)["']
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

impl Detector for InsecureTempFileDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-025".into(),
            name: "Insecure Temporary File Creation".into(),
            description: "Insecure creation of temporary files in shared directories without atomic permissions"
                .into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::ArbitraryFileAccess,
            cwe_id: Some("CWE-377".into()),
            owasp_mcp: Some(OwaspMcp::ExcessiveScope),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &target.source_files {
            match source.language {
                Language::Python => {
                    for (line_idx, line) in source.content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') {
                            continue;
                        }

                        if PY_INSECURE_TEMP_RE.is_match(line) {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-025".into(),
                                rule_name: "Insecure Temporary File Creation".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::ArbitraryFileAccess,
                                message: format!(
                                    "Insecure temporary file creation detected in '{}' at line {}",
                                    source.path.display(),
                                    line_idx + 1
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Predictable shared directory (/tmp) or insecure tempfile.mktemp() usage".into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Use 'tempfile.NamedTemporaryFile()', 'tempfile.TemporaryDirectory()', or secure temp directories with strict mode (0600) instead of predictable /tmp paths or 'tempfile.mktemp()'."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-377".into()),
                            });
                        }
                    }
                }
                Language::TypeScript | Language::JavaScript => {
                    for (line_idx, line) in source.content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("//") || trimmed.starts_with('*') {
                            continue;
                        }

                        if TS_INSECURE_TEMP_RE.is_match(line) {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-025".into(),
                                rule_name: "Insecure Temporary File Creation".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::ArbitraryFileAccess,
                                message: format!(
                                    "Insecure temporary file creation detected in '{}' at line {}",
                                    source.path.display(),
                                    line_idx + 1
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Predictable shared directory (/tmp) file write detected".into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Use 'fs.mkdtempSync()' or unique cryptographic prefixes inside dedicated per-user temporary directories instead of static /tmp paths."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-377".into()),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        DataSurface, DependencySurface, ExecutionSurface, Framework, ProvenanceSurface, SourceFile,
    };
    use std::path::PathBuf;

    fn make_target(files: Vec<(&str, Language, &str)>) -> ScanTarget {
        ScanTarget {
            name: "test_insecure_temp_target".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: ExecutionSurface::default(),
            data: DataSurface::default(),
            dependencies: DependencySurface::default(),
            provenance: ProvenanceSurface::default(),
            source_files: files
                .into_iter()
                .map(|(path, lang, content)| SourceFile {
                    path: PathBuf::from(path),
                    language: lang,
                    content: content.into(),
                    size_bytes: content.len() as u64,
                    content_hash: "hash".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn detects_python_mktemp_usage() {
        let code = r#"
import tempfile

def save_payload(data):
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write(data)
"#;
        let target = make_target(vec![("handler.py", Language::Python, code)]);
        let detector = InsecureTempFileDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-025");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn detects_python_predictable_tmp_file() {
        let code = r#"
def dump_output(job_id, result):
    with open(f"/tmp/agent_job_{job_id}.json", "w") as f:
        f.write(result)
"#;
        let target = make_target(vec![("exporter.py", Language::Python, code)]);
        let detector = InsecureTempFileDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-025");
    }

    #[test]
    fn detects_typescript_predictable_tmp_file() {
        let code = r#"
import fs from 'fs';

export function cacheResult(content: string) {
    fs.writeFileSync("/tmp/cached_mcp_output.txt", content);
}
"#;
        let target = make_target(vec![("cache.ts", Language::TypeScript, code)]);
        let detector = InsecureTempFileDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-025");
    }

    #[test]
    fn allows_secure_named_temporary_file() {
        let code = r#"
import tempfile

def safe_save(data):
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(data)
        return f.name
"#;
        let target = make_target(vec![("safe.py", Language::Python, code)]);
        let detector = InsecureTempFileDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }
}
