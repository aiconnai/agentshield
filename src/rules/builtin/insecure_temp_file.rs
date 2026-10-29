use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

use super::source_scan::{SourceLang, full_line_location, scan_py_ts_regex_matches};

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

        scan_py_ts_regex_matches(
            target,
            &PY_INSECURE_TEMP_RE,
            &TS_INSECURE_TEMP_RE,
            |source, lang, line_idx, line, _mat| {
                let loc = full_line_location(source, line_idx, line);
                let (description, remediation) = match lang {
                    SourceLang::Python => (
                        "Predictable shared directory (/tmp) or insecure tempfile.mktemp() usage",
                        "Use 'tempfile.NamedTemporaryFile()', 'tempfile.TemporaryDirectory()', or secure temp directories with strict mode (0600) instead of predictable /tmp paths or 'tempfile.mktemp()'.",
                    ),
                    SourceLang::TypeScriptOrJs => (
                        "Predictable shared directory (/tmp) file write detected",
                        "Use 'fs.mkdtempSync()' or unique cryptographic prefixes inside dedicated per-user temporary directories instead of static /tmp paths.",
                    ),
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
                        description: description.into(),
                        location: Some(loc),
                        snippet: Some(line.trim().to_string()),
                    }],
                    taint_path: None,
                    remediation: Some(remediation.into()),
                    cwe_id: Some("CWE-377".into()),
                });
            },
        );

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::make_target_from_files as make_target;
    use super::*;
    use crate::ir::Language;

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
