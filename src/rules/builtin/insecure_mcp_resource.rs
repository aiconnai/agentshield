use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-032: Insecure MCP Resource URI Path Traversal / Resource Tampering
///
/// Detects MCP resource URI templates or resource handlers that construct local filesystem
/// paths from unvalidated URI parameters or raw path templates without path confinement
/// checks (CWE-22 / OWASP MCP02 & MCP06).
pub struct InsecureMcpResourceDetector;

static PY_RESOURCE_DECORATOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)@(?:mcp|server|app)\.resource\s*\(\s*["'`]([^"'`]*\{[^"'`]+\}[^"'`]*)["'`]"#)
        .expect("valid python resource decorator regex")
});

static PY_UNCONFINED_FILE_READ_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:with\s+)?open\s*\(\s*(?:f?["'`][^"'`]*\{(\w+)\}[^"'`]*["'`]|(\w+)|os\.path\.join\([^)]*(\w+)[^)]*\))\s*[,)]"#)
        .expect("valid python unconfined file read regex")
});

static TS_RESOURCE_TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:new\s+ResourceTemplate\s*\(\s*["'`]([^"'`]*\{[^"'`]+\}[^"'`]*)["'`]|server\.resource\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*new\s+ResourceTemplate)"#)
        .expect("valid ts resource template regex")
});

static TS_UNCONFINED_FS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*(?:path\.join\([^)]*|uri\.pathname|uri\.replace\([^)]*\)|new\s+URL\(uri\)\.pathname|decodeURIComponent\([^)]*\)|`[^`]*\$\{[^}]+\}[^`]*`)"#)
        .expect("valid ts unconfined fs regex")
});

static TS_READ_RESOURCE_HANDLER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)server\.setRequestHandler\s*\(\s*ReadResourceRequestSchema\s*,"#)
        .expect("valid ts read resource handler regex")
});

static PATH_CONFINEMENT_GUARD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:validate_path|realpath|path_is_safe|is_safe_path|is_relative_to|startsWith\s*\(|startsWith\s*\(\s*root|resolve\([^)]*\)\.startsWith|indexOf\s*\(\s*root\)\s*===?\s*0|commonpath|commonprefix)"#)
        .expect("valid path confinement guard regex")
});

impl Detector for InsecureMcpResourceDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-032".into(),
            name: "Insecure MCP Resource URI Path Traversal / Resource Tampering".into(),
            description: "MCP resource URI templates or handlers that construct local filesystem paths from unvalidated URI parameters without path confinement checks, allowing arbitrary file read or resource tampering".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::ArbitraryFileAccess,
            cwe_id: Some("CWE-22".into()),
            owasp_mcp: Some(OwaspMcp::ExcessiveScope),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &target.source_files {
            match source.language {
                Language::Python => {
                    findings.extend(scan_python_resources(source.path.as_path(), &source.content));
                }
                Language::TypeScript | Language::JavaScript => {
                    findings.extend(scan_ts_resources(source.path.as_path(), &source.content));
                }
                _ => {}
            }
        }

        findings
    }
}

fn scan_python_resources(file_path: &std::path::Path, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        if let Some(cap) = PY_RESOURCE_DECORATOR_RE.captures(line) {
            let uri_template = cap[1].to_string();
            let start_line = idx + 1;

            // Lookahead 30 lines inside the resource handler function
            let window_end = (idx + 30).min(lines.len());
            let handler_window = lines[idx..window_end].join("\n");

            let has_guard = PATH_CONFINEMENT_GUARD_RE.is_match(&handler_window);
            if !has_guard && PY_UNCONFINED_FILE_READ_RE.is_match(&handler_window) {
                let loc = Some(SourceLocation {
                    file: file_path.to_path_buf(),
                    line: start_line,
                    column: 0,
                    end_line: Some(start_line),
                    end_column: None,
                });

                findings.push(Finding {
                    rule_id: "SHIELD-032".into(),
                    rule_name: "Insecure MCP Resource URI Path Traversal / Resource Tampering".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::ArbitraryFileAccess,
                    message: format!(
                        "MCP resource URI template \"{}\" reads files directly from URI parameters without path confinement validation",
                        uri_template
                    ),
                    location: loc.clone(),
                    evidence: vec![Evidence {
                        description: format!("Resource template '{}' accesses filesystem without confinement validation", uri_template),
                        location: loc,
                        snippet: Some(line.to_string()),
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Validate that the resolved resource file path is strictly confined within an authorized root directory (e.g. using `os.path.realpath` and `os.path.commonpath` or `path.is_relative_to(root)`).".into(),
                    ),
                    cwe_id: Some("CWE-22".into()),
                });
            }
        }
    }

    findings
}

fn scan_ts_resources(file_path: &std::path::Path, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let is_template = TS_RESOURCE_TEMPLATE_RE.is_match(line);
        let is_read_handler = TS_READ_RESOURCE_HANDLER_RE.is_match(line);

        if is_template || is_read_handler {
            let start_line = idx + 1;
            let window_end = (idx + 35).min(lines.len());
            let handler_window = lines[idx..window_end].join("\n");

            let has_guard = PATH_CONFINEMENT_GUARD_RE.is_match(&handler_window);
            if !has_guard && TS_UNCONFINED_FS_RE.is_match(&handler_window) {
                let loc = Some(SourceLocation {
                    file: file_path.to_path_buf(),
                    line: start_line,
                    column: 0,
                    end_line: Some(start_line),
                    end_column: None,
                });

                findings.push(Finding {
                    rule_id: "SHIELD-032".into(),
                    rule_name: "Insecure MCP Resource URI Path Traversal / Resource Tampering".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::ArbitraryFileAccess,
                    message: "MCP Resource handler reads filesystem paths from request URI without path confinement checks".into(),
                    location: loc.clone(),
                    evidence: vec![Evidence {
                        description: "Resource handler performs filesystem operation on unvalidated URI parameter".into(),
                        location: loc,
                        snippet: Some(line.to_string()),
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Ensure the resolved path stays within an allowed base directory using `path.resolve(baseDir, userInput).startsWith(baseDir)` before invoking `fs.readFile`.".into(),
                    ),
                    cwe_id: Some("CWE-22".into()),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Framework, SourceFile};
    use std::path::PathBuf;

    fn target_with_source(lang: Language, content: &str) -> ScanTarget {
        ScanTarget {
            name: "test-mcp".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from(if lang == Language::Python {
                    "/test/server.py"
                } else {
                    "/test/server.ts"
                }),
                language: lang,
                content: content.into(),
                size_bytes: content.len() as u64,
                content_hash: "test".into(),
            }],
        }
    }

    #[test]
    fn detects_insecure_python_mcp_resource() {
        let py_code = r#"
@mcp.resource("file://{path}")
def read_log(path: str) -> str:
    with open(f"/var/log/{path}") as f:
        return f.read()
"#;
        let target = target_with_source(Language::Python, py_code);
        let detector = InsecureMcpResourceDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-032");
        assert!(findings[0].message.contains("file://{path}"));
    }

    #[test]
    fn ignores_safe_python_mcp_resource_with_guard() {
        let py_code = r#"
@mcp.resource("file://{path}")
def read_log(path: str) -> str:
    safe = validate_path(path)
    with open(safe) as f:
        return f.read()
"#;
        let target = target_with_source(Language::Python, py_code);
        let detector = InsecureMcpResourceDetector;
        let findings = detector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_insecure_ts_mcp_resource() {
        let ts_code = r#"
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    const content = fs.readFileSync(new URL(uri).pathname, "utf-8");
    return { contents: [{ uri, text: content }] };
});
"#;
        let target = target_with_source(Language::TypeScript, ts_code);
        let detector = InsecureMcpResourceDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-032");
    }
}
