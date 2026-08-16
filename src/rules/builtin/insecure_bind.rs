use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-024: Insecure Network Bind (Unauthenticated Local MCP Network Exposure)
///
/// Detects MCP servers, agent transports, or tool backends that bind to public
/// network interfaces (0.0.0.0 or ::) without explicit authentication (CWE-1327 / CWE-306).
pub struct InsecureBindDetector;

// Regex matching Python wildcard or open host binding
static PY_INSECURE_BIND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # Named parameter: host="0.0.0.0" or bind="0.0.0.0"
            (?:host|bind|address|listen)\s*=\s*["'](?:0\.0\.0\.0|::|all)["']|

            # FastMCP / Starlette / Uvicorn call with "0.0.0.0"
            (?:mcp\.run|uvicorn\.run|app\.run|serve|start_server|run_server|server\.listen)\s*\([^)]*["']0\.0\.0\.0["']
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

// Regex matching TypeScript / JavaScript wildcard host binding
static TS_INSECURE_BIND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # Property: host: "0.0.0.0" or address: "0.0.0.0"
            (?:host|address|bind|hostname)\s*:\s*["'](?:0\.0\.0\.0|::)["']|

            # Express / Fastify / Node http listen: app.listen(port, "0.0.0.0")
            \.(?:listen|bind)\s*\([^)]*["']0\.0\.0\.0["']
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

impl Detector for InsecureBindDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-024".into(),
            name: "Insecure Network Bind".into(),
            description: "MCP or agent server listening on 0.0.0.0 or wildcard interface without authentication"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::ExcessivePermissions,
            cwe_id: Some("CWE-1327".into()),
            owasp_mcp: Some(OwaspMcp::InsecureCommunication),
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

                        if PY_INSECURE_BIND_RE.is_match(line) {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-024".into(),
                                rule_name: "Insecure Network Bind".into(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::ExcessivePermissions,
                                message: format!(
                                    "Server in '{}' binds to wildcard interface (0.0.0.0) at line {}",
                                    source.path.display(),
                                    line_idx + 1
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Server transport configured with wildcard interface '0.0.0.0'".into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Bind local MCP tools exclusively to localhost (127.0.0.1) or enforce strict bearer authentication and network authorization when exposing on public interfaces."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-1327".into()),
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

                        if TS_INSECURE_BIND_RE.is_match(line) {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-024".into(),
                                rule_name: "Insecure Network Bind".into(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::ExcessivePermissions,
                                message: format!(
                                    "Server in '{}' binds to wildcard interface (0.0.0.0) at line {}",
                                    source.path.display(),
                                    line_idx + 1
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Server transport configured with wildcard interface '0.0.0.0'".into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Bind local MCP tools exclusively to localhost (127.0.0.1) or enforce strict bearer authentication and network authorization when exposing on public interfaces."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-1327".into()),
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
            name: "test_insecure_bind_target".into(),
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
    fn detects_python_fastmcp_insecure_bind() {
        let code = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-server")

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
"#;
        let target = make_target(vec![("server.py", Language::Python, code)]);
        let detector = InsecureBindDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-024");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_python_uvicorn_insecure_bind() {
        let code = r#"
import uvicorn

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=3000)
"#;
        let target = make_target(vec![("app.py", Language::Python, code)]);
        let detector = InsecureBindDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-024");
    }

    #[test]
    fn detects_typescript_insecure_bind() {
        let code = r#"
import express from 'express';
const app = express();

app.listen(3000, "0.0.0.0", () => {
    console.log("Server listening on 0.0.0.0:3000");
});
"#;
        let target = make_target(vec![("server.ts", Language::TypeScript, code)]);
        let detector = InsecureBindDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-024");
    }

    #[test]
    fn allows_safe_localhost_binding() {
        let code = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-server")

if __name__ == "__main__":
    mcp.run(transport="sse", host="127.0.0.1", port=8000)
"#;
        let target = make_target(vec![("safe.py", Language::Python, code)]);
        let detector = InsecureBindDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }
}
