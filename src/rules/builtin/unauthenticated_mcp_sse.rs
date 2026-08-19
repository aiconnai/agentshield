use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-035: Unauthenticated MCP SSE Transport / Missing Origin Validation
///
/// Detects MCP servers exposing Server-Sent Events (SSE) or HTTP transports (`SSEServerTransport`, `/sse`, `/messages`)
/// without validating the `Origin` header or requiring authentication tokens (CWE-346, CWE-306).
pub struct UnauthenticatedMcpSseDetector;

// Matches SSEServerTransport instantiation or import in TypeScript/JavaScript
static TS_SSE_TRANSPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\bnew\s+SSEServerTransport\s*\("#).expect("valid regex")
});

// Matches wildcard CORS in MCP transport files (applied to multi-line context windows).
// Three forms are covered:
//   1. cors({ origin: '*' }) — single-line object literal
//   2. origin: '*' — standalone property line in a multiline cors() config
//   3. setHeader / header('Access-Control-Allow-Origin', '*') — explicit header assignment
// Template-literal backtick values (e.g. origin: `*`) are also caught via [`'"`].
static WILDCARD_CORS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)(?:cors\s*\(\s*\{\s*origin\s*:\s*[`'"]\*[`'"]|(?:^|\s)origin\s*:\s*[`'"]\*[`'"]|Access-Control-Allow-Origin[`'"]?\s*,\s*[`'"]\*[`'"])"#)
        .expect("valid regex")
});

// Checks if explicit origin or auth verification exists within proximity (applied to multi-line context windows)
static ORIGIN_AUTH_GUARD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:authorization|bearer|validate_origin|check_origin|allowed_origins|auth_token|req\.headers\.origin|req\.headers\[['"]origin['"]\]|request\.headers\.get\(['"]origin['"]\)|headers\.get\(['"]origin['"]\)|origin\s*(?:===|==|!==|!=|\.includes|\.indexOf|in\b))\b"#)
        .expect("valid regex")
});

// Matches Python FastMCP or Starlette SSE transport run start
static PY_MCP_RUN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:mcp\.run\s*\(|SSEServerTransport\s*\()"#).expect("valid regex")
});

static PY_TRANSPORT_SSE_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches both legacy 'sse' and the newer 'streamable-http' transport (MCP SDK ≥ 1.2),
    // which carries the same unauthenticated origin risk as SSE.
    Regex::new(r#"transport\s*=\s*['"](?:sse|streamable-http)['"]|SSEServerTransport"#)
        .expect("valid regex")
});

impl Detector for UnauthenticatedMcpSseDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-035".into(),
            name: "Unauthenticated MCP SSE Transport / Missing Origin Validation".into(),
            description: "MCP Server-Sent Events (SSE) or HTTP endpoints exposed without \
                          Origin validation or authentication headers, enabling cross-site hijacking"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::ExcessivePermissions,
            cwe_id: Some("CWE-346".into()),
            owasp_mcp: Some(OwaspMcp::InsecureCommunication),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &target.source_files {
            let lines: Vec<&str> = file.content.lines().collect();

            match file.language {
                Language::TypeScript | Language::JavaScript => {
                    // Pre-check: only scan for CORS issues if this file actually uses
                    // SSEServerTransport. Wildcard CORS in a plain REST API file must
                    // not trigger SHIELD-035.
                    let file_has_sse = lines.iter().any(|l| TS_SSE_TRANSPORT_RE.is_match(l));

                    // Check for SSEServerTransport usage without Origin validation
                    for (line_idx, line) in lines.iter().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("//") || trimmed.starts_with('*') {
                            continue;
                        }

                        if TS_SSE_TRANSPORT_RE.is_match(line) {
                            // Lookahead and lookbehind window of 35 lines for origin / auth verification
                            let start_idx = line_idx.saturating_sub(15);
                            let end_idx = (line_idx + 35).min(lines.len());
                            let context_window = lines[start_idx..end_idx].join("\n");

                            let has_origin_guard = ORIGIN_AUTH_GUARD_RE.is_match(&context_window);

                            if !has_origin_guard {
                                let loc = SourceLocation {
                                    file: file.path.clone(),
                                    line: line_idx + 1,
                                    column: line.find("SSEServerTransport").unwrap_or(0),
                                    end_line: None,
                                    end_column: None,
                                };

                                findings.push(Finding {
                                    rule_id: "SHIELD-035".into(),
                                    rule_name: "Unauthenticated MCP SSE Transport / Missing Origin Validation".into(),
                                    severity: Severity::High,
                                    confidence: Confidence::Medium,
                                    attack_category: AttackCategory::ExcessivePermissions,
                                    message: "MCP `SSEServerTransport` endpoint instantiated without `Origin` header validation or authentication — susceptible to Cross-Site SSE Hijacking and unauthorized tool invocation".into(),
                                    location: Some(loc.clone()),
                                    evidence: vec![Evidence {
                                        description: "SSEServerTransport without Origin or Bearer verification".into(),
                                        location: Some(loc),
                                        snippet: Some(trimmed.to_string()),
                                    }],
                                    taint_path: None,
                                    remediation: Some(
                                        "Validate the `Origin` header against an explicit allowlist (e.g. check `req.headers.origin`) or require Bearer token authentication in HTTP/SSE middleware.".into(),
                                    ),
                                    cwe_id: Some("CWE-346".into()),
                                });
                            }
                        }

                        // Check for wildcard CORS — only when this file also exposes SSE transport,
                        // to avoid false-positives in unrelated REST API files.
                        if file_has_sse && WILDCARD_CORS_RE.is_match(line) {

                            let loc = SourceLocation {
                                file: file.path.clone(),
                                line: line_idx + 1,
                                column: 0,
                                end_line: None,
                                end_column: None,
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-035".into(),
                                rule_name: "Unauthenticated MCP SSE Transport / Missing Origin Validation".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::ExcessivePermissions,
                                message: "Wildcard CORS (`origin: '*'`) configured on MCP server endpoint — allows arbitrary web pages to access SSE streams".into(),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Wildcard CORS configuration on MCP endpoint".into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Restrict CORS `origin` to trusted domains or localhost rather than wildcard `*`.".into(),
                                ),
                                cwe_id: Some("CWE-346".into()),
                            });
                        }
                    }
                }
                Language::Python => {
                    for (line_idx, line) in lines.iter().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') {
                            continue;
                        }

                        if PY_MCP_RUN_RE.is_match(line) {
                            let end_run_idx = (line_idx + 10).min(lines.len());
                            let run_window = lines[line_idx..end_run_idx].join("\n");

                            if PY_TRANSPORT_SSE_RE.is_match(&run_window) {
                                let start_idx = line_idx.saturating_sub(15);
                                let end_idx = (line_idx + 35).min(lines.len());
                                let context_window = lines[start_idx..end_idx].join("\n");

                                let has_origin_guard = ORIGIN_AUTH_GUARD_RE.is_match(&context_window);

                                if !has_origin_guard {
                                    let loc = SourceLocation {
                                        file: file.path.clone(),
                                        line: line_idx + 1,
                                        column: 0,
                                        end_line: None,
                                        end_column: None,
                                    };

                                    findings.push(Finding {
                                        rule_id: "SHIELD-035".into(),
                                        rule_name: "Unauthenticated MCP SSE Transport / Missing Origin Validation".into(),
                                        severity: Severity::High,
                                        confidence: Confidence::Medium,
                                        attack_category: AttackCategory::ExcessivePermissions,
                                        message: "Python MCP SSE transport run without `Origin` verification or authentication middleware".into(),
                                        location: Some(loc.clone()),
                                        evidence: vec![Evidence {
                                            description: "MCP SSE transport without Origin guard".into(),
                                            location: Some(loc),
                                            snippet: Some(trimmed.to_string()),
                                        }],
                                        taint_path: None,
                                        remediation: Some(
                                            "Validate request `Origin` headers or enforce authentication tokens on SSE transport routes.".into(),
                                        ),
                                        cwe_id: Some("CWE-346".into()),
                                    });
                                }
                            }
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
    use crate::ir::{Framework, SourceFile};
    use std::path::PathBuf;

    fn target_with_source(code: &str, lang: Language) -> ScanTarget {
        ScanTarget {
            name: "test-sse-server".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from(if lang == Language::Python {
                    "server.py"
                } else if lang == Language::JavaScript {
                    "server.js"
                } else {
                    "server.ts"
                }),
                language: lang,
                size_bytes: code.len() as u64,
                content_hash: "hash".into(),
                content: code.into(),
            }],
        }
    }

    #[test]
    fn detects_unauthenticated_ts_sse_transport() {
        let code = r#"
import express from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

const app = express();

app.get("/sse", async (req, res) => {
    const transport = new SSEServerTransport("/messages", res);
    await server.connect(transport);
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = UnauthenticatedMcpSseDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-035");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_unauthenticated_js_sse_transport() {
        let code = r#"
const express = require("express");
const { SSEServerTransport } = require("@modelcontextprotocol/sdk/server/sse.js");

const app = express();

app.get("/sse", async (req, res) => {
    const transport = new SSEServerTransport("/messages", res);
    await server.connect(transport);
});
"#;
        let target = target_with_source(code, Language::JavaScript);
        let detector = UnauthenticatedMcpSseDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-035");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn ignores_ts_sse_with_origin_validation() {
        let code = r#"
import express from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

const app = express();

app.get("/sse", async (req, res) => {
    const origin = req.headers.origin;
    if (origin !== "https://trusted.app") {
        return res.status(403).send("Forbidden origin");
    }
    const transport = new SSEServerTransport("/messages", res);
    await server.connect(transport);
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = UnauthenticatedMcpSseDetector;
        let findings = detector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_wildcard_cors_and_unauthenticated_sse_together() {
        let code = r#"
import cors from "cors";
import express from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

const app = express();
app.use(cors({ origin: "*" }));

app.get("/sse", async (req, res) => {
    const transport = new SSEServerTransport("/messages", res);
    await server.connect(transport);
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = UnauthenticatedMcpSseDetector;
        let findings = detector.run(&target);
        // Emits both: wildcard CORS (Medium) and missing origin check on transport (High)
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn detects_unauthenticated_python_multiline_sse() {
        let code = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")
mcp.run(
    transport="sse",
    host="0.0.0.0"
)
"#;
        let target = target_with_source(code, Language::Python);
        let detector = UnauthenticatedMcpSseDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn wildcard_cors_in_non_sse_file_does_not_trigger() {
        // CORS wildcard in a plain REST API file with no SSEServerTransport must not
        // produce a SHIELD-035 finding — it is unrelated to MCP SSE transport.
        let code = r#"
import cors from "cors";
import express from "express";

const app = express();
app.use(cors({ origin: "*" }));

app.get("/api/data", (req, res) => {
    res.json({ data: "ok" });
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = UnauthenticatedMcpSseDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "wildcard CORS in a non-SSE file must not trigger SHIELD-035; got: {findings:#?}"
        );
    }
}
