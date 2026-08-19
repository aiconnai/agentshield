use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-036: Tool Response Prompt Injection / Unsanitized Parameter Reflection
///
/// Detects MCP tool handler functions that directly interpolate untrusted parameters
/// into their return value without sanitization or escaping, enabling an attacker who
/// controls tool inputs to inject arbitrary instructions into the downstream LLM prompt
/// (CWE-1336, OWASP MCP PromptInjection).
///
/// Covered patterns:
///   Python  — `@mcp.tool` / `@tool` decorated functions whose `return` statement
///             uses an f-string, `.format()`, `%`-formatting, or string concatenation
///             of a parameter variable.
///   TS/JS   — Functions registered via `.tool(` / `.addTool(` / `server.tool(` whose
///             body contains a template-literal or string-concatenation `return`.
pub struct ToolResponseInjectionDetector;

// ── Python statics (applied per-line; no (?m) flag) ───────────────────────────

// Matches @mcp.tool, @tool, @server.tool, @app.tool decorator lines
static PY_TOOL_DECORATOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*@(?:\w+\.)*tool\b"#).expect("valid regex")
});

// Matches `def <name>(` where <name> contains a tool-related keyword
static PY_TOOL_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^\s*(?:async\s+)?def\s+\w*(?:tool|handler|execute|process|handle|invoke)\w*\s*\("#,
    )
    .expect("valid regex")
});

// Matches any `def <name>(` — used to detect the function start after a decorator
static PY_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*(?:async\s+)?def\s+\w+\s*\("#).expect("valid regex")
});

// Matches `return f"...{var}..."` or `return f'...'` (f-string with at least one interpolation)
static PY_RETURN_FSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*return\s+f(?:"[^"]*\{[^}]+\}|'[^']*\{[^}]+\})"#).expect("valid regex")
});

// Matches `return "..." + var` or `return var + "..."` string concatenation
static PY_RETURN_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*return\s+(?:["'][^"']*["']\s*\+|\w+\s*\+\s*["'])"#).expect("valid regex")
});

// Matches `return "...".format(` or `return (...) % `
static PY_RETURN_FORMAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*return\s+(?:["'][^"']*["']|\w+)\s*(?:\.format\s*\(|%\s*[\w(])"#)
        .expect("valid regex")
});

// ── TypeScript / JavaScript statics (applied per-line; no (?m) flag) ──────────

// Matches tool registration: `.tool(`, `.addTool(`, `server.tool(`, `mcp.tool(`
static TS_TOOL_REGISTRATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:addTool|server\.tool|mcp\.tool|\.tool)\s*\("#).expect("valid regex")
});

// Matches template literal return with interpolation: return `...${...}...`
static TS_RETURN_TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*return\s+`[^`]*\$\{[^}]+\}"#).expect("valid regex")
});

// Matches string concatenation in return: return "..." + var or return var + "..."
static TS_RETURN_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*return\s+(?:["'][^"']*["']\s*\+|\w+\s*\+\s*["'])"#).expect("valid regex")
});

impl Detector for ToolResponseInjectionDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-036".into(),
            name: "Tool Response Prompt Injection / Unsanitized Parameter Reflection".into(),
            description: "MCP tool handler returns untrusted parameter values via f-string, \
                          template literal, or string concatenation without sanitization, enabling \
                          prompt injection into the downstream LLM conversation"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::PromptInjectionSurface,
            cwe_id: Some("CWE-1336".into()),
            owasp_mcp: Some(OwaspMcp::PromptInjection),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &target.source_files {
            let lines: Vec<&str> = file.content.lines().collect();

            match file.language {
                Language::Python => {
                    scan_python(&lines, file, &mut findings);
                }
                Language::TypeScript | Language::JavaScript => {
                    scan_ts_js(&lines, file, &mut findings);
                }
                _ => {}
            }
        }

        findings
    }
}

fn scan_python(
    lines: &[&str],
    file: &crate::ir::SourceFile,
    findings: &mut Vec<Finding>,
) {
    let mut in_tool_fn = false;
    let mut expecting_tool_def = false;
    let mut tool_fn_indent: usize = 0;

    for (line_idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let current_indent = line.len() - line.trim_start().len();

        if expecting_tool_def {
            if PY_DEF_RE.is_match(line) {
                in_tool_fn = true;
                expecting_tool_def = false;
                tool_fn_indent = current_indent;
                continue;
            }
        }

        if in_tool_fn && current_indent <= tool_fn_indent {
            in_tool_fn = false;
        }

        if !in_tool_fn {
            if PY_TOOL_DECORATOR_RE.is_match(line) {
                expecting_tool_def = true;
                continue;
            } else if PY_TOOL_DEF_RE.is_match(line) {
                in_tool_fn = true;
                tool_fn_indent = current_indent;
                continue;
            }
        }

        if in_tool_fn {
            let is_unsafe_return = PY_RETURN_FSTRING_RE.is_match(line)
                || PY_RETURN_CONCAT_RE.is_match(line)
                || PY_RETURN_FORMAT_RE.is_match(line);

            if is_unsafe_return {
                let col = line.find("return").unwrap_or(0);
                let loc = SourceLocation {
                    file: file.path.clone(),
                    line: line_idx + 1,
                    column: col,
                    end_line: None,
                    end_column: None,
                };
                findings.push(Finding {
                    rule_id: "SHIELD-036".into(),
                    rule_name: "Tool Response Prompt Injection / Unsanitized Parameter Reflection"
                        .into(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    attack_category: AttackCategory::PromptInjectionSurface,
                    message: "Tool handler returns an unsanitized parameter via string \
                              interpolation — an attacker controlling tool inputs can inject \
                              arbitrary instructions into the downstream LLM prompt"
                        .into(),
                    location: Some(loc.clone()),
                    evidence: vec![Evidence {
                        description: "Unsanitized return in tool handler".into(),
                        location: Some(loc),
                        snippet: Some(trimmed.to_string()),
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Sanitize or escape tool output before returning it. Consider wrapping \
                         the value in a structured JSON response, stripping control characters, \
                         or validating that output conforms to an expected schema."
                            .into(),
                    ),
                    cwe_id: Some("CWE-1336".into()),
                });
            }
        }
    }
}

fn scan_ts_js(
    lines: &[&str],
    file: &crate::ir::SourceFile,
    findings: &mut Vec<Finding>,
) {
    for (line_idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if TS_TOOL_REGISTRATION_RE.is_match(line) {
            // Scan the next 50 lines for template-literal or concat returns
            let end_idx = (line_idx + 50).min(lines.len());
            for (body_offset, &body_line) in lines[line_idx..end_idx].iter().enumerate() {
                let body_trimmed = body_line.trim();
                if body_trimmed.starts_with("//") {
                    continue;
                }

                let is_unsafe_return = TS_RETURN_TEMPLATE_RE.is_match(body_line)
                    || TS_RETURN_CONCAT_RE.is_match(body_line);

                if is_unsafe_return {
                    let col = body_line.find("return").unwrap_or(0);
                    let finding_line = line_idx + body_offset + 1;
                    let loc = SourceLocation {
                        file: file.path.clone(),
                        line: finding_line,
                        column: col,
                        end_line: None,
                        end_column: None,
                    };
                    findings.push(Finding {
                        rule_id: "SHIELD-036".into(),
                        rule_name:
                            "Tool Response Prompt Injection / Unsanitized Parameter Reflection"
                                .into(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::PromptInjectionSurface,
                        message: "Tool handler returns an unsanitized template literal or string \
                                  concatenation — an attacker controlling tool inputs can inject \
                                  arbitrary instructions into the downstream LLM prompt"
                            .into(),
                        location: Some(loc.clone()),
                        evidence: vec![Evidence {
                            description: "Unsanitized template-literal or concat return in tool"
                                .into(),
                            location: Some(loc),
                            snippet: Some(body_trimmed.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Sanitize tool output before returning it. Prefer structured JSON \
                             responses over raw string interpolation, or escape special characters \
                             before the value enters the LLM context."
                                .into(),
                        ),
                        cwe_id: Some("CWE-1336".into()),
                    });
                    // One finding per tool registration block
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Framework, Language, ScanTarget, SourceFile};
    use std::path::PathBuf;

    fn target_with_source(code: &str, language: Language) -> ScanTarget {
        ScanTarget {
            name: "test-tool-agent".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from(match language {
                    Language::Python => "tool.py",
                    Language::TypeScript => "tool.ts",
                    _ => "tool.js",
                }),
                language,
                size_bytes: code.len() as u64,
                content_hash: "hash".into(),
                content: code.to_string(),
            }],
        }
    }

    #[test]
    fn detects_python_fstring_return_in_mcp_tool() {
        let code = r#"
@mcp.tool
def search_database(query: str) -> str:
    results = db.search(query)
    return f"Search results for '{query}': {results}"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = ToolResponseInjectionDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for f-string return in @mcp.tool; got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-036");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn ignores_python_hardcoded_return_in_tool() {
        let code = r#"
@mcp.tool
def get_status() -> str:
    return "OK"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = ToolResponseInjectionDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "hardcoded return must not trigger SHIELD-036; got: {findings:#?}"
        );
    }

    #[test]
    fn detects_python_concat_return_in_tool_by_name() {
        let code = r#"
async def execute_query(query: str) -> str:
    result = db.run(query)
    return "Result: " + result
"#;
        let target = target_with_source(code, Language::Python);
        let detector = ToolResponseInjectionDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for concat return in tool-named function; got {}: {findings:#?}",
            findings.len()
        );
    }

    #[test]
    fn detects_ts_template_literal_return_in_tool() {
        let code = r#"
server.tool("search", async ({ query }) => {
    const results = await db.search(query);
    return `Found: ${results}`;
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = ToolResponseInjectionDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for template literal return; got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-036");
    }

    #[test]
    fn ignores_ts_hardcoded_return_in_tool() {
        let code = r#"
server.tool("ping", async () => {
    return "pong";
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = ToolResponseInjectionDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "hardcoded string return must not trigger SHIELD-036; got: {findings:#?}"
        );
    }

    #[test]
    fn ignores_non_tool_function_with_fstring() {
        // A regular Python helper (no tool decorator, no tool-related name) must not fire
        let code = r#"
def format_greeting(name: str) -> str:
    return f"Hello, {name}!"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = ToolResponseInjectionDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "non-tool function must not trigger SHIELD-036; got: {findings:#?}"
        );
    }
}
