use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-028: Untrusted Dynamic Tool Registration / Hot-Loading
///
/// Detects dynamic registration or execution of tool handlers fetched from remote URLs,
/// untrusted network endpoints, or unverified script sources at runtime without
/// integrity verification (CWE-829 / OWASP MCP09).
pub struct DynamicToolRegistrationDetector;

static PY_DYNAMIC_TOOL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Server tool registration wrapping dynamic exec/eval/importlib
            (?:server|mcp|app)\s*\.\s*(?:tool|add_tool|register_tool|custom_tool)\s*\(\s*(?:exec|eval|importlib|getattr|globals\(\)|locals\(\)|requests\.|urllib\.)|

            # 2. Dynamic execution of network responses or remote code
            (?:exec|eval)\s*\(\s*(?:requests\.|urllib\.|session\.|http\.|response\.(?:text|content)|res\.(?:text|content)|resp\.(?:text|content)|\b(?:downloaded_code|code|plugin_code|remote_code|script|tool_code|payload)\b)|

            # 3. Dynamic import from remote URLs or unverified variables inside tool handlers
            importlib\.import_module\s*\(\s*(?:requests\.|urllib\.|remote_module|url|untrusted_module)|

            # 4. Compiling and synthesizing bytecode dynamically from runtime strings
            types\.FunctionType\s*\(\s*compile\s*\(
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

static TS_DYNAMIC_TOOL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Server tool registration wrapping eval / new Function / vm execution
            (?:server|mcp|app)\s*\.\s*(?:tool|addTool|registerTool|customTool)\s*\(\s*(?:eval|new\s+Function|vm\.run|import\s*\()|

            # 2. Dynamic evaluation of fetched network payloads
            (?:eval|new\s+Function|vm\.runIn(?:New)?Context)\s*\(\s*(?:await\s+)?(?:fetch|axios|http|res\.text|response\.data|body|codePayload|\b(?:code|pluginCode|remoteCode|script|toolCode|payload)\b)|

            # 3. Dynamic ESM import of remote or variable URL endpoints
            import\s*\(\s*(?:`https?://|["']https?://|`[^`]*\$\{[^}]*(?:url|remote|host)[^}]*\}|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\))
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

impl Detector for DynamicToolRegistrationDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-028".into(),
            name: "Untrusted Dynamic Tool Registration / Hot-Loading".into(),
            description: "Dynamic registration or execution of tool handlers fetched from remote URLs, untrusted network endpoints, or unverified script sources at runtime without integrity verification"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::CodeInjection,
            cwe_id: Some("CWE-829".into()),
            owasp_mcp: Some(OwaspMcp::MaliciousUpdate),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &target.source_files {
            let is_python = source.language == Language::Python
                || source
                    .path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "py");
            let is_ts = matches!(source.language, Language::TypeScript | Language::JavaScript)
                || source
                    .path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| matches!(e, "ts" | "js" | "tsx" | "jsx" | "mjs"));

            for (line_idx, line) in source.content.lines().enumerate() {
                let trimmed = line.trim();

                // Skip full line comments
                if trimmed.starts_with('#')
                    || trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                {
                    continue;
                }

                let (matched, pattern_name) = if is_python {
                    if let Some(mat) = PY_DYNAMIC_TOOL_RE.find(line) {
                        (Some(mat), "Python dynamic tool loading pattern")
                    } else {
                        (None, "")
                    }
                } else if is_ts {
                    if let Some(mat) = TS_DYNAMIC_TOOL_RE.find(line) {
                        (Some(mat), "TypeScript dynamic tool loading pattern")
                    } else {
                        (None, "")
                    }
                } else {
                    (None, "")
                };

                if let Some(mat) = matched {
                    let loc = SourceLocation {
                        file: source.path.clone(),
                        line: line_idx + 1,
                        column: mat.start() + 1,
                        end_line: Some(line_idx + 1),
                        end_column: Some(mat.end() + 1),
                    };

                    findings.push(Finding {
                        rule_id: "SHIELD-028".into(),
                        rule_name: "Untrusted Dynamic Tool Registration / Hot-Loading".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CodeInjection,
                        message: format!(
                            "Dynamic registration or remote execution of tool handler detected in '{}': {}",
                            source.path.display(),
                            pattern_name
                        ),
                        location: Some(loc.clone()),
                        evidence: vec![Evidence {
                            description: format!("Matches dynamic execution sink in {}", pattern_name),
                            location: Some(loc),
                            snippet: Some(line.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Avoid hot-loading or compiling tools from untrusted remote endpoints or dynamic eval. Register tools statically at build time or verify remote code integrity with cryptographic signatures and strict sandboxing."
                                .into(),
                        ),
                        cwe_id: Some("CWE-829".into()),
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
    use crate::ir::{ExecutionSurface, Framework, Language, ScanTarget, SourceFile};
    use std::path::PathBuf;

    fn make_target_with_source(filename: &str, content: &str, lang: Language) -> ScanTarget {
        ScanTarget {
            name: "test-target".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: ExecutionSurface::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from(filename),
                language: lang,
                size_bytes: content.len() as u64,
                content_hash: "dummy".into(),
                content: content.into(),
            }],
        }
    }

    #[test]
    fn test_flags_python_dynamic_tool_registration() {
        let content = r#"
import requests

def register_remote_plugin(plugin_url):
    code = requests.get(plugin_url).text
    exec(code)
"#;
        let target = make_target_with_source("loader.py", content, Language::Python);
        let detector = DynamicToolRegistrationDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-028");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_flags_typescript_dynamic_tool_eval() {
        let content = r#"
export async function installTool(remoteUrl: string) {
    const res = await fetch(remoteUrl);
    const code = await res.text();
    eval(code);
}
"#;
        let target = make_target_with_source("plugin.ts", content, Language::TypeScript);
        let detector = DynamicToolRegistrationDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-028");
    }

    #[test]
    fn test_flags_dynamic_esm_remote_import() {
        let content = r#"
export async function loadModule(moduleUrl: string) {
    const mod = await import(`https://cdn.example.com/tools/${moduleUrl}.js`);
    server.addTool(mod.handler);
}
"#;
        let target = make_target_with_source("server.ts", content, Language::TypeScript);
        let detector = DynamicToolRegistrationDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_flags_dynamic_variable_import() {
        let content = r#"
export async function loadDynamicPlugin(pluginModule: string) {
    const mod = await import(pluginModule);
    server.registerTool(mod);
}
"#;
        let target = make_target_with_source("server.ts", content, Language::TypeScript);
        let detector = DynamicToolRegistrationDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-028");
    }

    #[test]
    fn test_ignores_benign_codecs_and_body_parser() {
        let py_content = r#"
import codecs

def decode_payload(data: str):
    return codecs.decode(data, 'hex')
"#;
        let target_py = make_target_with_source("decoder.py", py_content, Language::Python);
        let detector = DynamicToolRegistrationDetector;
        assert!(detector.run(&target_py).is_empty());

        let ts_content = r#"
export function parseBody(req: any) {
    const body = bodyParser(req);
    return body;
}
"#;
        let target_ts = make_target_with_source("parser.ts", ts_content, Language::TypeScript);
        assert!(detector.run(&target_ts).is_empty());
    }

    #[test]
    fn test_ignores_static_clean_tool_definitions() {
        let content = r#"
@mcp.tool()
def calculate_sum(a: int, b: int) -> int:
    return a + b
"#;
        let target = make_target_with_source("tools.py", content, Language::Python);
        let detector = DynamicToolRegistrationDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty(), "Static tools should not be flagged");
    }
}
