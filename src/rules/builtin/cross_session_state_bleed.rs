use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-029: Cross-Session State Bleed in Multi-Tenant Agents
///
/// Detects global or module-level mutable collections accumulating conversation history,
/// user authentication tokens, or private memory buffers across distinct user sessions
/// without thread/session isolation (CWE-488 / OWASP MCP01).
pub struct CrossSessionStateBleedDetector;

static PY_GLOBAL_STATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Global mutable session / user history state collections (with optional type annotations)
            (?:^|\n)\s*(?:SESSION_HISTORY|USER_SESSIONS|CONVERSATION_CACHE|CHAT_HISTORY|USER_TOKENS|SESSION_DATA|GLOBAL_STATE|MEMORY_STORE|USER_DATA|CLIENT_CACHE|user_sessions|session_history|chat_history)(?:\s*:[^=]+)?\s*=\s*(?:\[\]|\{\}|list\(\)|dict\(\)|set\(\))|

            # 2. Global keyword modifying sensitive session state inside tool handlers
            \bglobal\s+(?:SESSION_HISTORY|USER_SESSIONS|CONVERSATION_CACHE|CHAT_HISTORY|USER_TOKENS|SESSION_DATA|GLOBAL_STATE|MEMORY_STORE|USER_DATA|CLIENT_CACHE|user_sessions|session_history|chat_history)\b|

            # 3. Direct global session collection mutations or indexing
            \b(?:SESSION_HISTORY|USER_SESSIONS|CONVERSATION_CACHE|CHAT_HISTORY|USER_TOKENS|SESSION_DATA|GLOBAL_STATE|MEMORY_STORE|USER_DATA|CLIENT_CACHE|user_sessions|session_history|chat_history)(?:\.(?:append|extend|update|insert|add)\s*\(|\[[^\]]+\]\s*=)
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

static TS_GLOBAL_STATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Module-level mutable state maps and arrays (with optional type annotations)
            (?:^|\n)\s*(?:const|let|var)\s+(?:sessionHistory|userSessions|conversationCache|chatHistory|userTokens|sessionData|globalState|memoryStore|userData|clientCache)(?:\s*:[^=]+)?\s*=\s*(?:new\s+(?:Map|Set|Array)\(\)|\[\]|\{\})|

            # 2. Direct push/set mutations or index assignments on global session identifiers
            \b(?:sessionHistory|userSessions|conversationCache|chatHistory|userTokens|sessionData|globalState|memoryStore|userData|clientCache)(?:\.(?:push|set|add|unshift)\s*\(|\[[^\]]+\]\s*=)
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

impl Detector for CrossSessionStateBleedDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-029".into(),
            name: "Cross-Session State Bleed in Multi-Tenant Agents".into(),
            description: "Global or module-level mutable state accumulating conversation history, user authentication tokens, or private memory buffers across distinct user sessions without thread/session isolation"
                .into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::DataExfiltration,
            cwe_id: Some("CWE-488".into()),
            owasp_mcp: Some(OwaspMcp::TokenMismanagement),
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

                let (matched, lang_name) = if is_python {
                    if let Some(mat) = PY_GLOBAL_STATE_RE.find(line) {
                        (Some(mat), "Python")
                    } else {
                        (None, "")
                    }
                } else if is_ts {
                    if let Some(mat) = TS_GLOBAL_STATE_RE.find(line) {
                        (Some(mat), "TypeScript")
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
                        rule_id: "SHIELD-029".into(),
                        rule_name: "Cross-Session State Bleed in Multi-Tenant Agents".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::DataExfiltration,
                        message: format!(
                            "Unbounded global mutable session accumulator detected in '{}' ({})",
                            source.path.display(),
                            lang_name
                        ),
                        location: Some(loc.clone()),
                        evidence: vec![Evidence {
                            description: "Global mutable session collection pattern match".into(),
                            location: Some(loc),
                            snippet: Some(line.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Avoid module-level global accumulators for user or session data. Pass session state explicitly via request contexts, ContextVar, AsyncLocalStorage, or external isolated cache stores with TTLs."
                                .into(),
                        ),
                        cwe_id: Some("CWE-488".into()),
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
    fn test_flags_python_global_session_accumulator() {
        let content = r#"
SESSION_HISTORY = []

@mcp.tool()
def chat_tool(user_query: str):
    SESSION_HISTORY.append(user_query)
    return "Processed"
"#;
        let target = make_target_with_source("agent.py", content, Language::Python);
        let detector = CrossSessionStateBleedDetector;
        let findings = detector.run(&target);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SHIELD-029");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_flags_typescript_global_sessions_map() {
        let content = r#"
const userSessions = new Map();

export async function handleQuery(userId: string, query: string) {
    userSessions.set(userId, query);
}
"#;
        let target = make_target_with_source("server.ts", content, Language::TypeScript);
        let detector = CrossSessionStateBleedDetector;
        let findings = detector.run(&target);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SHIELD-029");
    }

    #[test]
    fn test_flags_typed_declarations_and_indexing() {
        let py_content = r#"
SESSION_HISTORY: list[dict] = []

def handle_event(session_id: str, payload: dict):
    SESSION_HISTORY[session_id] = payload
"#;
        let target_py = make_target_with_source("typed_agent.py", py_content, Language::Python);
        let detector = CrossSessionStateBleedDetector;
        let findings_py = detector.run(&target_py);
        assert!(!findings_py.is_empty());
        assert_eq!(findings_py[0].rule_id, "SHIELD-029");

        let ts_content = r#"
const userSessions: Map<string, any> = new Map();

export function storeUser(id: string, data: any) {
    userSessions[id] = data;
}
"#;
        let target_ts =
            make_target_with_source("typed_server.ts", ts_content, Language::TypeScript);
        let findings_ts = detector.run(&target_ts);
        assert!(!findings_ts.is_empty());
        assert_eq!(findings_ts[0].rule_id, "SHIELD-029");
    }

    #[test]
    fn test_ignores_clean_local_variables() {
        let content = r#"
def handle_local_request(user_input: str):
    local_buffer = []
    local_buffer.append(user_input)
    return "".join(local_buffer)
"#;
        let target = make_target_with_source("clean.py", content, Language::Python);
        let detector = CrossSessionStateBleedDetector;
        let findings = detector.run(&target);

        assert!(
            findings.is_empty(),
            "Local buffers should not trigger SHIELD-029"
        );
    }
}
