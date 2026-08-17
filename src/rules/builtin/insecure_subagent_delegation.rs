use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-031: Insecure Inter-Agent Delegation / Unauthenticated Subagent Spawn
///
/// Detects autonomous subagent spawning, dynamic prompt passing, or inter-agent task delegation
/// without authentication envelopes, role boundary controls, or capability isolation (CWE-287 / OWASP MCP07).
pub struct InsecureSubagentDelegationDetector;

static PY_INSECURE_DELEGATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Unbounded CrewAI / LangChain / custom agent spawning with dangerous tools or unconstrained delegation
            \b(?:Agent|Task|Crew|DelegatingAgent|spawn_agent|create_agent|invoke_subagent|SubAgent)\s*\([^)]*
            (?:
                allow_delegation\s*=\s*True|
                tools\s*=\s*(?:all_tools|get_all_tools\(\)|locals\(\)|globals\(\)|\[[^\]]*\b(?:Bash|Terminal|Shell|Execute|System|Filesystem|AdminTools)\b[^\]]*\])|
                system_prompt\s*=\s*(?:user_input|prompt|task_input|args\.|kwargs\.|request\.|user_query)
            )|

            # 2. Spawning dynamic subagent directly from user prompt variable with execution tools
            \.(?:spawn_agent|create_subagent|invoke_subagent)\s*\(\s*
            (?:user_prompt|untrusted_prompt|query|prompt|input_text|user_input)\s*,
            [^)]*\b(?:Bash|Terminal|Shell|Execute|all_tools)\b
        )
    "#,
    )
    .expect("valid Python insecure delegation regex")
});

static TS_INSECURE_DELEGATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Unbounded JS/TS subagent constructor with unrestricted delegation or dangerous tools
            \b(?:new\s+Agent|spawnSubagent|invokeSubagent|createAgent|new\s+Task)\s*\([^)]*
            (?:
                allowDelegation\s*:\s*true|
                tools\s*:\s*(?:allTools|getAllTools\(\)|\[[^\]]*\b(?:Bash|Terminal|Shell|Execute|System|Filesystem|AdminTools)\b[^\]]*\])|
                systemPrompt\s*:\s*(?:userInput|prompt|taskInput|req\.body|req\.query|userQuery)
            )|

            # 2. Method invocation spawning subagent with dangerous tools and raw input
            \.(?:spawnSubagent|invokeSubagent|createAgent)\s*\(\s*
            (?:userPrompt|untrustedPrompt|query|prompt|inputText|userInput)\s*,
            [^)]*\b(?:Bash|Terminal|Shell|Execute|allTools)\b
        )
    "#,
    )
    .expect("valid TypeScript insecure delegation regex")
});

impl Detector for InsecureSubagentDelegationDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-031".into(),
            name: "Insecure Inter-Agent Delegation / Unauthenticated Subagent Spawn".into(),
            description: "Autonomous subagent spawning, dynamic prompt passing, or inter-agent task delegation without authentication envelopes, role boundary controls, or capability isolation".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::CodeInjection,
            cwe_id: Some("CWE-287".into()),
            owasp_mcp: Some(OwaspMcp::SupplyChain),
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
                    if let Some(mat) = PY_INSECURE_DELEGATION_RE.find(line) {
                        (
                            Some(mat),
                            "Python Unauthenticated / Unrestricted Subagent Spawn",
                        )
                    } else {
                        (None, "")
                    }
                } else if is_ts {
                    if let Some(mat) = TS_INSECURE_DELEGATION_RE.find(line) {
                        (
                            Some(mat),
                            "TypeScript Unauthenticated / Unrestricted Subagent Spawn",
                        )
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
                        rule_id: "SHIELD-031".into(),
                        rule_name: "Insecure Inter-Agent Delegation / Unauthenticated Subagent Spawn".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CodeInjection,
                        message: format!(
                            "Unauthenticated or unconstrained subagent delegation pattern detected in '{}': \"{}\" ({})",
                            source.path.display(),
                            mat.as_str(),
                            pattern_name
                        ),
                        location: Some(loc.clone()),
                        evidence: vec![Evidence {
                            description: format!("Matched {} in {}", pattern_name, source.path.display()),
                            location: Some(loc),
                            snippet: Some(line.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Require explicit authentication envelopes or permission tokens for subagents, enforce strictly bounded read-only tool sets, and disallow passing untrusted user input directly as subagent system prompts."
                                .into(),
                        ),
                        cwe_id: Some("CWE-287".into()),
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

    fn make_empty_target() -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: vec![],
            execution: ExecutionSurface::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    #[test]
    fn test_shield_031_detects_python_unbounded_agent() {
        let detector = InsecureSubagentDelegationDetector;
        let mut target = make_empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("agent_manager.py"),
            language: Language::Python,
            size_bytes: 120,
            content_hash: "1234".into(),
            content: r#"
subagent = Agent(role="executor", tools=[BashTool, Terminal], allow_delegation=True)
"#
            .into(),
        });

        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-031");
    }

    #[test]
    fn test_shield_031_detects_python_user_prompt_override() {
        let detector = InsecureSubagentDelegationDetector;
        let mut target = make_empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("crew.py"),
            language: Language::Python,
            size_bytes: 120,
            content_hash: "5678".into(),
            content: r#"
worker = Agent(role="worker", system_prompt=user_input, tools=[SearchTool])
"#
            .into(),
        });

        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-031");
    }

    #[test]
    fn test_shield_031_detects_ts_unbounded_agent() {
        let detector = InsecureSubagentDelegationDetector;
        let mut target = make_empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("orchestrator.ts"),
            language: Language::TypeScript,
            size_bytes: 120,
            content_hash: "9012".into(),
            content: r#"
const agent = new Agent({ role: "admin", tools: [Bash, Terminal], allowDelegation: true });
"#
            .into(),
        });

        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-031");
    }

    #[test]
    fn test_shield_031_benign_subagent_passes() {
        let detector = InsecureSubagentDelegationDetector;
        let mut target = make_empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("safe_agent.py"),
            language: Language::Python,
            size_bytes: 120,
            content_hash: "3456".into(),
            content: r#"
# Constrained researcher agent with read-only calculator tool
researcher = Agent(role="researcher", goal="Summarize papers", tools=[CalculatorTool], allow_delegation=False)
"#
            .into(),
        });

        let findings = detector.run(&target);
        assert!(findings.is_empty());
    }
}
