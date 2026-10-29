use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

use super::source_scan::{SourceLang, regex_match_location, scan_py_ts_regex_matches};

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

        scan_py_ts_regex_matches(
            target,
            &PY_INSECURE_DELEGATION_RE,
            &TS_INSECURE_DELEGATION_RE,
            |source, lang, line_idx, line, mat| {
                let pattern_name = match lang {
                    SourceLang::Python => "Python Unauthenticated / Unrestricted Subagent Spawn",
                    SourceLang::TypeScriptOrJs => {
                        "TypeScript Unauthenticated / Unrestricted Subagent Spawn"
                    }
                };
                let loc = regex_match_location(source, line_idx, &mat);

                findings.push(Finding {
                    rule_id: "SHIELD-031".into(),
                    rule_name:
                        "Insecure Inter-Agent Delegation / Unauthenticated Subagent Spawn".into(),
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
            },
        );

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::empty_target as make_empty_target;
    use super::*;
    use crate::ir::{Language, SourceFile};
    use std::path::PathBuf;

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
