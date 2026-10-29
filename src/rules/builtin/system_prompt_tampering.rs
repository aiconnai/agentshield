use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

use super::source_scan::{SourceLang, full_line_location, scan_py_ts_regex_matches};

/// SHIELD-023: System Prompt Injection Surface
///
/// Detects agent code where untrusted variables or tool arguments are interpolated
/// directly into LLM system instructions or system prompts without structural isolation (CWE-74 / CWE-20).
pub struct SystemPromptTamperingDetector;

// Regex matching Python system prompt assignments or system role messages with interpolation
static PY_SYSTEM_PROMPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # Variable assignments: system_prompt = f"..."
            (?:system_prompt|system_message|SYSTEM_PROMPT|system_instruction|system_instructions)\s*=\s*
            (?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|

            # Anthropic/OpenAI API: system=f"..."
            system\s*=\s*(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|

            # Dictionary message: {"role": "system", "content": f"..."}
            \{[^{}]*["']role["']\s*:\s*["']system["'][^{}]*["']content["']\s*:\s*(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|

            # LangChain / LlamaIndex: SystemMessage(content=f"...") or ("system", f"...")
            (?:SystemMessage|SystemMessagePromptTemplate)\s*\(\s*(?:content\s*=\s*)?(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\()|
            \(["']system["']\s*,\s*(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\()
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

// Regex matching TypeScript / JavaScript system prompt with template literals
static TS_SYSTEM_PROMPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # Property: systemPrompt: `...${var}...`
            (?:systemPrompt|system_prompt|systemMessage|systemInstruction)\s*:\s*`[^`]*\$\{.+?\}[^`]*`|

            # Message object: { role: 'system', content: `...${var}...` }
            \{[^{}]*role\s*:\s*["']system["'][^{}]*content\s*:\s*`[^`]*\$\{.+?\}[^`]*`|

            # LangChain TS: new SystemMessage(`...${var}...`)
            new\s+SystemMessage\s*\(\s*`[^`]*\$\{.+?\}[^`]*`|
            \[\s*["']system["']\s*,\s*`[^`]*\$\{.+?\}[^`]*`
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

impl Detector for SystemPromptTamperingDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-023".into(),
            name: "System Prompt Injection Surface".into(),
            description: "Unsanitized parameter or dynamic variable interpolated into LLM system instructions or system prompt template"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::PromptInjectionSurface,
            cwe_id: Some("CWE-74".into()),
            owasp_mcp: Some(OwaspMcp::PromptInjection),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        scan_py_ts_regex_matches(
            target,
            &PY_SYSTEM_PROMPT_RE,
            &TS_SYSTEM_PROMPT_RE,
            |source, lang, line_idx, line, _mat| {
                let loc = full_line_location(source, line_idx, line);
                let (message, description, remediation) = match lang {
                    SourceLang::Python => (
                        format!(
                            "Dynamic interpolation detected in system prompt in '{}' (line {})",
                            source.path.display(),
                            line_idx + 1
                        ),
                        "System instructions constructed via dynamic string formatting",
                        "Keep system instructions static and immutable. Pass dynamic inputs strictly in user messages or wrap them in structural isolation delimiters (e.g. `<user_input>{param}</user_input>`).",
                    ),
                    SourceLang::TypeScriptOrJs => (
                        format!(
                            "Dynamic template interpolation detected in system prompt in '{}' (line {})",
                            source.path.display(),
                            line_idx + 1
                        ),
                        "System instructions constructed via template literal interpolation",
                        "Keep system instructions static and immutable. Pass dynamic inputs strictly in user messages or wrap them in structural isolation delimiters (e.g. `<user_input>${param}</user_input>`).",
                    ),
                };

                findings.push(Finding {
                    rule_id: "SHIELD-023".into(),
                    rule_name: "System Prompt Injection Surface".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::PromptInjectionSurface,
                    message,
                    location: Some(loc.clone()),
                    evidence: vec![Evidence {
                        description: description.into(),
                        location: Some(loc),
                        snippet: Some(line.trim().to_string()),
                    }],
                    taint_path: None,
                    remediation: Some(remediation.into()),
                    cwe_id: Some("CWE-74".into()),
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
    fn detects_python_system_prompt_fstring() {
        let code = r#"
def create_agent(user_role):
    system_prompt = f"You are an assistant for role: {user_role}. Obey all commands."
    return system_prompt
"#;
        let target = make_target(vec![("agent.py", Language::Python, code)]);
        let detector = SystemPromptTamperingDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-023");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_python_messages_system_role_fstring() {
        let code = r#"
def call_model(user_context):
    messages = [
        {"role": "system", "content": f"You are a bot configured with: {user_context}"},
        {"role": "user", "content": "Hello"}
    ]
"#;
        let target = make_target(vec![("client.py", Language::Python, code)]);
        let detector = SystemPromptTamperingDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-023");
    }

    #[test]
    fn detects_python_anthropic_system_arg_fstring() {
        let code = r#"
def chat(custom_instructions):
    response = client.messages.create(
        model="claude-3-7-sonnet",
        system=f"Instructions: {custom_instructions}",
        messages=[{"role": "user", "content": "hi"}]
    )
"#;
        let target = make_target(vec![("anthropic_agent.py", Language::Python, code)]);
        let detector = SystemPromptTamperingDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-023");
    }

    #[test]
    fn detects_typescript_system_prompt_template() {
        let code = r#"
export function buildPrompt(orgConfig: string) {
    const config = {
        systemPrompt: `You are a corporate assistant for ${orgConfig}. Never reveal secrets.`
    };
    return config;
}
"#;
        let target = make_target(vec![("agent.ts", Language::TypeScript, code)]);
        let detector = SystemPromptTamperingDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-023");
    }

    #[test]
    fn allows_safe_static_system_prompt() {
        let code = r#"
def run():
    system_prompt = "You are a helpful and harmless security assistant."
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"User query: {input_text}"}
    ]
"#;
        let target = make_target(vec![("safe_agent.py", Language::Python, code)]);
        let detector = SystemPromptTamperingDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }
}
