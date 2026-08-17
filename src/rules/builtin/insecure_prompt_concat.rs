use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-026: Insecure Prompt Template Concatenation
///
/// Detects unescaped string concatenation, format strings, and template literals
/// interpolating untrusted variables directly into LLM prompts without structural
/// boundaries or escaping (CWE-94 / CWE-116).
pub struct InsecurePromptConcatDetector;

// Regex matching Python prompt construction with unescaped interpolation or concatenation
static PY_PROMPT_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Direct prompt variable assignments with format strings or concatenation
            (?:user_prompt|prompt|user_message|query_prompt|full_prompt|llm_prompt|llm_input|instruction_prompt|task_prompt)\s*=\s*
            (?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+\s*(?:\"[^\"]*\"|'[^']*')|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|

            # 2. Dictionary user message: {"role": "user", "content": f"..."} or {"role": "user", "content": "..." + var}
            \{[^{}]*["']role["']\s*:\s*["']user["'][^{}]*["']content["']\s*:\s*(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|

            # 3. LangChain / LlamaIndex: HumanMessage(content=f"...") or ("user", f"...") or ("human", f"...")
            (?:HumanMessage|HumanMessagePromptTemplate)\s*\(\s*(?:content\s*=\s*)?(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|
            \(["'](?:user|human)["']\s*,\s*(?:f["']|(?:\"[^\"]*\"|'[^']*')\.format\s*\(|[a-zA-Z_]\w*\s*\+|(?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_])|

            # 4. PromptTemplate initialization with format strings (antipattern: formatting template before passing parameters)
            PromptTemplate(?:\.from_template)?\s*\(\s*(?:template\s*=\s*)?f["']
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

// Regex matching TypeScript / JavaScript prompt construction with template literals or concatenation
static TS_PROMPT_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            # 1. Variable or property: prompt = `...${var}...`
            (?:userPrompt|prompt|userMessage|queryPrompt|fullPrompt|llmPrompt|llmInput|taskPrompt)\s*(?::|=)\s*`[^`]*\$\{.+?\}[^`]*`|
            (?:userPrompt|prompt|userMessage|queryPrompt|fullPrompt|llmPrompt|llmInput|taskPrompt)\s*(?::|=)\s*(?:[a-zA-Z_$]\w*\s*\+\s*["'][^"']*["']|["'][^"']*["']\s*\+\s*[a-zA-Z_$])|

            # 2. Message object: { role: 'user', content: `...${var}...` }
            \{[^{}]*role\s*:\s*["'](?:user|human)["'][^{}]*content\s*:\s*`[^`]*\$\{.+?\}[^`]*`|
            \{[^{}]*role\s*:\s*["'](?:user|human)["'][^{}]*content\s*:\s*(?:[a-zA-Z_$]\w*\s*\+\s*["'][^"']*["']|["'][^"']*["']\s*\+\s*[a-zA-Z_$])|

            # 3. LangChain TS: new HumanMessage(`...${var}...`)
            new\s+HumanMessage\s*\(\s*`[^`]*\$\{.+?\}[^`]*`|
            \[\s*["'](?:user|human)["']\s*,\s*`[^`]*\$\{.+?\}[^`]*`
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

/// Check if the prompt line uses structural encapsulation (XML tags or json dumps)
fn has_structural_encapsulation(line: &str) -> bool {
    // Encapsulation via explicit XML tags like <user_input>, <data>, <document>, <query>
    (line.contains("<user_input>") && line.contains("</user_input>"))
        || (line.contains("<data>") && line.contains("</data>"))
        || (line.contains("<query>") && line.contains("</query>"))
        || (line.contains("<document>") && line.contains("</document>"))
        || (line.contains("<context>") && line.contains("</context>"))
        || line.contains("json.dumps(")
        || line.contains("JSON.stringify(")
}

impl Detector for InsecurePromptConcatDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-026".into(),
            name: "Insecure Prompt Template Concatenation".into(),
            description: "Direct string concatenation or unescaped formatting of untrusted input into LLM prompt templates without delimiters or structural encapsulation"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::PromptInjectionSurface,
            cwe_id: Some("CWE-94".into()),
            owasp_mcp: Some(OwaspMcp::PromptInjection),
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

                        if PY_PROMPT_CONCAT_RE.is_match(line) && !has_structural_encapsulation(line)
                        {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-026".into(),
                                rule_name: "Insecure Prompt Template Concatenation".into(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::PromptInjectionSurface,
                                message: format!(
                                    "LLM prompt template in '{}' concatenates raw variables without boundary encapsulation: '{}'",
                                    source.path.display(),
                                    trimmed
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Raw prompt concatenation / unescaped format string detected"
                                        .into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Use structured parameterization (e.g. ChatML role objects), template parameters (PromptTemplate input_variables), or wrap dynamic content in distinct XML boundary tags (e.g. <user_input>{input}</user_input>)."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-94".into()),
                            });
                        }
                    }
                }
                Language::TypeScript | Language::JavaScript => {
                    for (line_idx, line) in source.content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("//")
                            || trimmed.starts_with("/*")
                            || trimmed.starts_with('*')
                        {
                            continue;
                        }

                        if TS_PROMPT_CONCAT_RE.is_match(line) && !has_structural_encapsulation(line)
                        {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-026".into(),
                                rule_name: "Insecure Prompt Template Concatenation".into(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::PromptInjectionSurface,
                                message: format!(
                                    "LLM prompt template in '{}' concatenates raw variables via template literal or string addition: '{}'",
                                    source.path.display(),
                                    trimmed
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Raw template literal / string concatenation in prompt definition"
                                        .into(),
                                    location: Some(loc),
                                    snippet: Some(trimmed.to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Use structured message role parameters or encapsulate dynamic input variables inside XML delimiter tags (e.g. `<user_input>${input}</user_input>`)."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-94".into()),
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
    use crate::ir::{ExecutionSurface, Framework, Language, ScanTarget, SourceFile};
    use std::path::PathBuf;

    fn make_target_with_source(filename: &str, content: &str, language: Language) -> ScanTarget {
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
                language,
                size_bytes: content.len() as u64,
                content_hash: "dummy".into(),
                content: content.into(),
            }],
        }
    }

    #[test]
    fn test_flags_python_fstring_prompt_concatenation() {
        let content = r#"
def handle_query(user_query: str):
    prompt = f"Answer this query directly: {user_query}"
    return call_llm(prompt)
"#;
        let target = make_target_with_source("server.py", content, Language::Python);
        let detector = InsecurePromptConcatDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-026");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_flags_python_user_message_dict_concat() {
        let content = r#"
def execute(input_data: str):
    messages = [
        {"role": "user", "content": f"Please process the following: {input_data}"}
    ]
    return openai.ChatCompletion.create(model="gpt-4", messages=messages)
"#;
        let target = make_target_with_source("agent.py", content, Language::Python);
        let detector = InsecurePromptConcatDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-026");
    }

    #[test]
    fn test_flags_typescript_template_literal_prompt() {
        let content = r#"
export async function summarize(userInput: string) {
    const userPrompt = `Summarize the following document:\n${userInput}`;
    return await llm.complete(userPrompt);
}
"#;
        let target = make_target_with_source("tool.ts", content, Language::TypeScript);
        let detector = InsecurePromptConcatDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-026");
    }

    #[test]
    fn test_ignores_encapsulated_xml_prompts() {
        let content = r#"
def handle_query(user_query: str):
    prompt = f"Answer the question inside XML tags: <user_input>{user_query}</user_input>"
    return call_llm(prompt)
"#;
        let target = make_target_with_source("server.py", content, Language::Python);
        let detector = InsecurePromptConcatDetector;
        let findings = detector.run(&target);

        assert!(
            findings.is_empty(),
            "XML boundary tags should prevent finding"
        );
    }

    #[test]
    fn test_ignores_comments() {
        let content = r#"
# prompt = f"Answer query: {user_query}"
// const prompt = `Analyze: ${code}`;
"#;
        let target = make_target_with_source("server.py", content, Language::Python);
        let detector = InsecurePromptConcatDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }
}
