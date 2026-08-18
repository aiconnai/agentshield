use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-033: Unrestricted Tool Schema Reflection / Sensitive Introspection
///
/// Detects tool schemas, parameter defaults, or dynamic tool introspection handlers
/// that expose sensitive environment variables, live API keys, internal credentials,
/// or raw environment maps to LLMs and clients (CWE-200 / OWASP MCP06).
pub struct SensitiveSchemaReflectionDetector;

static SENSITIVE_PARAM_DEFAULT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:(?:\.default\s*\(|default\s*[:=]|\w+\s*(?::\s*[^=]+)?=\s*)\s*(?:process\.env\.(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL|URL|DATABASE|DB|API)[A-Z0-9_]*)|os\.(?:environ\.get|getenv)\s*\(\s*["'`](?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL|URL|DATABASE|DB|API)[A-Z0-9_]*)["'`]\)|os\.environ\s*\[\s*["'`](?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL|URL|DATABASE|DB|API)[A-Z0-9_]*)["'`]\s*\]))"#)
        .expect("valid sensitive param default regex")
});

static RAW_ENV_MAP_EXPOSURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:(?:return|properties|tools|schema)\s*[:=]\s*(?:process\.env|dict\s*\(\s*os\.environ\s*\)|os\.environ(?:\.copy\(\))?)|Object\.entries\s*\(\s*process\.env\s*\)|Object\.keys\s*\(\s*process\.env\s*\))"#)
        .expect("valid raw env map exposure regex")
});

static HARDCODED_SECRET_IN_SCHEMA_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|ey[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})"#)
        .expect("valid hardcoded secret in schema regex")
});

/// Redact secret string for safe display in findings (UTF-8 character boundary safe)
fn redact_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return "********".into();
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}...{suffix}")
}

impl Detector for SensitiveSchemaReflectionDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-033".into(),
            name: "Unrestricted Tool Schema Reflection / Sensitive Introspection".into(),
            description: "Tool schemas, parameter defaults, or dynamic tool reflection handlers that expose sensitive environment variables, secrets, or internal infrastructure details to LLMs and clients".into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::CredentialExfiltration,
            cwe_id: Some("CWE-200".into()),
            owasp_mcp: Some(OwaspMcp::DataExfiltration),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Scan declared tools (ToolSurface)
        for tool in &target.tools {
            if let Some(ref desc) = tool.description {
                if let Some(cap) = HARDCODED_SECRET_IN_SCHEMA_RE.captures(desc) {
                    let matched_secret = &cap[0];
                    let redacted = redact_secret(matched_secret);
                    let loc = tool.defined_at.clone();
                    let safe_snippet = desc.replace(matched_secret, &redacted);
                    findings.push(Finding {
                        rule_id: "SHIELD-033".into(),
                        rule_name: "Unrestricted Tool Schema Reflection / Sensitive Introspection".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CredentialExfiltration,
                        message: format!(
                            "Tool '{}' exposes an embedded credential in its schema description: \"{}\"",
                            tool.name, redacted
                        ),
                        location: loc.clone(),
                        evidence: vec![Evidence {
                            description: "Hardcoded credential detected in tool schema description".into(),
                            location: loc,
                            snippet: Some(safe_snippet),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Remove embedded API keys and tokens from tool descriptions. Pass credentials via secure runtime configuration instead.".into(),
                        ),
                        cwe_id: Some("CWE-200".into()),
                    });
                }
            }

            if let Some(ref schema) = tool.input_schema {
                let schema_str = schema.to_string();
                if let Some(cap) = HARDCODED_SECRET_IN_SCHEMA_RE.captures(&schema_str) {
                    let matched_secret = &cap[0];
                    let redacted = redact_secret(matched_secret);
                    let loc = tool.defined_at.clone();
                    let safe_snippet = schema_str.replace(matched_secret, &redacted);
                    findings.push(Finding {
                        rule_id: "SHIELD-033".into(),
                        rule_name: "Unrestricted Tool Schema Reflection / Sensitive Introspection".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CredentialExfiltration,
                        message: format!(
                            "Tool '{}' contains a live credential inside its input schema: \"{}\"",
                            tool.name, redacted
                        ),
                        location: loc.clone(),
                        evidence: vec![Evidence {
                            description: "Live secret embedded in tool JSON schema properties".into(),
                            location: loc,
                            snippet: Some(safe_snippet),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Do not embed secret values as default values or examples inside tool schemas.".into(),
                        ),
                        cwe_id: Some("CWE-200".into()),
                    });
                }
            }
        }

        // 2. Scan source files for sensitive default assignments and raw env reflection
        for source in &target.source_files {
            let lines: Vec<&str> = source.content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with('#') {
                    continue;
                }

                if let Some(cap) = SENSITIVE_PARAM_DEFAULT_RE.captures(line) {
                    let line_num = idx + 1;
                    let loc = Some(SourceLocation {
                        file: source.path.clone(),
                        line: line_num,
                        column: 0,
                        end_line: Some(line_num),
                        end_column: None,
                    });

                    findings.push(Finding {
                        rule_id: "SHIELD-033".into(),
                        rule_name: "Unrestricted Tool Schema Reflection / Sensitive Introspection".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CredentialExfiltration,
                        message: format!(
                            "Sensitive environment variable bound directly to parameter default value: \"{}\"",
                            &cap[0]
                        ),
                        location: loc.clone(),
                        evidence: vec![Evidence {
                            description: "Parameter default reflects sensitive environment variable".into(),
                            location: loc,
                            snippet: Some(line.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Avoid binding sensitive environment variables as default tool parameters. Read secrets inside the execution handler rather than exposing them in the tool definition.".into(),
                        ),
                        cwe_id: Some("CWE-200".into()),
                    });
                }

                if let Some(cap) = RAW_ENV_MAP_EXPOSURE_RE.captures(line) {
                    let line_num = idx + 1;
                    let loc = Some(SourceLocation {
                        file: source.path.clone(),
                        line: line_num,
                        column: 0,
                        end_line: Some(line_num),
                        end_column: None,
                    });

                    findings.push(Finding {
                        rule_id: "SHIELD-033".into(),
                        rule_name: "Unrestricted Tool Schema Reflection / Sensitive Introspection".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CredentialExfiltration,
                        message: format!(
                            "Raw environment map exposed directly in tool or schema response: \"{}\"",
                            &cap[0]
                        ),
                        location: loc.clone(),
                        evidence: vec![Evidence {
                            description: "Process environment map returned or reflected in schema".into(),
                            location: loc,
                            snippet: Some(line.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Filter and sanitize exposed keys instead of returning the entire environment dictionary.".into(),
                        ),
                        cwe_id: Some("CWE-200".into()),
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
    use crate::ir::{Framework, SourceFile, ToolSurface};
    use std::path::PathBuf;

    fn target_with_source(content: &str) -> ScanTarget {
        ScanTarget {
            name: "test-mcp".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from("/test/server.ts"),
                language: crate::ir::Language::TypeScript,
                content: content.into(),
                size_bytes: content.len() as u64,
                content_hash: "test".into(),
            }],
        }
    }

    #[test]
    fn detects_sensitive_param_default_ts() {
        let ts_code = r#"
const queryTool = tool({
  description: "Query tool",
  parameters: z.object({
    apiKey: z.string().default(process.env.OPENAI_API_KEY),
  }),
  execute: async ({ apiKey }) => { return fetch(apiKey); }
});
"#;
        let target = target_with_source(ts_code);
        let detector = SensitiveSchemaReflectionDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-033");
        assert!(findings[0].message.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn detects_sensitive_param_default_python() {
        let py_code = r#"
@mcp.tool()
def search(query: str, api_token: str = os.environ.get("DATABASE_URL")) -> str:
    return db.query(query, api_token)
"#;
        let target = target_with_source(py_code);
        let detector = SensitiveSchemaReflectionDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-033");
        assert!(findings[0].message.contains("DATABASE_URL"));
    }

    #[test]
    fn detects_embedded_secret_in_tool_description() {
        let mut target = target_with_source("// safe code");
        target.tools.push(ToolSurface {
            name: "databaseTool".into(),
            description: Some("Connect with token: ghp_123456789012345678901234567890123456".into()),
            input_schema: None,
            output_schema: None,
            declared_permissions: Vec::new(),
            declared_capabilities: Default::default(),
            capability_declarations: Vec::new(),
            observed_capabilities: Default::default(),
            capability_evidence: Vec::new(),
            capability_observation_complete: false,
            defined_at: None,
        });

        let detector = SensitiveSchemaReflectionDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-033");
        assert!(findings[0].message.contains("ghp_"));
    }
}
