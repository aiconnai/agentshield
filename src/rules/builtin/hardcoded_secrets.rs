use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-027: Hardcoded AI & Cloud Provider Secrets
///
/// Detects static API keys, tokens, and credentials for AI (OpenAI, Anthropic, Gemini, Cohere)
/// and Cloud providers hardcoded directly in source code or configuration files (CWE-798).
pub struct HardcodedSecretsDetector;

/// Compute Shannon entropy in bits per character.
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in s.as_bytes() {
        counts[byte as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

struct SecretPattern {
    provider: &'static str,
    regex: &'static Lazy<Regex>,
    min_entropy: f64,
}

static OPENAI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(sk-(?:proj-|admin-|svcacct-)?[A-Za-z0-9_-]{20,})\b"#)
        .expect("static regex pattern is valid")
});

static ANTHROPIC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"#).expect("static regex pattern is valid")
});

static AWS_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b(AKIA[0-9A-Z]{16})\b"#).expect("static regex pattern is valid"));

static GOOGLE_API_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(AIzaSy[0-9A-Za-z_-]{33})\b"#).expect("static regex pattern is valid")
});

static HUGGINGFACE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(hf_[a-zA-Z0-9]{34,})\b"#).expect("static regex pattern is valid")
});

static GITHUB_PAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b((?:ghp_|gho_|github_pat_)[a-zA-Z0-9_]{36,})\b"#)
        .expect("static regex pattern is valid")
});

static COHERE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(co-[a-zA-Z0-9_-]{20,})\b"#).expect("static regex pattern is valid")
});

static PINECONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(pcsk_[a-zA-Z0-9_-]{35,})\b"#).expect("static regex pattern is valid")
});

static TAVILY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(tvly-[a-zA-Z0-9_-]{20,})\b"#).expect("static regex pattern is valid")
});

static REPLICATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(r8_[a-zA-Z0-9]{30,})\b"#).expect("static regex pattern is valid")
});

static KNOWN_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        provider: "OpenAI",
        regex: &OPENAI_RE,
        min_entropy: 3.2,
    },
    SecretPattern {
        provider: "Anthropic",
        regex: &ANTHROPIC_RE,
        min_entropy: 3.3,
    },
    SecretPattern {
        provider: "AWS IAM",
        regex: &AWS_KEY_RE,
        min_entropy: 2.8,
    },
    SecretPattern {
        provider: "Google AI / Gemini",
        regex: &GOOGLE_API_RE,
        min_entropy: 3.3,
    },
    SecretPattern {
        provider: "HuggingFace",
        regex: &HUGGINGFACE_RE,
        min_entropy: 3.2,
    },
    SecretPattern {
        provider: "GitHub",
        regex: &GITHUB_PAT_RE,
        min_entropy: 3.3,
    },
    SecretPattern {
        provider: "Cohere",
        regex: &COHERE_RE,
        min_entropy: 3.2,
    },
    SecretPattern {
        provider: "Pinecone",
        regex: &PINECONE_RE,
        min_entropy: 3.3,
    },
    SecretPattern {
        provider: "Tavily",
        regex: &TAVILY_RE,
        min_entropy: 3.2,
    },
    SecretPattern {
        provider: "Replicate",
        regex: &REPLICATE_RE,
        min_entropy: 3.2,
    },
];

/// Filter out well-known documentation examples and dummy placeholders
fn is_placeholder(secret: &str) -> bool {
    let lower = secret.to_lowercase();
    lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("your_key")
        || lower.contains("your-key")
        || lower.contains("your_token")
        || lower.contains("dummy")
        || lower.contains("xxxx")
        || lower.contains("1234567890")
        || lower.starts_with("sk-proj-test")
        || lower.starts_with("sk-ant-test")
        || secret == "AKIAIOSFODNN7EXAMPLE" // Standard AWS documentation example
}

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

impl Detector for HardcodedSecretsDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-027".into(),
            name: "Hardcoded AI & Cloud Provider Secrets".into(),
            description: "High-entropy API key or secret token for an AI or cloud provider hardcoded in source code or configuration"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::CredentialExfiltration,
            cwe_id: Some("CWE-798".into()),
            owasp_mcp: Some(OwaspMcp::TokenMismanagement),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &target.source_files {
            for (line_idx, line) in source.content.lines().enumerate() {
                for pattern in KNOWN_PATTERNS {
                    for mat in pattern.regex.find_iter(line) {
                        let candidate = mat.as_str();

                        // Disambiguate OpenAI pattern from Anthropic keys
                        if pattern.provider == "OpenAI" && candidate.starts_with("sk-ant-") {
                            continue;
                        }

                        if is_placeholder(candidate) {
                            continue;
                        }

                        let entropy = shannon_entropy(candidate);
                        if entropy < pattern.min_entropy {
                            continue;
                        }

                        let redacted = redact_secret(candidate);
                        let loc = SourceLocation {
                            file: source.path.clone(),
                            line: line_idx + 1,
                            column: mat.start() + 1,
                            end_line: Some(line_idx + 1),
                            end_column: Some(mat.end() + 1),
                        };

                        findings.push(Finding {
                            rule_id: "SHIELD-027".into(),
                            rule_name: "Hardcoded AI & Cloud Provider Secrets".into(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            attack_category: AttackCategory::CredentialExfiltration,
                            message: format!(
                                "Hardcoded {} API secret detected in '{}': '{}' (entropy: {:.2} bits/char)",
                                pattern.provider,
                                source.path.display(),
                                redacted,
                                entropy
                            ),
                            location: Some(loc.clone()),
                            evidence: vec![Evidence {
                                description: format!("Hardcoded {} key match ({})", pattern.provider, redacted),
                                location: Some(loc),
                                snippet: Some(line.replace(candidate, &redacted)),
                            }],
                            taint_path: None,
                            remediation: Some(
                                "Immediately revoke and rotate this secret. Store credentials in environment variables or an external secret vault (e.g. AWS Secrets Manager, Vault) and load them at runtime."
                                    .into(),
                            ),
                            cwe_id: Some("CWE-798".into()),
                        });
                    }
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

    fn make_target_with_source(filename: &str, content: &str) -> ScanTarget {
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
                language: Language::Python,
                size_bytes: content.len() as u64,
                content_hash: "dummy".into(),
                content: content.into(),
            }],
        }
    }

    #[test]
    fn test_shannon_entropy_calculation() {
        // Repeated character has 0 entropy
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
        // High randomness string has higher entropy
        let high_entropy =
            shannon_entropy("sk-proj-78aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890_-ABCDEF");
        assert!(high_entropy > 4.0);
    }

    #[test]
    fn test_flags_openai_project_key() {
        let content = concat!(
            "OPENAI_API_KEY = \"",
            "sk-proj-",
            "uR8x9Q2wK1pL0mZnVbC4x7Y6t5R3e2W1qAsDfGhJkLmNoPqRsTuV\"\n"
        );
        let target = make_target_with_source("config.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-027");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("OpenAI"));
    }

    #[test]
    fn test_flags_anthropic_api_key() {
        let content = concat!(
            "client = Anthropic(api_key=\"",
            "sk-ant-api03-",
            "ab9c8d7e6f5a4b3c-AB9C8D7E6F5A4B3C_XYZabc\")\n"
        );
        let target = make_target_with_source("client.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-027");
        assert!(findings[0].message.contains("Anthropic"));
    }

    #[test]
    fn test_flags_aws_access_key() {
        let content = concat!("aws_key = \"", "AKIA", "9B8C7D6E5F4A3B2C\"\n");
        let target = make_target_with_source("aws.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-027");
        assert!(findings[0].message.contains("AWS IAM"));
    }

    #[test]
    fn test_ignores_documentation_and_placeholders() {
        let content = r#"
# Example key
aws_key = "AKIAIOSFODNN7EXAMPLE"
openai_key = "sk-proj-placeholder-your-api-key-here-xxxx"
dummy = "sk-xxxxxxxxxxxxxxxxxxxxxxxx"
"#;
        let target = make_target_with_source("example.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty(), "Placeholders must be ignored");
    }

    #[test]
    fn test_flags_google_gemini_api_key() {
        let content = concat!(
            "gemini_key = \"",
            "AIza",
            "SyD9x8w7v6u5t4s3r2q1p0o9n8m7l6k5j4i\"\n"
        );
        let target = make_target_with_source("gemini.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-027");
        assert!(findings[0].message.contains("Google"));
    }

    #[test]
    fn test_flags_huggingface_and_github_tokens() {
        let content = concat!(
            "hf_token = \"",
            "hf_",
            "aBcDeFgHiJkLmNoPqRsTuVwXyZ98765432\"\n",
            "gh_token = \"",
            "ghp_",
            "9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A\"\n"
        );
        let target = make_target_with_source("tokens.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_rejects_low_entropy_secret_strings() {
        // Repeated character pattern has very low entropy (< 2.0)
        let content = r#"
fake_key = "sk-proj-abababababababababababababababababababababab"
"#;
        let target = make_target_with_source("fake.py", content);
        let detector = HardcodedSecretsDetector;
        let findings = detector.run(&target);

        assert!(
            findings.is_empty(),
            "Low-entropy repeating keys should be rejected"
        );
    }
}
