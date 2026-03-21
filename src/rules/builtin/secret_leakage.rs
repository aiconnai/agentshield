use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-018: Secret Leakage
///
/// Detects secrets flowing to logs or LLM responses without redaction (CWE-532).
pub struct SecretLeakageDetector;

/// Environment variable name patterns that commonly hold secrets.
const SECRET_ENV_PATTERNS: &[&str] = &[
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "CREDENTIALS",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH",
];

/// Returns true if the env var name looks like it holds a secret.
fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    SECRET_ENV_PATTERNS.iter().any(|p| upper.contains(p))
}

impl Detector for SecretLeakageDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-018".into(),
            name: "Secret Leakage".into(),
            description: "Secrets or sensitive environment variables flow to logs or LLM \
                          responses without redaction"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::DataExfiltration,
            cwe_id: Some("CWE-532".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Check taint paths for secret/env -> log/response flows.
        for path in &target.data.taint_paths {
            let is_secret_source = matches!(
                path.source.source_type,
                TaintSourceType::SecretStore | TaintSourceType::EnvVariable
            );

            let is_leak_sink = matches!(
                path.sink.sink_type,
                TaintSinkType::LogOutput | TaintSinkType::ResponseToLlm
            );

            if is_secret_source && is_leak_sink {
                let sink_desc = match path.sink.sink_type {
                    TaintSinkType::LogOutput => "log output",
                    TaintSinkType::ResponseToLlm => "LLM response",
                    _ => "output",
                };

                let source_desc = match path.source.source_type {
                    TaintSourceType::SecretStore => "secret store",
                    TaintSourceType::EnvVariable => "environment variable",
                    _ => "sensitive source",
                };

                findings.push(Finding {
                    rule_id: "SHIELD-018".into(),
                    rule_name: "Secret Leakage".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::DataExfiltration,
                    message: format!(
                        "{} '{}' flows to {} '{}' without redaction",
                        source_desc, path.source.description,
                        sink_desc, path.sink.description
                    ),
                    location: Some(path.sink.location.clone()),
                    evidence: vec![
                        Evidence {
                            description: format!(
                                "Source: {} '{}'",
                                source_desc, path.source.description
                            ),
                            location: Some(path.source.location.clone()),
                            snippet: None,
                        },
                        Evidence {
                            description: format!(
                                "Sink: {} '{}'",
                                sink_desc, path.sink.description
                            ),
                            location: Some(path.sink.location.clone()),
                            snippet: None,
                        },
                    ],
                    taint_path: Some(path.clone()),
                    remediation: Some(
                        "Redact or mask sensitive values before logging or returning \
                         them in responses. Use a secrets manager and never include \
                         raw secrets in log messages or LLM outputs."
                            .into(),
                    ),
                    cwe_id: Some("CWE-532".into()),
                });
            }
        }

        // Phase 2: Check ExecutionSurface — env accesses with secret-like names
        // that are marked sensitive.
        for env_access in &target.execution.env_accesses {
            if !env_access.is_sensitive {
                continue;
            }

            let var_name = match &env_access.var_name {
                crate::ir::ArgumentSource::Literal(name) => name.clone(),
                crate::ir::ArgumentSource::Parameter { name } => name.clone(),
                crate::ir::ArgumentSource::EnvVar { name } => name.clone(),
                _ => continue,
            };

            if !is_secret_env_name(&var_name) {
                continue;
            }

            // Check if there are any log sinks or LLM response sinks in the
            // data surface — if so, the secret env var could leak.
            let has_log_sink = target
                .data
                .sinks
                .iter()
                .any(|s| matches!(s.sink_type, TaintSinkType::LogOutput));

            let has_llm_sink = target
                .data
                .sinks
                .iter()
                .any(|s| matches!(s.sink_type, TaintSinkType::ResponseToLlm));

            if has_log_sink || has_llm_sink {
                let sink_type = if has_log_sink && has_llm_sink {
                    "log output and LLM responses"
                } else if has_log_sink {
                    "log output"
                } else {
                    "LLM responses"
                };

                findings.push(Finding {
                    rule_id: "SHIELD-018".into(),
                    rule_name: "Secret Leakage".into(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    attack_category: AttackCategory::DataExfiltration,
                    message: format!(
                        "Sensitive environment variable '{}' accessed in scope with \
                         {} — potential secret leakage",
                        var_name, sink_type
                    ),
                    location: Some(env_access.location.clone()),
                    evidence: vec![Evidence {
                        description: format!(
                            "Sensitive env var '{var_name}' accessed near {sink_type}"
                        ),
                        location: Some(env_access.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Ensure sensitive environment variables are never logged or \
                         returned in responses. Use redaction helpers to mask values \
                         before any output."
                            .into(),
                    ),
                    cwe_id: Some("CWE-532".into()),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::data_surface::*;
    use crate::ir::execution_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn loc() -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("test.py"),
            line: 5,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn empty_target() -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface::default(),
            data: DataSurface::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    #[test]
    fn detects_secret_to_log() {
        let mut target = empty_target();
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::SecretStore,
                description: "AWS_SECRET_KEY".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::LogOutput,
                description: "logging.info".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });

        let findings = SecretLeakageDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-018");
        assert!(findings[0].message.contains("log output"));
        assert!(findings[0].taint_path.is_some());
    }

    #[test]
    fn detects_env_var_to_llm_response() {
        let mut target = empty_target();
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::EnvVariable,
                description: "API_TOKEN".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::ResponseToLlm,
                description: "return response".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.8,
        });

        let findings = SecretLeakageDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("LLM response"));
    }

    #[test]
    fn no_finding_for_non_secret_sources() {
        let mut target = empty_target();
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::ToolArgument,
                description: "user_query".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::LogOutput,
                description: "logging.info".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });

        let findings = SecretLeakageDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_sensitive_env_access_near_log_sink() {
        let mut target = empty_target();

        target.execution.env_accesses.push(EnvAccess {
            var_name: ArgumentSource::Literal("AWS_SECRET_ACCESS_KEY".into()),
            is_sensitive: true,
            location: loc(),
        });

        target.data.sinks.push(TaintSink {
            sink_type: TaintSinkType::LogOutput,
            description: "print".into(),
            location: loc(),
        });

        let findings = SecretLeakageDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert!(findings[0].message.contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn no_finding_for_non_secret_env_var() {
        let mut target = empty_target();

        target.execution.env_accesses.push(EnvAccess {
            var_name: ArgumentSource::Literal("LOG_LEVEL".into()),
            is_sensitive: true, // marked sensitive but name doesn't match
            location: loc(),
        });

        target.data.sinks.push(TaintSink {
            sink_type: TaintSinkType::LogOutput,
            description: "print".into(),
            location: loc(),
        });

        let findings = SecretLeakageDetector.run(&target);
        assert!(findings.is_empty());
    }
}
