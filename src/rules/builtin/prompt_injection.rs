use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-007: Prompt Injection Surface
///
/// Flags tools that fetch external content (HTTP, file read) and could
/// return it unsanitized to the LLM. External content may contain
/// adversarial instructions that hijack the agent's behavior.
///
/// When `DataSurface.taint_paths` are available, taint-path based findings
/// take priority. Falls back to `ArgumentSource`-based network operation
/// checking when no taint paths exist.
pub struct PromptInjectionDetector;

impl Detector for PromptInjectionDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-007".into(),
            name: "Prompt Injection Surface".into(),
            description:
                "Tool fetches external content that may be returned unsanitized to the LLM".into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::PromptInjectionSurface,
            cwe_id: None,
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Taint-path based detection (higher confidence)
        for path in &target.data.taint_paths {
            let source_matches = matches!(
                path.source.source_type,
                TaintSourceType::ToolArgument | TaintSourceType::PromptContent
            );
            let sink_matches = matches!(
                path.sink.sink_type,
                TaintSinkType::DynamicEval | TaintSinkType::ResponseToLlm
            );

            if !source_matches || !sink_matches {
                continue;
            }

            // Check for sanitization in the path — if there are intermediate
            // nodes, we still flag but with slightly lower confidence
            let has_sanitization = false; // TaintPath.through contains locations,
                                          // not sanitizer info — reserved for future use

            if has_sanitization {
                continue;
            }

            let confidence = if path.confidence >= 0.8 {
                Confidence::High
            } else {
                Confidence::Medium
            };

            findings.push(Finding {
                rule_id: "SHIELD-007".into(),
                rule_name: "Prompt Injection Surface".into(),
                severity: Severity::Medium,
                confidence,
                attack_category: AttackCategory::PromptInjectionSurface,
                message: format!(
                    "Taint path: {} flows to {} without sanitization",
                    path.source.description, path.sink.description,
                ),
                location: Some(path.sink.location.clone()),
                evidence: vec![
                    Evidence {
                        description: format!(
                            "Taint source ({:?}): {}",
                            path.source.source_type, path.source.description
                        ),
                        location: Some(path.source.location.clone()),
                        snippet: None,
                    },
                    Evidence {
                        description: format!(
                            "Taint sink ({:?}): {}",
                            path.sink.sink_type, path.sink.description
                        ),
                        location: Some(path.sink.location.clone()),
                        snippet: None,
                    },
                ],
                taint_path: Some(path.clone()),
                remediation: Some(
                    "Sanitize or escape external content before returning it to the LLM. \
                     Consider stripping HTML tags, limiting response length, and adding \
                     content boundaries."
                        .into(),
                ),
                cwe_id: None,
            });
        }

        // Phase 2: Fallback to existing network operation checking
        let fallback_findings = self.run_fallback(target);

        // Deduplicate: keep taint-path findings over fallback at same location.
        // Collect owned locations to avoid borrowing `findings` during mutation.
        let taint_path_locations: Vec<_> =
            findings.iter().filter_map(|f| f.location.clone()).collect();

        let new_findings: Vec<_> = fallback_findings
            .into_iter()
            .filter(|finding| {
                let dominated = finding
                    .location
                    .as_ref()
                    .is_some_and(|loc| taint_path_locations.iter().any(|tp_loc| tp_loc == loc));
                !dominated
            })
            .collect();

        findings.extend(new_findings);

        findings
    }
}

impl PromptInjectionDetector {
    /// Original network-operation based detection logic.
    fn run_fallback(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Any network GET that reads external content is a prompt injection surface
        for net_op in &target.execution.network_operations {
            // Only flag reads (GET), not sends (POST with sends_data)
            if net_op.sends_data {
                continue;
            }

            findings.push(Finding {
                rule_id: "SHIELD-007".into(),
                rule_name: "Prompt Injection Surface".into(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                attack_category: AttackCategory::PromptInjectionSurface,
                message: format!(
                    "'{}' fetches external content that may be returned to the LLM unsanitized",
                    net_op.function
                ),
                location: Some(net_op.location.clone()),
                evidence: vec![Evidence {
                    description: format!("External content fetch via '{}'", net_op.function),
                    location: Some(net_op.location.clone()),
                    snippet: None,
                }],
                taint_path: None,
                remediation: Some(
                    "Sanitize or escape external content before returning it to the LLM. \
                     Consider stripping HTML tags, limiting response length, and adding \
                     content boundaries."
                        .into(),
                ),
                cwe_id: None,
            });
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
            file: PathBuf::from("server.py"),
            line: 10,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn loc_at(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from(file),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_get_request() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Parameter { name: "url".into() },
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = PromptInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-007");
    }

    #[test]
    fn ignores_post_with_data() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = PromptInjectionDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn prompt_injection_with_taint_path() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: DataSurface {
                sources: vec![],
                sinks: vec![],
                taint_paths: vec![TaintPath {
                    source: TaintSource {
                        source_type: TaintSourceType::ToolArgument,
                        description: "user_query parameter".into(),
                        location: loc_at("handler.py", 3),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::ResponseToLlm,
                        description: "return response to LLM".into(),
                        location: loc_at("handler.py", 15),
                    },
                    through: vec![],
                    confidence: 0.85,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = PromptInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-007");
        assert_eq!(findings[0].confidence, Confidence::High);
        assert!(
            findings[0].taint_path.is_some(),
            "finding should have taint_path populated"
        );

        let tp = findings[0].taint_path.as_ref().unwrap();
        assert_eq!(tp.source.source_type, TaintSourceType::ToolArgument);
        assert_eq!(tp.sink.sink_type, TaintSinkType::ResponseToLlm);
    }

    #[test]
    fn prompt_injection_with_dynamic_eval_sink() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: DataSurface {
                sources: vec![],
                sinks: vec![],
                taint_paths: vec![TaintPath {
                    source: TaintSource {
                        source_type: TaintSourceType::ToolArgument,
                        description: "code parameter".into(),
                        location: loc_at("eval_tool.py", 1),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::DynamicEval,
                        description: "eval(code)".into(),
                        location: loc_at("eval_tool.py", 5),
                    },
                    through: vec![],
                    confidence: 0.95,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = PromptInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].taint_path.is_some());
    }

    #[test]
    fn prompt_injection_fallback_without_taint_paths() {
        // Empty DataSurface but has network operations — old behavior works
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "fetch".into(),
                    url_arg: ArgumentSource::Parameter { name: "url".into() },
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc_at("tool.ts", 20),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = PromptInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-007");
        assert!(
            findings[0].taint_path.is_none(),
            "fallback findings should not have taint_path"
        );
    }

    #[test]
    fn prompt_injection_deduplicates_by_location() {
        let shared_loc = loc_at("handler.py", 15);

        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Parameter { name: "url".into() },
                    method: Some("GET".into()),
                    sends_data: false,
                    location: shared_loc.clone(),
                }],
                ..Default::default()
            },
            data: DataSurface {
                sources: vec![],
                sinks: vec![],
                taint_paths: vec![TaintPath {
                    source: TaintSource {
                        source_type: TaintSourceType::ToolArgument,
                        description: "url parameter".into(),
                        location: loc_at("handler.py", 3),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::ResponseToLlm,
                        description: "return fetched content".into(),
                        location: shared_loc,
                    },
                    through: vec![],
                    confidence: 0.9,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = PromptInjectionDetector.run(&target);

        // Both point to handler.py:15, taint-path finding should win
        let taint_path_count = findings.iter().filter(|f| f.taint_path.is_some()).count();
        let fallback_count = findings.iter().filter(|f| f.taint_path.is_none()).count();

        assert_eq!(taint_path_count, 1, "should have one taint-path finding");
        assert_eq!(
            fallback_count, 0,
            "fallback at same location should be deduplicated"
        );
    }

    #[test]
    fn prompt_injection_ignores_irrelevant_taint_paths() {
        // EnvVariable -> FileWrite should NOT trigger SHIELD-007
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: DataSurface {
                sources: vec![],
                sinks: vec![],
                taint_paths: vec![TaintPath {
                    source: TaintSource {
                        source_type: TaintSourceType::EnvVariable,
                        description: "HOME".into(),
                        location: loc_at("config.py", 1),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::FileWrite,
                        description: "write config".into(),
                        location: loc_at("config.py", 5),
                    },
                    through: vec![],
                    confidence: 0.7,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = PromptInjectionDetector.run(&target);
        assert!(
            findings.is_empty(),
            "EnvVariable->FileWrite should not trigger prompt injection"
        );
    }
}
