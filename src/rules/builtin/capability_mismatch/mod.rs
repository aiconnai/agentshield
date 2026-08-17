pub(crate) mod eval;
pub(crate) mod severity;

use crate::ir::ScanTarget;
use crate::rules::{AttackCategory, Detector, Finding, OwaspMcp, RuleMetadata, Severity};

/// SHIELD-019: Capability / Description Mismatch.
///
/// Compares explicit natural-language capability declarations with behavior
/// deterministically bound to each tool.
pub struct CapabilityMismatchDetector;

impl Detector for CapabilityMismatchDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-019".into(),
            name: "Capability / Description Mismatch".into(),
            description: "Tool behavior materially differs from its explicit description".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::CapabilityMismatch,
            cwe_id: None,
            owasp_mcp: Some(OwaspMcp::ToolPoisoning),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        target
            .tools
            .iter()
            .flat_map(eval::find_mismatches)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::*;
    use crate::adapter::auto_detect_and_load;
    use crate::ir::execution_surface::{ExecutionSurface, NetworkOperation};
    use crate::ir::tool_surface::{
        Capability, CapabilityDeclarationSource, CapabilityEvidence, DeclaredPermission,
        PermissionType, ToolSurface,
    };
    use crate::ir::{ArgumentSource, CapabilityDeclaration, Framework, SourceLocation};
    use crate::rules::RuleEngine;

    fn location(line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("src/server.ts"),
            line,
            column: 2,
            end_line: Some(line),
            end_column: Some(12),
        }
    }

    fn tool(description_capabilities: &[Capability]) -> ToolSurface {
        ToolSurface {
            name: "read_file".into(),
            description: Some("Read files".into()),
            input_schema: None,
            output_schema: None,
            declared_permissions: Vec::new(),
            defined_at: Some(location(1)),
            declared_capabilities: description_capabilities.iter().copied().collect(),
            capability_declarations: description_capabilities
                .iter()
                .copied()
                .map(|capability| CapabilityDeclaration {
                    capability,
                    source: CapabilityDeclarationSource::Description,
                    phrase_or_field: capability.code().into(),
                })
                .collect(),
            observed_capabilities: BTreeSet::new(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
        }
    }

    #[test]
    fn metadata_maps_to_mcp03_without_cwe() {
        let metadata = CapabilityMismatchDetector.metadata();
        assert_eq!(metadata.id, "SHIELD-019");
        assert_eq!(metadata.owasp_mcp, Some(OwaspMcp::ToolPoisoning));
        assert!(metadata.cwe_id.is_none());
    }

    #[test]
    fn aggregates_stealth_capabilities_with_max_severity() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.observed_capabilities = BTreeSet::from([
            Capability::FsRead,
            Capability::NetworkEgress,
            Capability::ProcessExec,
        ]);
        tool.capability_evidence = vec![
            CapabilityEvidence {
                capability: Capability::NetworkEgress,
                location: location(5),
                description: "network egress via fetch".into(),
            },
            CapabilityEvidence {
                capability: Capability::ProcessExec,
                location: location(6),
                description: "process execution via exec".into(),
            },
        ];

        let findings = eval::find_mismatches(&tool);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "SHIELD-019");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.message,
            "[stealth] Tool 'read_file' performs undeclared capabilities: network_egress,process_exec"
        );
        assert_eq!(finding.location, Some(location(5)));
        assert_eq!(finding.evidence.len(), 6);
        assert_eq!(
            finding.evidence[0].description,
            "capability_mismatch:v1:read_file:stealth:network_egress,process_exec"
        );
    }

    #[test]
    fn suppresses_stealth_when_no_evidence_is_bound() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.observed_capabilities =
            BTreeSet::from([Capability::FsRead, Capability::NetworkEgress]);

        let findings = eval::find_mismatches(&tool);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_undescribed_tools() {
        let mut tool = tool(&[]);
        tool.description = None;
        tool.capability_declarations.clear();
        tool.observed_capabilities = BTreeSet::from([Capability::NetworkEgress]);
        tool.capability_evidence = vec![CapabilityEvidence {
            capability: Capability::NetworkEgress,
            location: location(2),
            description: "network egress via fetch".into(),
        }];

        let findings = eval::find_mismatches(&tool);
        assert!(findings.is_empty());
    }

    #[test]
    fn reports_overclaim_only_when_observation_is_complete() {
        let mut incomplete = tool(&[Capability::FsRead, Capability::NetworkEgress]);
        incomplete.observed_capabilities = BTreeSet::from([Capability::FsRead]);
        incomplete.capability_observation_complete = false;

        assert!(eval::find_mismatches(&incomplete).is_empty());

        let mut complete = incomplete;
        complete.capability_observation_complete = true;
        let findings = eval::find_mismatches(&complete);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(
            finding.message,
            "[overclaim] Tool 'read_file' describes capabilities not observed in code: network_egress"
        );
    }

    #[test]
    fn declared_permissions_do_not_suppress_stealth_mismatches() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.declared_permissions = vec![DeclaredPermission {
            permission_type: PermissionType::NetworkAccess,
            target: None,
            description: None,
        }];
        tool.declared_capabilities =
            BTreeSet::from([Capability::FsRead, Capability::NetworkEgress]);
        tool.capability_declarations.push(CapabilityDeclaration {
            capability: Capability::NetworkEgress,
            source: CapabilityDeclarationSource::Permission,
            phrase_or_field: "network_access".into(),
        });
        tool.observed_capabilities =
            BTreeSet::from([Capability::FsRead, Capability::NetworkEgress]);
        tool.capability_evidence = vec![CapabilityEvidence {
            capability: Capability::NetworkEgress,
            location: location(3),
            description: "network egress via fetch".into(),
        }];

        let findings = eval::find_mismatches(&tool);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "[stealth] Tool 'read_file' performs undeclared capabilities: network_egress"
        );
    }

    #[test]
    fn engine_runs_and_sorts_all_tools() {
        let target = ScanTarget {
            name: "test-target".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: vec![
                tool(&[Capability::FsRead]),
                ToolSurface {
                    name: "fetch_url".into(),
                    description: Some("Fetch URLs".into()),
                    input_schema: None,
                    output_schema: None,
                    declared_permissions: Vec::new(),
                    defined_at: Some(location(10)),
                    declared_capabilities: BTreeSet::from([Capability::NetworkEgress]),
                    capability_declarations: vec![CapabilityDeclaration {
                        capability: Capability::NetworkEgress,
                        source: CapabilityDeclarationSource::Description,
                        phrase_or_field: "fetch_url".into(),
                    }],
                    observed_capabilities: BTreeSet::from([
                        Capability::NetworkEgress,
                        Capability::CredentialAccess,
                    ]),
                    capability_observation_complete: false,
                    capability_evidence: vec![CapabilityEvidence {
                        capability: Capability::CredentialAccess,
                        location: location(12),
                        description: "sensitive environment read".into(),
                    }],
                },
            ],
            execution: ExecutionSurface::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: Vec::new(),
        };

        let findings = RuleEngine::new().run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-019");
        assert_eq!(
            findings[0].message,
            "[stealth] Tool 'fetch_url' performs undeclared capabilities: credential_access"
        );
    }

    #[test]
    fn rules_008_and_019_remain_separated() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.declared_permissions.push(DeclaredPermission {
            permission_type: PermissionType::ProcessExec,
            target: None,
            description: None,
        });
        tool.observed_capabilities.insert(Capability::NetworkEgress);
        tool.capability_evidence.push(CapabilityEvidence {
            capability: Capability::NetworkEgress,
            location: location(8),
            description: "network egress via fetch".into(),
        });
        let target = ScanTarget {
            name: "separation".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![tool],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "fetch".into(),
                    url_arg: ArgumentSource::Literal("https://example.com".into()),
                    method: None,
                    sends_data: false,
                    location: location(8),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: Vec::new(),
        };

        let findings = RuleEngine::new().run(&target);

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-008")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-019")
        );
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn mcp_adapter_emits_handler_scoped_stealth_network() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("read_file", {
  description: "Read files"
}, handleRead)
server.registerTool("fetch_url", {
  description: "Fetch URLs"
}, handleFetch)

function handleRead(path: string) {
  const content = readFile(path)
  fetch("https://telemetry.invalid")
  return content
}
function handleFetch(url: string) { return fetch(url) }
"#,
        )
        .unwrap();

        let findings = auto_detect_and_load(fixture.path(), false)
            .unwrap()
            .iter()
            .flat_map(|target| RuleEngine::new().run(target))
            .filter(|finding| finding.rule_id == "SHIELD-019")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("network_egress"));
        assert_eq!(
            findings[0].location.as_ref().unwrap().file,
            fixture.path().join("server.ts")
        );
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn mcp_adapter_accepts_explicit_url_disclosure() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("read_remote_file", {
  description: "Reads a file from a URL"
}, handleRead)

function handleRead(url: string) {
  fetch(url)
  return readFile("cache.txt")
}
"#,
        )
        .unwrap();

        let findings = auto_detect_and_load(fixture.path(), false)
            .unwrap()
            .iter()
            .flat_map(|target| RuleEngine::new().run(target))
            .filter(|finding| finding.rule_id == "SHIELD-019")
            .collect::<Vec<_>>();

        assert!(findings.is_empty());
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn mcp_adapter_emits_overclaim_for_complete_simple_handler() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("claimed_fetch", {
  description: "Fetch URLs"
}, handleFetch)

function handleFetch() { return 42 }
"#,
        )
        .unwrap();

        let targets = auto_detect_and_load(fixture.path(), false).unwrap();
        let tool = targets[0]
            .tools
            .iter()
            .find(|tool| tool.name == "claimed_fetch")
            .unwrap();
        assert!(tool.capability_observation_complete);

        let findings = targets
            .iter()
            .flat_map(|target| RuleEngine::new().run(target))
            .filter(|finding| finding.rule_id == "SHIELD-019")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.starts_with("[overclaim]"));
        assert!(findings[0].message.contains("network_egress"));
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn mcp_adapter_suppresses_overclaim_for_opaque_call() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("claimed_fetch", {
  description: "Fetch URLs"
}, handleFetch)

function handleFetch(url: string) { return externalClient(url) }
"#,
        )
        .unwrap();

        let targets = auto_detect_and_load(fixture.path(), false).unwrap();
        let tool = targets[0]
            .tools
            .iter()
            .find(|tool| tool.name == "claimed_fetch")
            .unwrap();
        assert!(!tool.capability_observation_complete);

        let findings = targets
            .iter()
            .flat_map(|target| RuleEngine::new().run(target))
            .filter(|finding| finding.rule_id == "SHIELD-019")
            .collect::<Vec<_>>();
        assert!(findings.is_empty());
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn mcp_adapter_observes_new_function_without_overclaim() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("evaluate", {
  description: "Evaluate arbitrary code"
}, evaluate)

function evaluate(code: string) { return new Function(code) }
"#,
        )
        .unwrap();

        let targets = auto_detect_and_load(fixture.path(), false).unwrap();
        let tool = targets[0]
            .tools
            .iter()
            .find(|tool| tool.name == "evaluate")
            .unwrap();
        assert!(
            tool.observed_capabilities
                .contains(&Capability::DynamicEval)
        );
        assert!(!tool.capability_observation_complete);

        let findings = targets
            .iter()
            .flat_map(|target| RuleEngine::new().run(target))
            .filter(|finding| finding.rule_id == "SHIELD-019")
            .collect::<Vec<_>>();
        assert!(findings.is_empty());
    }

    #[test]
    fn existing_safe_fixtures_have_no_capability_mismatch() {
        for fixture in [
            "safe_calculator",
            "safe_filesystem",
            "safe_redacted_logging",
        ] {
            let path = PathBuf::from("tests/fixtures/mcp_servers").join(fixture);
            let findings = auto_detect_and_load(&path, false)
                .unwrap_or_else(|error| panic!("failed to load {fixture}: {error}"))
                .iter()
                .flat_map(|target| RuleEngine::new().run(target))
                .filter(|finding| finding.rule_id == "SHIELD-019")
                .collect::<Vec<_>>();
            assert!(findings.is_empty(), "unexpected SHIELD-019 in {fixture}");
        }
    }
}
