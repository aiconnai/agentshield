use std::collections::BTreeSet;

use crate::ir::{
    Capability, CapabilityDeclarationSource, CapabilityEvidence, ScanTarget, ToolSurface,
};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

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
        target.tools.iter().flat_map(find_mismatches).collect()
    }
}

fn find_mismatches(tool: &ToolSurface) -> Vec<Finding> {
    let description_declared = tool
        .capability_declarations
        .iter()
        .filter(|declaration| declaration.source == CapabilityDeclarationSource::Description)
        .map(|declaration| declaration.capability)
        .collect::<BTreeSet<_>>();

    if description_declared.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let stealth = tool
        .observed_capabilities
        .difference(&description_declared)
        .filter(|capability| {
            tool.capability_evidence
                .iter()
                .any(|evidence| evidence.capability == **capability)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    if !stealth.is_empty() {
        findings.push(stealth_finding(tool, &description_declared, &stealth));
    }

    if tool.capability_observation_complete {
        let overclaim = description_declared
            .difference(&tool.observed_capabilities)
            .copied()
            .collect::<BTreeSet<_>>();
        if !overclaim.is_empty() {
            findings.push(overclaim_finding(tool, &description_declared, &overclaim));
        }
    }

    findings
}

fn stealth_finding(
    tool: &ToolSurface,
    description_declared: &BTreeSet<Capability>,
    stealth: &BTreeSet<Capability>,
) -> Finding {
    let primary_evidence = first_matching_evidence(tool, stealth);
    let location = primary_evidence
        .map(|evidence| evidence.location.clone())
        .or_else(|| tool.defined_at.clone());
    let mut evidence = common_evidence(tool, "stealth", description_declared, stealth);
    evidence.extend(
        tool.capability_evidence
            .iter()
            .filter(|item| stealth.contains(&item.capability))
            .map(|item| Evidence {
                description: format!("Observed {}: {}", item.capability.code(), item.description),
                location: Some(item.location.clone()),
                snippet: None,
            }),
    );
    evidence.push(Evidence {
        description: "Association: deterministic handler binding".into(),
        location: tool.defined_at.clone(),
        snippet: None,
    });

    Finding {
        rule_id: "SHIELD-019".into(),
        rule_name: "Capability / Description Mismatch".into(),
        severity: stealth
            .iter()
            .copied()
            .map(capability_severity)
            .max()
            .unwrap_or(Severity::Low),
        confidence: Confidence::High,
        attack_category: AttackCategory::CapabilityMismatch,
        message: format!(
            "[stealth] Tool '{}' performs undeclared capabilities: {}",
            tool.name,
            capability_codes(stealth)
        ),
        location,
        evidence,
        taint_path: None,
        remediation: Some(
            "Make the tool description explicitly disclose its behavior, or remove the \
             hidden capability from the implementation."
                .into(),
        ),
        cwe_id: None,
    }
}

fn overclaim_finding(
    tool: &ToolSurface,
    description_declared: &BTreeSet<Capability>,
    overclaim: &BTreeSet<Capability>,
) -> Finding {
    Finding {
        rule_id: "SHIELD-019".into(),
        rule_name: "Capability / Description Mismatch".into(),
        severity: Severity::Low,
        confidence: Confidence::Medium,
        attack_category: AttackCategory::CapabilityMismatch,
        message: format!(
            "[overclaim] Tool '{}' describes capabilities not observed in code: {}",
            tool.name,
            capability_codes(overclaim)
        ),
        location: tool.defined_at.clone(),
        evidence: common_evidence(tool, "overclaim", description_declared, overclaim),
        taint_path: None,
        remediation: Some(
            "Update the tool description to match its implementation, or implement the \
             documented behavior."
                .into(),
        ),
        cwe_id: None,
    }
}

fn common_evidence(
    tool: &ToolSurface,
    kind: &str,
    description_declared: &BTreeSet<Capability>,
    mismatch: &BTreeSet<Capability>,
) -> Vec<Evidence> {
    let phrases = tool
        .capability_declarations
        .iter()
        .filter(|declaration| declaration.source == CapabilityDeclarationSource::Description)
        .map(|declaration| {
            format!(
                "{}={}",
                declaration.phrase_or_field,
                declaration.capability.code()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    vec![
        Evidence {
            description: format!(
                "capability_mismatch:v1:{}:{}:{}",
                tool.name,
                kind,
                capability_codes(mismatch)
            ),
            location: None,
            snippet: None,
        },
        Evidence {
            description: format!(
                "Tool description: {}",
                tool.description.as_deref().unwrap_or_default()
            ),
            location: tool.defined_at.clone(),
            snippet: None,
        },
        Evidence {
            description: format!(
                "Description declarations: {} ({phrases})",
                capability_codes(description_declared)
            ),
            location: tool.defined_at.clone(),
            snippet: None,
        },
    ]
}

fn first_matching_evidence<'a>(
    tool: &'a ToolSurface,
    capabilities: &BTreeSet<Capability>,
) -> Option<&'a CapabilityEvidence> {
    tool.capability_evidence
        .iter()
        .find(|evidence| capabilities.contains(&evidence.capability))
}

fn capability_codes(capabilities: &BTreeSet<Capability>) -> String {
    capabilities
        .iter()
        .map(|capability| capability.code())
        .collect::<Vec<_>>()
        .join(",")
}

fn capability_severity(capability: Capability) -> Severity {
    match capability {
        Capability::CredentialAccess
        | Capability::ProcessExec
        | Capability::DynamicEval
        | Capability::PackageInstall => Severity::High,
        Capability::NetworkEgress | Capability::FsWrite | Capability::DatabaseWrite => {
            Severity::Medium
        }
        Capability::FsRead | Capability::EnvRead | Capability::DatabaseRead => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::auto_detect_and_load;
    use crate::ir::execution_surface::{ExecutionSurface, NetworkOperation};
    use crate::ir::tool_surface::{DeclaredPermission, PermissionType};
    use crate::ir::{ArgumentSource, CapabilityDeclaration, Framework, ScanTarget, SourceLocation};
    use crate::rules::RuleEngine;
    use std::path::Path;
    use std::path::PathBuf;

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

        let findings = find_mismatches(&tool);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.starts_with("[stealth]"));
        assert_eq!(
            findings[0].evidence[0].description,
            "capability_mismatch:v1:read_file:stealth:network_egress,process_exec"
        );
        assert_eq!(findings[0].location.as_ref().unwrap().line, 5);
    }

    #[test]
    fn permission_does_not_suppress_description_stealth() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.declared_capabilities.insert(Capability::NetworkEgress);
        tool.capability_declarations.push(CapabilityDeclaration {
            capability: Capability::NetworkEgress,
            source: CapabilityDeclarationSource::Permission,
            phrase_or_field: "network_access".into(),
        });
        tool.observed_capabilities.insert(Capability::NetworkEgress);
        tool.capability_evidence.push(CapabilityEvidence {
            capability: Capability::NetworkEgress,
            location: location(4),
            description: "network egress via fetch".into(),
        });

        let findings = find_mismatches(&tool);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("network_egress"));
    }

    #[test]
    fn vague_description_and_matching_behavior_do_not_find() {
        let mut vague = tool(&[]);
        vague
            .observed_capabilities
            .insert(Capability::NetworkEgress);
        assert!(find_mismatches(&vague).is_empty());

        let mut matching = tool(&[Capability::FsRead]);
        matching.observed_capabilities.insert(Capability::FsRead);
        assert!(find_mismatches(&matching).is_empty());
    }

    #[test]
    fn observed_capability_without_bound_evidence_does_not_find() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.observed_capabilities.insert(Capability::NetworkEgress);

        assert!(find_mismatches(&tool).is_empty());
    }

    #[test]
    fn incomplete_observation_suppresses_overclaim() {
        let tool = tool(&[Capability::NetworkEgress]);
        assert!(find_mismatches(&tool).is_empty());
    }

    #[test]
    fn complete_observation_can_emit_distinct_overclaim_and_stealth() {
        let mut tool = tool(&[Capability::FsRead]);
        tool.capability_observation_complete = true;
        tool.observed_capabilities.insert(Capability::NetworkEgress);
        tool.capability_evidence.push(CapabilityEvidence {
            capability: Capability::NetworkEgress,
            location: location(8),
            description: "network egress via fetch".into(),
        });

        let findings = find_mismatches(&tool);

        assert_eq!(findings.len(), 2);
        assert!(findings[0].message.starts_with("[stealth]"));
        assert!(findings[1].message.starts_with("[overclaim]"));
        assert_ne!(
            findings[0].fingerprint(Path::new(".")),
            findings[1].fingerprint(Path::new("."))
        );
    }

    #[test]
    fn shield_008_and_019_operate_on_distinct_axes() {
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

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "SHIELD-008"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "SHIELD-019"));
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
