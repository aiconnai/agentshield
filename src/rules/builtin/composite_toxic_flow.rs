use crate::analysis::composite_flow::{CompositeFlowCandidate, FlowEdgeKind, SemanticAnchor};
use crate::analysis::DetectionInput;
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, ContextDetector, Evidence, Finding, OwaspMcp, RuleMetadata,
    Severity,
};

/// SHIELD-020: Arbitrary Read Exfiltration Chain.
pub struct ArbitraryReadExfiltrationDetector;

impl ContextDetector for ArbitraryReadExfiltrationDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-020".into(),
            name: "Arbitrary Read Exfiltration Chain".into(),
            description: "File content read from controllable input is sent over the network"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::DataExfiltration,
            cwe_id: Some("CWE-200".into()),
            owasp_mcp: Some(OwaspMcp::DataExfiltration),
        }
    }

    fn run(&self, input: &DetectionInput<'_>) -> Vec<Finding> {
        input
            .composite_flows
            .iter()
            .filter(|candidate| candidate.observation_complete)
            .filter_map(|candidate| shield_020_finding(candidate, input.target))
            .collect()
    }
}

fn shield_020_finding(candidate: &CompositeFlowCandidate, target: &ScanTarget) -> Option<Finding> {
    let tool_name = target
        .tools
        .iter()
        .find(|tool| tool.name == candidate.tool_name)
        .map(|tool| tool.name.clone())
        .unwrap_or_else(|| candidate.tool_name.clone());

    Some(Finding {
        rule_id: "SHIELD-020".into(),
        rule_name: "Arbitrary Read Exfiltration Chain".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        attack_category: AttackCategory::DataExfiltration,
        message: format!(
            "Tool '{}' can read an attacker-controlled file and send its contents over HTTP",
            tool_name
        ),
        location: Some(candidate.sink_location.clone()),
        evidence: finding_evidence(candidate),
        taint_path: None,
        remediation: Some(
            "Validate file paths before reading and avoid sending raw file contents to untrusted sinks."
                .into(),
        ),
        cwe_id: Some("CWE-200".into()),
    })
}

fn finding_evidence(candidate: &CompositeFlowCandidate) -> Vec<Evidence> {
    let mut evidence = Vec::with_capacity(candidate.edges.len() + 2);
    evidence.push(Evidence {
        description: format!(
            "composite_flow:v1:arbitrary_read_exfiltration:{}:{}:{}",
            candidate.tool_name,
            format_anchor(&candidate.source_anchor),
            format_anchor(&candidate.sink_anchor),
        ),
        location: Some(candidate.sink_location.clone()),
        snippet: None,
    });
    evidence.extend(candidate.edges.iter().map(|edge| Evidence {
        description: chain_label(edge.kind).into(),
        location: Some(edge.location.clone()),
        snippet: None,
    }));
    evidence.push(Evidence {
        description: "Related context: SHIELD-004 (arbitrary file access).".into(),
        location: Some(candidate.source_location.clone()),
        snippet: None,
    });
    evidence
}

fn chain_label(kind: FlowEdgeKind) -> &'static str {
    match kind {
        FlowEdgeKind::ControlsFilePath => "Tool argument controls the file path.",
        FlowEdgeKind::ProducesFileContent => "File read produces the content value.",
        FlowEdgeKind::Propagates => "The file content value propagates through an alias or helper.",
        FlowEdgeKind::EntersNetworkPayload => {
            "The network payload receives the same file content value."
        }
    }
}

fn format_anchor(anchor: &SemanticAnchor) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        anchor.relative_file.display(),
        anchor.lexical_owner,
        anchor.operation_kind,
        anchor.resolved_api,
        anchor.normalized_subtree_hash,
        anchor.identical_ordinal,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::DetectionInput;
    use crate::ir::{ExecutionSurface, SourceLocation};
    use crate::rules::ContextDetector;
    use crate::rules::RuleEngine;
    use std::path::{Path, PathBuf};

    fn source_loc(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from(file),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn target_with_tool(name: &str) -> crate::ir::ScanTarget {
        crate::ir::ScanTarget {
            name: "fixture".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![crate::ir::ToolSurface {
                name: name.into(),
                description: Some("fixture tool".into()),
                input_schema: None,
                output_schema: None,
                declared_permissions: Vec::new(),
                defined_at: Some(source_loc("server.ts", 1)),
                declared_capabilities: Default::default(),
                capability_declarations: Vec::new(),
                observed_capabilities: Default::default(),
                capability_observation_complete: false,
                capability_evidence: Vec::new(),
            }],
            execution: ExecutionSurface::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    fn anchor(file: &str, owner: &str, op: &'static str, api: &'static str) -> SemanticAnchor {
        SemanticAnchor {
            relative_file: PathBuf::from(file),
            lexical_owner: owner.into(),
            operation_kind: op,
            resolved_api: api,
            normalized_subtree_hash: String::new(),
            identical_ordinal: 0,
        }
    }

    fn candidate(observation_complete: bool) -> CompositeFlowCandidate {
        CompositeFlowCandidate {
            tool_name: "read_and_send".into(),
            source_location: source_loc("server.ts", 12),
            sink_location: source_loc("server.ts", 17),
            source_anchor: anchor("server.ts", "read_and_send", "file_read", "fs.read"),
            sink_anchor: anchor("server.ts", "read_and_send", "network_payload", "fetch"),
            edges: vec![
                edge(FlowEdgeKind::ControlsFilePath, 12),
                edge(FlowEdgeKind::ProducesFileContent, 12),
                edge(FlowEdgeKind::EntersNetworkPayload, 17),
            ],
            observation_complete,
        }
    }

    fn edge(kind: FlowEdgeKind, line: usize) -> crate::analysis::composite_flow::FlowEdge {
        use crate::analysis::composite_flow::{ByteSpan, DefinitionId, FlowEdge, ScopeId, ValueId};

        let value = ValueId {
            definition: DefinitionId {
                scope: ScopeId {
                    relative_file: PathBuf::from("server.ts"),
                    lexical_owner: "read_and_send".into(),
                },
                definition_span: ByteSpan {
                    start: line,
                    end: line + 1,
                },
            },
            version: 0,
        };
        FlowEdge {
            kind,
            input: value.clone(),
            output: value,
            location: source_loc("server.ts", line),
        }
    }

    #[test]
    fn emits_shield_020_for_complete_chain() {
        let target = target_with_tool("read_and_send");
        let composite = vec![candidate(true)];
        let input = DetectionInput {
            target: &target,
            composite_flows: &composite,
        };

        let findings = ArbitraryReadExfiltrationDetector.run(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-020");
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(
            findings[0].message,
            "Tool 'read_and_send' can read an attacker-controlled file and send its contents over HTTP"
        );
        assert!(findings[0].evidence[0]
            .description
            .starts_with("composite_flow:v1:arbitrary_read_exfiltration:"));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|ev| ev.description.contains("SHIELD-004")));
    }

    #[test]
    fn ignores_incomplete_observation() {
        let target = target_with_tool("read_and_send");
        let composite = vec![candidate(false)];
        let input = DetectionInput {
            target: &target,
            composite_flows: &composite,
        };

        let findings = ArbitraryReadExfiltrationDetector.run(&input);
        assert!(findings.is_empty());
    }

    #[test]
    fn appears_in_scanner_registry() {
        let target = target_with_tool("read_and_send");
        let composite = vec![candidate(true)];
        let input = DetectionInput {
            target: &target,
            composite_flows: &composite,
        };

        let engine_findings = {
            let engine = RuleEngine::new();
            engine.run_with_context(&input)
        };

        assert!(engine_findings
            .iter()
            .any(|finding| finding.rule_id == "SHIELD-020"));

        let engine = RuleEngine::new();
        assert!(!engine
            .list_rules()
            .iter()
            .any(|metadata| metadata.id == "SHIELD-020"));
        let metadata = engine
            .list_scanner_rules()
            .into_iter()
            .find(|metadata| metadata.id == "SHIELD-020")
            .expect("SHIELD-020 must appear in scanner metadata");
        assert_eq!(metadata.owasp_mcp, Some(OwaspMcp::DataExfiltration));
    }

    #[test]
    fn fingerprint_uses_semantic_anchors_not_line_numbers() {
        let target = target_with_tool("read_and_send");
        let mut original = candidate(true);
        original.source_anchor.normalized_subtree_hash = "source-hash".into();
        original.sink_anchor.normalized_subtree_hash = "sink-hash".into();
        let original_finding =
            shield_020_finding(&original, &target).expect("complete candidate emits");

        let mut shifted = original.clone();
        shifted.source_location.line += 20;
        shifted.sink_location.line += 20;
        for edge in &mut shifted.edges {
            edge.location.line += 20;
        }
        let shifted_finding =
            shield_020_finding(&shifted, &target).expect("shifted candidate emits");
        assert_eq!(
            original_finding.fingerprint(Path::new(".")),
            shifted_finding.fingerprint(Path::new("."))
        );

        let mut second_sink = original;
        second_sink.sink_anchor.identical_ordinal = 1;
        let second_finding =
            shield_020_finding(&second_sink, &target).expect("second candidate emits");
        assert_ne!(
            original_finding.fingerprint(Path::new(".")),
            second_finding.fingerprint(Path::new("."))
        );
    }
}
