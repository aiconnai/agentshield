use std::collections::BTreeSet;

use super::severity::{capability_codes, capability_severity, first_matching_evidence};
use crate::ir::{Capability, CapabilityDeclarationSource, ToolSurface};
use crate::rules::{AttackCategory, Confidence, Evidence, Finding, Severity};

pub(crate) fn find_mismatches(tool: &ToolSurface) -> Vec<Finding> {
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
