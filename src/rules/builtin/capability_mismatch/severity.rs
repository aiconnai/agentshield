use std::collections::BTreeSet;

use crate::ir::{Capability, CapabilityEvidence, ToolSurface};
use crate::rules::Severity;

pub(crate) fn capability_severity(capability: Capability) -> Severity {
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

pub(crate) fn capability_codes(capabilities: &BTreeSet<Capability>) -> String {
    capabilities
        .iter()
        .map(|capability| capability.code())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn first_matching_evidence<'a>(
    tool: &'a ToolSurface,
    capabilities: &BTreeSet<Capability>,
) -> Option<&'a CapabilityEvidence> {
    tool.capability_evidence
        .iter()
        .find(|evidence| capabilities.contains(&evidence.capability))
}
