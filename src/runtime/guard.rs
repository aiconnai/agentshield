use crate::rules::builtin::metadata_ssrf::references_metadata_endpoint;
use crate::runtime::{
    redact_runtime_event, RuntimeEvent, RuntimeGuardFinding, RuntimeGuardResult,
    RuntimeSchemaVersion, RuntimeSeverity, RuntimeVerdict,
};

const SECRET_RULE_ID: &str = "AGENTSHIELD-RUNTIME-SECRET";
const METADATA_SSRF_RULE_ID: &str = "AGENTSHIELD-RUNTIME-METADATA-SSRF";
pub const INVALID_INPUT_RULE_ID: &str = "AGENTSHIELD-RUNTIME-INVALID-INPUT";

pub fn evaluate_runtime_event(event: RuntimeEvent) -> RuntimeGuardResult {
    let (redacted_event, redactions) = redact_runtime_event(event);
    let mut findings = Vec::new();

    if !redactions.is_empty() {
        findings.push(RuntimeGuardFinding {
            rule_id: SECRET_RULE_ID.to_string(),
            severity: RuntimeSeverity::High,
            message: "Secret material observed in runtime event".to_string(),
            evidence: Some(format!("redaction_count={}", redactions.len())),
        });
    }

    // Inspect every field that can carry a request target, regardless of the
    // self-declared `action` (which is attacker-controlled). A metadata
    // endpoint reachable via the url OR command field is blocked.
    if let Some(evidence) = [
        redacted_event.url.as_deref(),
        redacted_event.command.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|text| references_metadata_endpoint(text))
    {
        findings.push(RuntimeGuardFinding {
            rule_id: METADATA_SSRF_RULE_ID.to_string(),
            severity: RuntimeSeverity::Critical,
            message: "Runtime event references a cloud metadata endpoint".to_string(),
            evidence: Some(evidence.to_string()),
        });
    }

    // Derive the verdict from the highest finding severity so any future
    // Critical/High detector blocks/warns by construction, rather than keying
    // on a specific rule id that a new detector might forget to wire in.
    let max_severity = findings.iter().map(|f| f.severity).max();
    let verdict = match max_severity {
        Some(RuntimeSeverity::Critical) => RuntimeVerdict::Block,
        Some(RuntimeSeverity::High) | Some(RuntimeSeverity::Medium) => RuntimeVerdict::Warn,
        _ => RuntimeVerdict::Allow,
    };

    RuntimeGuardResult {
        schema_version: RuntimeSchemaVersion::V1,
        verdict,
        findings,
        redacted: redacted_event.redacted,
    }
}

pub fn invalid_runtime_guard_input(
    reason: impl Into<String>,
    redacted: bool,
) -> RuntimeGuardResult {
    RuntimeGuardResult {
        schema_version: RuntimeSchemaVersion::V1,
        verdict: RuntimeVerdict::Block,
        findings: vec![RuntimeGuardFinding {
            rule_id: INVALID_INPUT_RULE_ID.to_string(),
            severity: RuntimeSeverity::Critical,
            message: "Invalid runtime guard input; blocking fail-closed".to_string(),
            evidence: Some(reason.into()),
        }],
        redacted,
    }
}
