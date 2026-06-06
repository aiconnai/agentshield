use crate::runtime::{
    redact_runtime_event, RuntimeAction, RuntimeEvent, RuntimeGuardFinding, RuntimeGuardResult,
    RuntimeSchemaVersion, RuntimeSeverity, RuntimeVerdict,
};

const SECRET_RULE_ID: &str = "AGENTSHIELD-RUNTIME-SECRET";
const METADATA_SSRF_RULE_ID: &str = "AGENTSHIELD-RUNTIME-METADATA-SSRF";
pub const INVALID_INPUT_RULE_ID: &str = "AGENTSHIELD-RUNTIME-INVALID-INPUT";
const METADATA_ENDPOINT: &str = "169.254.169.254";

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

    if redacted_event.action == RuntimeAction::NetworkRequest
        && redacted_event
            .url
            .as_deref()
            .is_some_and(|url| url.contains(METADATA_ENDPOINT))
    {
        findings.push(RuntimeGuardFinding {
            rule_id: METADATA_SSRF_RULE_ID.to_string(),
            severity: RuntimeSeverity::Critical,
            message: "Runtime network request targets cloud metadata endpoint".to_string(),
            evidence: redacted_event.url.clone(),
        });
    }

    let verdict = if findings
        .iter()
        .any(|finding| finding.rule_id == METADATA_SSRF_RULE_ID)
    {
        RuntimeVerdict::Block
    } else if !redactions.is_empty() {
        RuntimeVerdict::Warn
    } else {
        RuntimeVerdict::Allow
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
