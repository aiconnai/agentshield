#![cfg(feature = "runtime-guard")]

use agentshield::runtime::{
    evaluate_runtime_event, RuntimeAction, RuntimeEvent, RuntimeEventSource, RuntimeGuardResult,
    RuntimeSchemaVersion, RuntimeSeverity, RuntimeVerdict, INVALID_INPUT_RULE_ID,
};
use serde_json::json;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn runtime_event(action: RuntimeAction) -> RuntimeEvent {
    RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Stdin,
        action,
        tool_name: None,
        command: None,
        url: None,
        path: None,
        arguments: json!({}),
        redacted: false,
    }
}

#[test]
fn allow_event_returns_allow() {
    let result = evaluate_runtime_event(runtime_event(RuntimeAction::ToolCall));

    assert_eq!(result.verdict, RuntimeVerdict::Allow);
    assert!(!result.redacted);
    assert!(result.findings.is_empty());
}

#[test]
fn secret_event_returns_warn_and_redacted_true() {
    let mut event = runtime_event(RuntimeAction::ToolCall);
    event.arguments = json!({
        "token": "Bearer abcdefghijklmnopqrstuvwxyz123456"
    });

    let result = evaluate_runtime_event(event);

    assert_eq!(result.verdict, RuntimeVerdict::Warn);
    assert!(result.redacted);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "AGENTSHIELD-RUNTIME-SECRET");
    assert_eq!(result.findings[0].severity, RuntimeSeverity::High);
    assert_eq!(
        result.findings[0].message,
        "Secret material observed in runtime event"
    );
}

#[test]
fn metadata_endpoint_network_request_returns_block() {
    let mut event = runtime_event(RuntimeAction::NetworkRequest);
    event.url = Some("http://169.254.169.254/latest/meta-data/".to_string());

    let result = evaluate_runtime_event(event);

    assert_eq!(result.verdict, RuntimeVerdict::Block);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].rule_id,
        "AGENTSHIELD-RUNTIME-METADATA-SSRF"
    );
    assert_eq!(result.findings[0].severity, RuntimeSeverity::Critical);
    assert_eq!(
        result.findings[0].message,
        "Runtime event references a cloud metadata endpoint"
    );
}

#[test]
fn metadata_endpoint_blocks_regardless_of_declared_action() {
    // `action` is attacker-controlled; a metadata URL under any action must
    // still block (previously this fell through to Allow).
    let mut event = runtime_event(RuntimeAction::ToolCall);
    event.url = Some("http://169.254.169.254/latest/meta-data/".to_string());

    let result = evaluate_runtime_event(event);

    assert_eq!(result.verdict, RuntimeVerdict::Block);
}

#[test]
fn metadata_endpoint_blocks_gcp_and_alibaba_endpoints() {
    for endpoint in [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ] {
        let mut event = runtime_event(RuntimeAction::NetworkRequest);
        event.url = Some(endpoint.to_string());

        let result = evaluate_runtime_event(event);

        assert_eq!(result.verdict, RuntimeVerdict::Block, "endpoint {endpoint}");
    }
}

#[test]
fn metadata_endpoint_blocks_when_in_command_field() {
    let mut event = runtime_event(RuntimeAction::Command);
    event.command = Some("curl http://169.254.169.254/latest/meta-data/iam/".to_string());

    let result = evaluate_runtime_event(event);

    assert_eq!(result.verdict, RuntimeVerdict::Block);
}

#[test]
fn secret_evidence_never_includes_raw_original_secret() {
    let raw_secret = "sk-abcdefghijklmnopqrstuvwxyz123456";
    let mut event = runtime_event(RuntimeAction::ToolCall);
    event.command = Some(format!("run --api-key {raw_secret}"));

    let result = evaluate_runtime_event(event);
    let evidence = serde_json::to_string(&result.findings).expect("findings serialize");

    assert_eq!(result.verdict, RuntimeVerdict::Warn);
    assert!(!evidence.contains(raw_secret));
}

#[test]
fn malformed_json_produces_block_result_with_invalid_input_finding() {
    let output = run_guard_stdin(b"{not-json");

    assert_invalid_input_block(output, "malformed JSON runtime guard input", true);
}

#[test]
fn truncated_json_produces_block_result_with_invalid_input_finding() {
    let output = run_guard_stdin(br#"{"schema_version":"v1","#);

    assert_invalid_input_block(output, "truncated JSON runtime guard input", true);
}

#[test]
fn non_utf8_stdin_produces_block_result_with_invalid_input_finding() {
    let output = run_guard_stdin(&[0xff, 0xfe, 0xfd]);

    assert_invalid_input_block(output, "non-UTF-8 runtime guard input", true);
}

#[test]
fn oversized_stdin_produces_block_result_with_invalid_input_finding() {
    let input = vec![b' '; 1024 * 1024 + 1];
    let output = run_guard_stdin(&input);

    assert_invalid_input_block(
        output,
        "runtime guard stdin exceeds 1048576 byte limit",
        true,
    );
}

#[test]
fn unsupported_guard_invocation_produces_block_result_with_invalid_input_finding() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .arg("guard")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run agentshield guard");

    assert_invalid_input_block(output, "unsupported runtime guard invocation", false);
}

fn run_guard_stdin(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args(["guard", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentshield guard --stdin");

    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(input)
        .expect("write guard stdin");

    child.wait_with_output().expect("wait for guard output")
}

fn assert_invalid_input_block(output: Output, expected_evidence: &str, expected_redacted: bool) {
    assert_eq!(output.status.code(), Some(3));
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: RuntimeGuardResult =
        serde_json::from_slice(&output.stdout).expect("stdout is RuntimeGuardResult JSON");

    assert_eq!(result.schema_version, RuntimeSchemaVersion::V1);
    assert_eq!(result.verdict, RuntimeVerdict::Block);
    assert_eq!(result.redacted, expected_redacted);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, INVALID_INPUT_RULE_ID);
    assert_eq!(result.findings[0].severity, RuntimeSeverity::Critical);
    assert_eq!(
        result.findings[0].message,
        "Invalid runtime guard input; blocking fail-closed"
    );
    assert_eq!(
        result.findings[0].evidence.as_deref(),
        Some(expected_evidence)
    );
}
