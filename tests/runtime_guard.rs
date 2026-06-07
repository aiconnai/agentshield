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

fn run_mcp_proxy(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args(["guard", "--mcp-proxy"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentshield guard --mcp-proxy");
    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(input)
        .expect("write proxy stdin");
    child.wait_with_output().expect("wait for proxy output")
}

#[test]
fn mcp_proxy_forwards_pass_through_and_benign_blocks_ssrf() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"calc.add","arguments":{"a":1}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http.get","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}}"#,
        "\n"
    );
    let output = run_mcp_proxy(input.as_bytes());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "one response per request: {stdout}");

    let l1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(l1.get("forward").is_some(), "tools/list should forward");

    let l2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert!(
        l2.get("forward").is_some(),
        "benign tool call should forward"
    );

    let l3: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(l3["error"]["code"], -32001, "ssrf call should block");
    assert_eq!(l3["id"], 3);
    assert_eq!(
        l3["error"]["data"]["rule_id"],
        "AGENTSHIELD-RUNTIME-METADATA-SSRF"
    );
    // The raw metadata IP must not leak into the error.
    assert!(!lines[2].contains("169.254.169.254"));

    // Exit code is 3 because at least one call was blocked.
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn mcp_proxy_fails_closed_on_malformed_line() {
    let output = run_mcp_proxy(b"not json{\n");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(line["error"]["code"], -32001);
    assert_eq!(
        line["error"]["data"]["rule_id"],
        "AGENTSHIELD-RUNTIME-INVALID-INPUT"
    );
    assert_eq!(output.status.code(), Some(3));
}

fn run_mcp_proxy_transport(input: &[u8]) -> Output {
    // The proxy spawns python3 running the fake echo MCP server.
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args([
            "guard",
            "--mcp-proxy",
            "--",
            "python3",
            "tests/fixtures/fake_mcp_server.py",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentshield guard --mcp-proxy server");
    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(input)
        .expect("write proxy stdin");
    child.wait_with_output().expect("wait for proxy output")
}

#[test]
fn mcp_proxy_transport_forwards_allowed_and_blocks_ssrf_at_the_server() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"calc.add","arguments":{"a":1}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http.get","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}}"#,
        "\n"
    );
    let output = run_mcp_proxy_transport(input.as_bytes());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let responses: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();

    // id 1 (pass-through) and id 2 (allowed) reach the server → it returns a
    // `result.served` echo for each.
    let served: Vec<i64> = responses
        .iter()
        .filter(|r| r.get("result").and_then(|x| x.get("served")).is_some())
        .filter_map(|r| r["id"].as_i64())
        .collect();
    assert!(
        served.contains(&1),
        "tools/list should reach the server: {stdout}"
    );
    assert!(
        served.contains(&2),
        "allowed tool call should reach the server: {stdout}"
    );

    // id 3 (SSRF) is blocked by the proxy: an error response with -32001, and
    // the server NEVER served id 3.
    let blocked: Vec<&serde_json::Value> = responses
        .iter()
        .filter(|r| r.get("error").is_some())
        .collect();
    assert_eq!(blocked.len(), 1, "exactly one block expected: {stdout}");
    assert_eq!(blocked[0]["id"], 3);
    assert_eq!(blocked[0]["error"]["code"], -32001);
    assert!(
        !served.contains(&3),
        "blocked call must NOT reach the server"
    );
    // The raw metadata IP must not leak in the block error.
    assert!(!stdout.contains("169.254.169.254"));

    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn mcp_proxy_transport_fails_closed_when_server_missing() {
    // A server command that cannot be spawned → block all, exit 3, no panic.
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args([
            "guard",
            "--mcp-proxy",
            "--",
            "definitely-not-a-real-binary-xyz",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .ok();
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(3), "missing server fails closed");
}
