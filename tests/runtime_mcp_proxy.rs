#![cfg(feature = "runtime-guard")]

use std::io::Write;
use std::process::{Command, Output, Stdio};

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

fn run_mcp_proxy_transport(input: &[u8]) -> Output {
    run_mcp_proxy_transport_with_server(input, "tests/fixtures/fake_mcp_server.py")
}

fn run_mcp_proxy_transport_with_server(input: &[u8], server: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args(["guard", "--mcp-proxy", "--", python_command(), server])
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

#[cfg(windows)]
fn python_command() -> &'static str {
    "python"
}

#[cfg(not(windows))]
fn python_command() -> &'static str {
    "python3"
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

    let l1: serde_json::Value = serde_json::from_str(lines[0]).expect("line 1 is JSON");
    assert!(l1.get("forward").is_some(), "tools/list should forward");

    let l2: serde_json::Value = serde_json::from_str(lines[1]).expect("line 2 is JSON");
    assert!(
        l2.get("forward").is_some(),
        "benign tool call should forward"
    );

    let l3: serde_json::Value = serde_json::from_str(lines[2]).expect("line 3 is JSON");
    assert_eq!(l3["error"]["code"], -32001, "ssrf call should block");
    assert_eq!(l3["id"], 3);
    assert_eq!(
        l3["error"]["data"]["rule_id"],
        "AGENTSHIELD-RUNTIME-METADATA-SSRF"
    );
    assert!(!lines[2].contains("169.254.169.254"));
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn mcp_proxy_fails_closed_on_malformed_line() {
    let output = run_mcp_proxy(b"not json{\n");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line: serde_json::Value =
        serde_json::from_str(stdout.lines().next().expect("one line")).expect("line is JSON");
    assert_eq!(line["error"]["code"], -32001);
    assert_eq!(
        line["error"]["data"]["rule_id"],
        "AGENTSHIELD-RUNTIME-INVALID-INPUT"
    );
    assert_eq!(output.status.code(), Some(3));
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
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each line is JSON"))
        .collect();

    let served: Vec<i64> = responses
        .iter()
        .filter(|response| {
            response
                .get("result")
                .and_then(|result| result.get("served"))
                .is_some()
        })
        .filter_map(|response| response["id"].as_i64())
        .collect();
    assert!(
        served.contains(&1),
        "tools/list should reach the server: {stdout}"
    );
    assert!(
        served.contains(&2),
        "allowed tool call should reach the server: {stdout}"
    );

    let blocked: Vec<&serde_json::Value> = responses
        .iter()
        .filter(|response| response.get("error").is_some())
        .collect();
    assert_eq!(blocked.len(), 1, "exactly one block expected: {stdout}");
    assert_eq!(blocked[0]["id"], 3);
    assert_eq!(blocked[0]["error"]["code"], -32001);
    assert!(
        !served.contains(&3),
        "blocked call must NOT reach the server"
    );
    assert!(!stdout.contains("169.254.169.254"));
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn mcp_proxy_transport_propagates_downstream_exit_code_when_no_call_blocked() {
    let input = concat!(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, "\n");

    let output = run_mcp_proxy_transport_with_server(
        input.as_bytes(),
        "tests/fixtures/fake_mcp_exit_server.py",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: serde_json::Value =
        serde_json::from_str(stdout.lines().next().expect("one response")).expect("valid JSON");

    assert_eq!(response["result"]["served"], "tools/list");
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn mcp_proxy_transport_fails_closed_when_downstream_does_not_exit_after_eof() {
    let input = concat!(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, "\n");

    let output = run_mcp_proxy_transport_with_server(
        input.as_bytes(),
        "tests/fixtures/fake_mcp_hanging_server.py",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3));
    assert!(
        stderr.contains("downstream MCP server did not exit before timeout"),
        "stderr: {stderr}"
    );
}

#[test]
fn mcp_proxy_transport_fails_closed_when_server_missing() {
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
