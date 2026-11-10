#![cfg(feature = "runtime-guard")]

//! `agentshield guard` must not silently ignore a configuration it cannot use.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn guard_mcp_proxy(cwd: &Path, extra: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .current_dir(cwd)
        .args(["guard", "--mcp-proxy"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentshield guard --mcp-proxy");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

#[test]
fn explicit_invalid_config_exits_non_zero_with_clear_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("bad.toml");
    std::fs::write(&config, "[runtime.proxy]\nfail_on = \"sometimes\"\n").expect("write");

    let output = guard_mcp_proxy(dir.path(), &["--config", config.to_str().expect("utf-8")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("bad.toml"), "names the file: {stderr}");
    assert!(output.stdout.is_empty(), "nothing is proxied");
}

#[test]
fn explicit_missing_config_exits_non_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = guard_mcp_proxy(dir.path(), &["--config", "does-not-exist.toml"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("does-not-exist.toml"), "{stderr}");
}

#[test]
fn invalid_default_config_exits_non_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".agentshield.toml"), "not = [valid").expect("write");
    let output = guard_mcp_proxy(dir.path(), &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(".agentshield.toml"));
}

#[test]
fn missing_default_config_falls_back_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = guard_mcp_proxy(dir.path(), &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("default"),
        "announces the fallback: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("forward"), "still proxies: {stdout}");
}

#[test]
fn valid_explicit_config_is_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("ok.toml");
    std::fs::write(&config, "[runtime.proxy]\nfail_on = \"warn\"\n").expect("write");
    let output = guard_mcp_proxy(dir.path(), &["--config", config.to_str().expect("utf-8")]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty(), "no fallback note");
}
