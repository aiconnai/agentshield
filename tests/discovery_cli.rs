use std::process::Command;

fn agentshield() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentshield"))
}

#[test]
fn discover_json_is_versioned_and_does_not_leak_config_values() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join(".cursor")).expect("cursor directory");
    std::fs::write(
        root.path().join(".cursor/mcp.json"),
        br#"{"mcpServers":{"local":{"command":"node","args":["--token","secret"]}}}"#,
    )
    .expect("config");
    let root = root.path().canonicalize().expect("canonical root");

    let output = agentshield()
        .args(["discover", "--no-default-paths", "--root"])
        .arg(&root)
        .args(["--format", "json"])
        .output()
        .expect("run discover");
    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json output");
    assert_eq!(envelope["schema"], "agentshield.discovery/v1");
    assert_eq!(envelope["registry_version"], 1);
    #[cfg(unix)]
    {
        assert_eq!(envelope["summary"]["sources"], 1);
        assert_eq!(envelope["summary"]["entries"], 1);
    }
    #[cfg(not(unix))]
    assert_eq!(
        envelope["sources"][0]["status"],
        "unsupported_filesystem_safety"
    );

    assert!(!stdout.contains("secret"));
    assert!(!stdout.contains("node"));
    assert!(!stdout.contains(root.to_string_lossy().as_ref()));
}

#[test]
fn discover_no_default_paths_with_no_roots_is_empty() {
    let output = agentshield()
        .args(["discover", "--no-default-paths", "--format", "json"])
        .env("HOME", "/this/path/must/not/be/read")
        .output()
        .expect("run discover");
    assert!(output.status.success(), "{output:?}");

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(envelope["summary"]["sources"], 0);
    assert_eq!(envelope["summary"]["entries"], 0);
    assert_eq!(envelope["summary"]["diagnostics"], 0);
}

#[test]
fn discover_explain_redacts_root_and_keeps_json_clean() {
    let root = tempfile::tempdir().expect("tempdir");
    let root = root.path().canonicalize().expect("canonical root");
    let output = agentshield()
        .args(["discover", "--no-default-paths", "--root"])
        .arg(&root)
        .args(["--format", "json", "--explain"])
        .output()
        .expect("run discover");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("stdout remains JSON");

    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("$ROOT[0]"));
    assert!(stderr.contains("never followed or read"));
    assert!(!stderr.contains(root.to_string_lossy().as_ref()));
}

#[test]
fn discover_rejects_invalid_format_and_parent_root() {
    let invalid_format = agentshield()
        .args(["discover", "--no-default-paths", "--format", "sarif"])
        .output()
        .expect("run discover");
    assert_eq!(invalid_format.status.code(), Some(2));

    let invalid_root = agentshield()
        .args(["discover", "--no-default-paths", "--root", "../private"])
        .output()
        .expect("run discover");
    assert_eq!(invalid_root.status.code(), Some(2));
    let stderr = String::from_utf8(invalid_root.stderr).expect("utf8 stderr");
    assert!(stderr.contains("root[0]"));
    assert!(!stderr.contains("private"));
}
