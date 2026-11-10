//! Regression tests for ways a scanned package could hide a vulnerable sink
//! from the scanner (false negatives) or stall it.

use std::path::Path;
use std::time::{Duration, Instant};

use agentshield::{ScanOptions, scan};

const PACKAGE_JSON: &str =
    r#"{"name":"case","version":"1.0.0","dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;
const PY_HEAD: &str =
    "import os\nimport subprocess\n\nfrom mcp import Server\n\nserver = Server(\"case\")\n\n\n";
const RUN_CMD: &str = "@server.tool(\"run_cmd\")\ndef run_cmd(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n";
const SAFE_TOOL: &str =
    "@server.tool(\"add\")\ndef add(a: int, b: int) -> int:\n    return a + b\n";
const TS_HEAD: &str = "import { Server } from \"@modelcontextprotocol/sdk/server\";\nimport { exec } from \"child_process\";\n\nconst server = new Server({ name: \"case\", version: \"1.0.0\" });\n\n";

fn write(root: &Path, rel: &str, content: impl AsRef<[u8]>) {
    let target = root.join(rel);
    std::fs::create_dir_all(target.parent().expect("fixture path has a parent"))
        .expect("create fixture dir");
    std::fs::write(target, content).expect("write fixture file");
}

fn package(files: &[(&str, Vec<u8>)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    write(dir.path(), "package.json", PACKAGE_JSON);
    for (rel, content) in files {
        write(dir.path(), rel, content);
    }
    dir
}

fn has_command_injection(root: &Path) -> bool {
    scan(root, &ScanOptions::default())
        .expect("scan succeeds")
        .findings
        .iter()
        .any(|finding| finding.rule_id == "SHIELD-001")
}

fn py(body: &str) -> Vec<u8> {
    format!("{PY_HEAD}{body}").into_bytes()
}

fn ts(body: &str) -> Vec<u8> {
    format!("{TS_HEAD}{body}").into_bytes()
}

#[test]
fn python_quote_bounded_concatenation_is_not_a_literal() {
    let dir = package(&[(
        "server.py",
        py(
            "@server.tool(\"ls\")\ndef ls(user: str) -> int:\n    return os.system(\"ls \" + user + \" -la\")\n",
        ),
    )]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn typescript_quote_bounded_concatenation_is_not_a_literal() {
    let dir = package(&[(
        "server.ts",
        ts(
            "async function listDir(dir: string): Promise<void> {\n  exec('ls ' + dir + ' -la');\n}\n",
        ),
    )]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn literal_command_stays_clean() {
    let dir = package(&[(
        "server.py",
        py("@server.tool(\"ls\")\ndef ls() -> int:\n    return os.system(\"ls -la\")\n"),
    )]);
    assert!(!has_command_injection(dir.path()));
}

#[test]
fn python_implicit_literal_concatenation_stays_clean() {
    let dir = package(&[(
        "server.py",
        py("@server.tool(\"ls\")\ndef ls() -> int:\n    return os.system(\"ls \" \"-la\")\n"),
    )]);
    assert!(!has_command_injection(dir.path()));
}

#[test]
fn python_implicit_concatenation_with_a_parameter_is_flagged() {
    let dir = package(&[(
        "server.py",
        py(
            "@server.tool(\"ls\")\ndef ls(user: str) -> int:\n    return os.system(\"ls \" \"-la\" + user)\n",
        ),
    )]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn test_file_call_site_does_not_clear_tool_handler() {
    let dir = package(&[
        ("server.py", py(RUN_CMD)),
        (
            "tests/test_server.py",
            b"from server import run_cmd\n\n\ndef test_it():\n    assert run_cmd(\"ls\")\n"
                .to_vec(),
        ),
    ]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn dot_ignore_file_cannot_hide_a_payload() {
    let dir = package(&[
        ("server.py", py(SAFE_TOOL)),
        ("payload.py", py(RUN_CMD)),
        (".ignore", b"payload.py\n".to_vec()),
    ]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn hidden_directory_cannot_hide_a_payload() {
    let dir = package(&[
        ("server.py", py(SAFE_TOOL)),
        (".hidden/payload.py", py(RUN_CMD)),
    ]);
    assert!(has_command_injection(dir.path()));
}

fn bare_tree(files: &[(&str, Vec<u8>)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    for (rel, content) in files {
        write(dir.path(), rel, content);
    }
    dir
}

#[test]
fn python_mcp_server_only_in_dot_directory_is_detected() {
    let dir = bare_tree(&[(".srv/server.py", py(RUN_CMD))]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn crewai_tool_only_in_dot_directory_is_detected() {
    let dir = bare_tree(&[(
        ".src/tools.py",
        b"import subprocess\nfrom crewai.tools import tool\n\n\n@tool(\"run\")\ndef run(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True).stdout\n"
            .to_vec(),
    )]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn non_utf8_byte_cannot_hide_a_python_mcp_server() {
    let mut source = py(RUN_CMD);
    source.extend_from_slice(b"# caf\xe9\n");
    let dir = bare_tree(&[("server.py", source)]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn deep_nesting_cannot_hide_a_payload() {
    let dir = package(&[
        ("server.py", py(SAFE_TOOL)),
        ("a/b/c/d/e/f/g/payload.py", py(RUN_CMD)),
    ]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn non_utf8_byte_cannot_hide_a_payload() {
    let mut payload = py(RUN_CMD);
    payload.extend_from_slice(b"# caf\xe9 latin-1 comment\n");
    let dir = package(&[("server.py", py(SAFE_TOOL)), ("payload.py", payload)]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn dense_call_graph_does_not_stall_the_scan() {
    let functions = 14;
    let mut source = String::from(PY_HEAD);
    for i in 0..functions {
        source.push_str(&format!("def f{i}(x):\n"));
        if i == 0 {
            source.push_str("    x = os.environ.get(\"A\")\n");
        }
        for j in (0..functions).filter(|j| *j != i) {
            source.push_str(&format!("    f{j}(x)\n"));
        }
        source.push_str("    return x\n\n\n");
    }
    source.push_str("@server.tool(\"go\")\ndef go(x: str) -> str:\n    return f0(x)\n");
    let dir = package(&[("server.py", source.into_bytes())]);

    let started = Instant::now();
    scan(dir.path(), &ScanOptions::default()).expect("scan succeeds");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "scan took {:?}",
        started.elapsed()
    );
}
