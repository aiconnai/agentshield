//! End-to-end regression tests for parser accuracy: multi-line Python calls,
//! sink resolution through imports, shell false positives, and sanitizer scope.

use std::path::Path;

use agentshield::{ScanOptions, scan};

const PACKAGE_JSON: &str =
    r#"{"name":"case","version":"1.0.0","dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;
const PY_HEAD: &str = "from mcp import Server\n\nserver = Server(\"case\")\n\n\n";

fn package(files: &[(&str, String)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(dir.path().join("package.json"), PACKAGE_JSON).expect("write package.json");
    for (rel, content) in files {
        let target = dir.path().join(rel);
        std::fs::create_dir_all(target.parent().expect("fixture path has a parent"))
            .expect("create fixture dir");
        std::fs::write(target, content).expect("write fixture file");
    }
    dir
}

fn flagged(root: &Path, rule_id: &str) -> bool {
    scan(root, &ScanOptions::default())
        .expect("scan succeeds")
        .findings
        .iter()
        .any(|finding| finding.rule_id == rule_id)
}

fn py_case(body: &str) -> tempfile::TempDir {
    package(&[("server.py", format!("{PY_HEAD}{body}"))])
}

// --- 1. Multi-line Python calls -------------------------------------------

#[test]
fn python_black_formatted_concatenation_is_flagged() {
    let dir = py_case(
        "import os\n\n\n@server.tool(\"ls\")\ndef ls(user: str) -> int:\n    return os.system(\n        \"ls \"\n        + user\n        + \" -la\"\n    )\n",
    );
    assert!(flagged(dir.path(), "SHIELD-001"));
}

#[test]
fn python_multiline_subprocess_run_with_concatenation_is_flagged() {
    let dir = py_case(
        "import subprocess\n\n\n@server.tool(\"ls\")\ndef ls(user: str) -> object:\n    return subprocess.run(\n        \"ls \"\n        + user,\n        shell=True,\n    )\n",
    );
    assert!(flagged(dir.path(), "SHIELD-001"));
}

#[test]
fn python_first_argument_on_call_line_with_continuation_is_flagged() {
    let dir = py_case(
        "import subprocess\n\n\n@server.tool(\"ls\")\ndef ls(cmd: str) -> object:\n    return subprocess.run(cmd,\n                          shell=True)\n",
    );
    assert!(flagged(dir.path(), "SHIELD-001"));
}

#[test]
fn python_multiline_literal_command_stays_clean() {
    let dir = py_case(
        "import os\n\n\n@server.tool(\"ls\")\ndef ls() -> int:\n    return os.system(\n        \"ls -la\"\n    )\n",
    );
    assert!(!flagged(dir.path(), "SHIELD-001"));
}

#[test]
fn python_multiline_adjacent_literals_stay_clean() {
    let dir = py_case(
        "import os\n\n\n@server.tool(\"ls\")\ndef ls() -> int:\n    return os.system(\n        \"ls \"\n        \"-la\"  # not a call (really)\n    )\n",
    );
    assert!(!flagged(dir.path(), "SHIELD-001"));
}

#[test]
fn python_parens_in_strings_and_comments_do_not_end_the_call() {
    let dir = py_case(
        "import os\n\n\n@server.tool(\"ls\")\ndef ls(user: str) -> int:\n    return os.system(\n        \"echo ) \"  # closing ) in a comment\n        + user\n    )\n",
    );
    assert!(flagged(dir.path(), "SHIELD-001"));
}

// --- 2b. Python import aliases --------------------------------------------

#[test]
fn python_import_aliases_resolve_to_process_sinks() {
    let cases = [
        ("from subprocess import run", "run(cmd, shell=True)"),
        ("from subprocess import Popen as P", "P(cmd, shell=True)"),
        (
            "from subprocess import (\n    run,\n    Popen,\n)",
            "run(cmd, shell=True)",
        ),
        ("from os import system", "system(cmd)"),
        ("from os import system as sh", "sh(cmd)"),
        ("import subprocess as sp", "sp.run(cmd, shell=True)"),
        (
            "import os as operating_system",
            "operating_system.system(cmd)",
        ),
    ];
    for (import, call) in cases {
        let dir = py_case(&format!(
            "{import}\n\n\n@server.tool(\"x\")\ndef x(cmd: str) -> object:\n    return {call}\n"
        ));
        assert!(
            flagged(dir.path(), "SHIELD-001"),
            "expected SHIELD-001 for `{import}` + `{call}`"
        );
    }
}

#[test]
fn python_local_run_function_is_not_a_process_sink() {
    let dir = py_case(
        "def run(cmd: str) -> str:\n    return cmd\n\n\n@server.tool(\"x\")\ndef x(cmd: str) -> str:\n    return run(cmd)\n",
    );
    assert!(!flagged(dir.path(), "SHIELD-001"));
}
