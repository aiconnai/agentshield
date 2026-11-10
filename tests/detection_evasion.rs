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

#[test]
fn production_call_site_does_not_clear_python_tool_handler() {
    let dir = package(&[
        ("server.py", py(RUN_CMD)),
        (
            "cli.py",
            b"from server import run_cmd\n\n\ndef main():\n    run_cmd(\"ls\")\n".to_vec(),
        ),
    ]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn production_call_site_does_not_clear_typescript_tool_handler() {
    let dir = package(&[
        (
            "server.ts",
            ts("export async function runCmd(cmd: string): Promise<void> {\n  exec(cmd);\n}\n\nserver.tool(\"run_cmd\", { cmd: { type: \"string\" } }, runCmd);\n"),
        ),
        (
            "cli.ts",
            b"import { runCmd } from \"./server\";\n\nexport function main(): void {\n  runCmd(\"ls\");\n}\n"
                .to_vec(),
        ),
    ]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn literal_only_helper_called_from_tool_handler_stays_clean() {
    let dir = package(&[(
        "server.py",
        py(
            "def list_root(path):\n    return subprocess.run(path, shell=True).stdout\n\n\n@server.tool(\"ls\")\ndef ls() -> str:\n    return list_root(\"ls -la\")\n",
        ),
    )]);
    assert!(!has_command_injection(dir.path()));
}

const CLI_PY: &str = "from server import run_cmd\n\n\ndef main():\n    run_cmd(\"ls\")\n";
const CLI_TS: &str = "import { runCmd } from \"./handlers\";\n\nexport function main(): void {\n  runCmd(\"ls\");\n}\n";
const HANDLERS_TS: &str = "import { exec } from \"child_process\";\n\nexport async function runCmd(cmd: string): Promise<void> {\n  exec(cmd);\n}\n";

fn python_handler_called_from_cli(decorator: &str) -> bool {
    let body = format!(
        "{decorator}\ndef run_cmd(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n"
    );
    let dir = package(&[
        ("server.py", py(&body)),
        ("cli.py", CLI_PY.as_bytes().to_vec()),
    ]);
    has_command_injection(dir.path())
}

fn typescript_handler_registered_as(registration: &str) -> bool {
    let dir = package(&[
        ("handlers.ts", HANDLERS_TS.as_bytes().to_vec()),
        ("server.ts", ts(registration)),
        ("cli.ts", CLI_TS.as_bytes().to_vec()),
    ]);
    has_command_injection(dir.path())
}

#[test]
fn comment_after_bare_tool_decorator_still_marks_handler() {
    assert!(python_handler_called_from_cli(
        "@server.tool  # exposed to the agent"
    ));
}

#[test]
fn unbalanced_paren_in_decorator_string_still_marks_handler() {
    assert!(python_handler_called_from_cli(
        "@server.tool(\"run_cmd\", description=\"(\")"
    ));
}

#[test]
fn unbalanced_paren_in_multiline_decorator_comment_still_marks_handler() {
    assert!(python_handler_called_from_cli(
        "@server.tool(  # (\n    \"run_cmd\",\n)"
    ));
}

#[test]
fn other_agent_exposed_decorators_mark_handlers() {
    for decorator in [
        "@agent.tool_plain",
        "@server.call_tool()",
        "@server.resource(\"file://{cmd}\")",
        "@mcp.prompt()",
    ] {
        assert!(python_handler_called_from_cli(decorator), "{decorator}");
    }
}

#[test]
fn decoy_registration_with_same_tool_name_does_not_hide_handler() {
    assert!(typescript_handler_registered_as(
        "import { runCmd } from \"./handlers\";\n\nfunction decoy(): void {}\n\nserver.tool(\"run_cmd\", {}, decoy);\nserver.tool(\"run_cmd\", {}, runCmd);\n"
    ));
}

#[test]
fn namespaced_handler_reference_marks_handler() {
    assert!(typescript_handler_registered_as(
        "import * as handlers from \"./handlers\";\n\nserver.tool(\"run_cmd\", {}, handlers.runCmd);\n"
    ));
}

#[test]
fn aliased_handler_import_marks_handler() {
    assert!(typescript_handler_registered_as(
        "import { runCmd as rc } from \"./handlers\";\n\nserver.tool(\"run_cmd\", {}, rc);\n"
    ));
}

#[test]
fn wrapped_handler_reference_marks_handler() {
    assert!(typescript_handler_registered_as(
        "import { runCmd } from \"./handlers\";\n\nconst withLog = (f: any) => f;\n\nserver.tool(\"run_cmd\", {}, withLog(runCmd));\nserver.tool(\"run_bound\", {}, runCmd.bind(null));\n"
    ));
}

#[test]
fn plain_handler_reference_marks_handler() {
    assert!(typescript_handler_registered_as(
        "import { runCmd } from \"./handlers\";\n\nserver.tool(\"run_cmd\", {}, runCmd);\n"
    ));
}
