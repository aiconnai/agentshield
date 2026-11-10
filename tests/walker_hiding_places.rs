//! Regression tests for the places a scanned package could hide a payload
//! from the file walker: ignore files, look-alike tooling directories,
//! oversized files and deep nesting. The scanned tree is untrusted input.

use std::path::Path;

use agentshield::adapter::Adapter;
use agentshield::adapter::hermes::HermesAgentAdapter;
use agentshield::adapter::openclaw::OpenClawAdapter;
use agentshield::adapter::vercel_ai::VercelAiAdapter;
use agentshield::coverage::ScanCoverage;
use agentshield::{ScanOptions, scan, scan_with_coverage};

const PACKAGE_JSON: &str =
    r#"{"name":"case","version":"1.0.0","dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;
const PY_HEAD: &str =
    "import os\nimport subprocess\n\nfrom mcp import Server\n\nserver = Server(\"case\")\n\n\n";
const RUN_CMD: &str = "@server.tool(\"run_cmd\")\ndef run_cmd(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n";
const SAFE_TOOL: &str =
    "@server.tool(\"add\")\ndef add(a: int, b: int) -> int:\n    return a + b\n";

fn write(root: &Path, rel: &str, content: impl AsRef<[u8]>) {
    let target = root.join(rel);
    std::fs::create_dir_all(target.parent().expect("fixture path has a parent"))
        .expect("create fixture dir");
    std::fs::write(target, content).expect("write fixture file");
}

fn py(body: &str) -> Vec<u8> {
    format!("{PY_HEAD}{body}").into_bytes()
}

/// A package with a safe visible server plus the given extra files.
fn package(files: &[(&str, Vec<u8>)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    write(dir.path(), "package.json", PACKAGE_JSON);
    write(dir.path(), "server.py", py(SAFE_TOOL));
    for (rel, content) in files {
        write(dir.path(), rel, content);
    }
    dir
}

fn report(root: &Path) -> agentshield::ScanReport {
    scan(root, &ScanOptions::default()).expect("scan succeeds")
}

fn covered(root: &Path) -> (agentshield::ScanReport, ScanCoverage) {
    scan_with_coverage(root, &ScanOptions::default(), &[], &[]).expect("scan succeeds")
}

fn has_command_injection(root: &Path) -> bool {
    report(root)
        .findings
        .iter()
        .any(|finding| finding.rule_id == "SHIELD-001")
}

fn payload() -> Vec<u8> {
    py(RUN_CMD)
}

#[test]
fn gitignore_in_a_fake_git_repo_cannot_hide_a_payload() {
    let dir = package(&[
        ("payload.py", payload()),
        (".gitignore", b"payload.py\n".to_vec()),
    ]);
    std::fs::create_dir(dir.path().join(".git")).expect("create empty .git");
    assert!(has_command_injection(dir.path()));
}

#[test]
fn parent_gitignore_cannot_hide_a_payload() {
    let outer = tempfile::tempdir().expect("create temp dir");
    std::fs::create_dir(outer.path().join(".git")).expect("create parent .git");
    write(outer.path(), ".gitignore", "payload.py\n");
    let pkg = outer.path().join("pkg");
    write(&pkg, "package.json", PACKAGE_JSON);
    write(&pkg, "server.py", py(SAFE_TOOL));
    write(&pkg, "payload.py", payload());
    assert!(has_command_injection(&pkg));
}

#[test]
fn git_info_exclude_cannot_hide_a_payload() {
    let dir = package(&[("payload.py", payload())]);
    write(dir.path(), ".git/info/exclude", "payload.py\n");
    write(dir.path(), ".git/HEAD", "ref: refs/heads/main\n");
    assert!(has_command_injection(dir.path()));
}

#[test]
fn fake_venv_without_pyvenv_cfg_cannot_hide_a_payload() {
    let dir = package(&[(".venv/payload.py", payload())]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn fake_venv_named_venv_cannot_hide_a_payload() {
    let dir = package(&[("venv/payload.py", payload())]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn fake_git_directory_without_head_cannot_hide_a_payload() {
    let dir = package(&[(".git/x/payload.py", payload())]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn nested_node_modules_without_markers_cannot_hide_a_payload() {
    let dir = package(&[("src/node_modules/payload.py", payload())]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn build_and_dist_directories_are_scanned() {
    let dir = package(&[("dist/payload.py", payload())]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn real_venv_with_pyvenv_cfg_stays_skipped() {
    let dir = package(&[
        (".venv/pyvenv.cfg", b"home = /usr/bin\n".to_vec()),
        (".venv/lib/payload.py", payload()),
    ]);
    assert!(!has_command_injection(dir.path()));
}

#[test]
fn real_git_directory_with_head_stays_skipped() {
    let dir = package(&[
        (".git/HEAD", b"ref: refs/heads/main\n".to_vec()),
        (".git/hooks/payload.py", payload()),
    ]);
    assert!(!has_command_injection(dir.path()));
}

#[test]
fn root_node_modules_stays_pruned() {
    let dir = package(&[("node_modules/dep/payload.py", payload())]);
    assert!(!has_command_injection(dir.path()));
}

#[test]
fn root_directory_named_like_a_pruned_directory_is_still_scanned() {
    let outer = tempfile::tempdir().expect("create temp dir");
    let pkg = outer.path().join("node_modules");
    write(&pkg, "package.json", PACKAGE_JSON);
    write(&pkg, "server.py", py(SAFE_TOOL));
    write(&pkg, "payload.py", payload());
    assert!(has_command_injection(&pkg));
}

#[test]
fn payload_padded_past_one_mebibyte_is_still_scanned() {
    let mut padded = PY_HEAD.as_bytes().to_vec();
    padded.extend(b"# ".iter().chain(&vec![b'x'; 1_100_000]));
    padded.extend(b"\n\n");
    padded.extend(RUN_CMD.as_bytes());
    let dir = package(&[("payload.py", padded)]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn payload_past_the_hard_cap_is_reported_not_silently_dropped() {
    let mut huge = PY_HEAD.as_bytes().to_vec();
    huge.extend(RUN_CMD.as_bytes());
    huge.extend(b"\n# ".iter().chain(&vec![b'x'; 9 * 1024 * 1024]));
    let dir = package(&[("payload.py", huge)]);
    let (report, coverage) = covered(dir.path());
    // The head of the file is still scanned...
    assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-001"));
    // ...and the truncation is surfaced.
    assert!(
        coverage
            .skipped
            .iter()
            .any(|entry| entry.path == "payload.py" && entry.reason.as_str() == "truncated"),
        "coverage: {coverage:?}"
    );
}

#[test]
fn deeply_nested_payload_is_scanned() {
    let nested = (0..65)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let dir = package(&[(&format!("{nested}/payload.py"), payload())]);
    assert!(has_command_injection(dir.path()));
}

#[test]
fn pruned_directories_are_reported_in_coverage() {
    let dir = package(&[("node_modules/dep/index.js", b"x\n".to_vec())]);
    let (_, coverage) = covered(dir.path());
    assert!(
        coverage
            .skipped
            .iter()
            .any(|entry| entry.path == "node_modules" && entry.reason.as_str() == "pruned"),
        "coverage: {coverage:?}"
    );
}

#[test]
fn json_report_carries_additive_coverage_field() {
    let dir = package(&[("node_modules/dep/index.js", b"x\n".to_vec())]);
    let (report, coverage) = covered(dir.path());
    let rendered = agentshield::render_report_with_coverage(
        &report,
        agentshield::output::OutputFormat::Json,
        &coverage,
    )
    .expect("render json");
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert!(value["coverage"]["skipped"].is_array(), "{rendered}");
    assert_eq!(value["coverage"]["skipped"][0]["path"], "node_modules");
}

#[cfg(unix)]
#[test]
fn unreadable_directory_is_reported() {
    use std::os::unix::fs::PermissionsExt;

    let dir = package(&[("locked/payload.py", payload())]);
    let locked = dir.path().join("locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("chmod locked dir");
    if std::fs::read_dir(&locked).is_ok() {
        // Running as a user that bypasses permissions (for example root).
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
        return;
    }
    let (_, coverage) = covered(dir.path());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
    assert!(
        coverage
            .skipped
            .iter()
            .any(|entry| entry.path == "locked" && entry.reason.as_str() == "unreadable"),
        "coverage: {coverage:?}"
    );
}

#[test]
fn user_directory_excludes_still_apply() {
    let dir = package(&[
        ("vendor/payload.py", payload()),
        ("lib/nested/payload.py", payload()),
        (
            ".agentshield.toml",
            b"[scan]\nexclude = [\"vendor/**\", \"lib/*\"]\n".to_vec(),
        ),
    ]);
    // The config lives in a temp dir, not the cwd, so it applies only when
    // the caller opts in to the target's policy.
    let options = ScanOptions {
        trust_target_config: true,
        ..ScanOptions::default()
    };
    let report = scan(dir.path(), &options).expect("scan succeeds");
    let flagged: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "SHIELD-001")
        .filter_map(|f| f.location.as_ref().map(|l| l.file.display().to_string()))
        .collect();
    // `vendor/**` prunes the directory; `lib/*` only matches direct children,
    // so the nested file stays in scope.
    assert!(flagged.iter().all(|file| !file.contains("vendor")));
    assert!(flagged.iter().any(|file| file.contains("lib/nested")));
}

// ---- Framework adapters that used to build their own walker ----

fn loaded_paths(adapter: &dyn Adapter, root: &Path) -> Vec<String> {
    adapter
        .load(root, false)
        .expect("adapter loads")
        .iter()
        .flat_map(|target| target.source_files.iter())
        .map(|file| {
            file.path
                .strip_prefix(root)
                .unwrap_or(&file.path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn openclaw_skill_sees_hidden_and_deep_files() {
    let dir = tempfile::tempdir().expect("create temp dir");
    write(dir.path(), "SKILL.md", "# skill\n");
    write(dir.path(), ".hidden/payload.py", payload());
    write(dir.path(), "a/b/c/d/e/f/deep.py", payload());
    let paths = loaded_paths(&OpenClawAdapter, dir.path());
    assert!(
        paths.contains(&".hidden/payload.py".to_owned()),
        "{paths:?}"
    );
    assert!(
        paths.contains(&"a/b/c/d/e/f/deep.py".to_owned()),
        "{paths:?}"
    );
}

#[test]
fn openclaw_skill_ignores_ignore_files_and_reads_non_utf8() {
    let dir = tempfile::tempdir().expect("create temp dir");
    write(dir.path(), "SKILL.md", "# skill\n");
    write(dir.path(), ".gitignore", "ignored.py\n");
    std::fs::create_dir(dir.path().join(".git")).expect("create empty .git");
    write(dir.path(), "ignored.py", payload());
    let mut latin1 = payload();
    latin1.extend(b"# caf\xe9\n");
    write(dir.path(), "latin1.py", latin1);
    let paths = loaded_paths(&OpenClawAdapter, dir.path());
    assert!(paths.contains(&"ignored.py".to_owned()), "{paths:?}");
    assert!(paths.contains(&"latin1.py".to_owned()), "{paths:?}");
}

#[test]
fn openclaw_nested_skills_are_not_double_counted_in_the_root_skill() {
    let dir = tempfile::tempdir().expect("create temp dir");
    write(dir.path(), "SKILL.md", "# root\n");
    write(dir.path(), ".agents/skills/inner/SKILL.md", "# inner\n");
    write(dir.path(), ".agents/skills/inner/tool.py", payload());
    let targets = OpenClawAdapter
        .load(dir.path(), false)
        .expect("adapter loads");
    let owners = targets
        .iter()
        .filter(|target| {
            target
                .source_files
                .iter()
                .any(|file| file.path.ends_with("inner/tool.py"))
        })
        .count();
    assert_eq!(owners, 1);
}

#[test]
fn hermes_skill_tree_sees_hidden_and_deep_files() {
    let dir = tempfile::tempdir().expect("create temp dir");
    write(dir.path(), ".hermes.md", "# hermes\n");
    write(dir.path(), "skills/s/SKILL.md", "# s\n");
    write(dir.path(), "skills/.hidden/payload.py", payload());
    write(dir.path(), "skills/a/b/c/d/e/f/g/h/deep.py", payload());
    let paths = loaded_paths(&HermesAgentAdapter, dir.path());
    assert!(
        paths.contains(&"skills/.hidden/payload.py".to_owned()),
        "{paths:?}"
    );
    assert!(
        paths.contains(&"skills/a/b/c/d/e/f/g/h/deep.py".to_owned()),
        "{paths:?}"
    );
}

#[test]
fn vercel_ai_detection_sees_deep_and_hidden_imports() {
    let deep = tempfile::tempdir().expect("create temp dir");
    write(
        deep.path(),
        "a/b/c/d/e/f/tool.ts",
        "import { generateText } from 'ai';\n",
    );
    assert!(VercelAiAdapter.detect(deep.path()));

    let hidden = tempfile::tempdir().expect("create temp dir");
    write(
        hidden.path(),
        ".src/tool.ts",
        "import { generateText } from 'ai';\n",
    );
    assert!(VercelAiAdapter.detect(hidden.path()));
}
