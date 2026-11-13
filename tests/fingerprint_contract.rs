//! Contract tests for finding fingerprints (scheme v2) and their
//! compatibility with schema-v1 baselines and legacy suppressions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use agentshield::rules::fingerprint::compute_fingerprints;
use agentshield::{ScanOptions, scan};

const SSRF: &str = "tests/fixtures/mcp_servers/vuln_ssrf";
const CMD_INJECT: &str = "tests/fixtures/mcp_servers/vuln_cmd_inject";

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args(arguments)
        .output()
        .expect("run agentshield")
}

fn json_findings(arguments: &[&str]) -> Vec<serde_json::Value> {
    let output = run(arguments);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "parse JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    report["findings"].as_array().expect("findings").clone()
}

fn fingerprints(findings: &[serde_json::Value]) -> Vec<String> {
    let mut fps: Vec<String> = findings
        .iter()
        .map(|f| f["fingerprint"].as_str().expect("fingerprint").to_owned())
        .collect();
    fps.sort();
    fps
}

fn absolute(path: &str) -> PathBuf {
    Path::new(path).canonicalize().expect("canonical fixture")
}

#[test]
fn same_rule_findings_in_one_file_have_distinct_fingerprints() {
    let findings = json_findings(&["scan", SSRF, "--format", "json"]);
    let fps = fingerprints(&findings);
    let unique: HashSet<_> = fps.iter().collect();
    assert_eq!(unique.len(), fps.len(), "fingerprints collide: {fps:?}");
}

#[test]
fn relative_and_absolute_scan_paths_give_equal_fingerprints() {
    let abs = absolute(SSRF);
    let relative = fingerprints(&json_findings(&["scan", SSRF, "--format", "json"]));
    let absolute = fingerprints(&json_findings(&[
        "scan",
        abs.to_str().expect("utf-8"),
        "--format",
        "json",
    ]));
    assert!(!relative.is_empty());
    assert_eq!(relative, absolute);
}

#[test]
fn sarif_fingerprint_property_matches_json() {
    let json = fingerprints(&json_findings(&["scan", SSRF, "--format", "json"]));
    let output = run(&["scan", SSRF, "--format", "sarif"]);
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).expect("sarif");
    let mut sarif_fps: Vec<String> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| {
            r["properties"]["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .to_owned()
        })
        .collect();
    sarif_fps.sort();
    let json_set: HashSet<_> = json.iter().collect();
    assert!(sarif_fps.iter().all(|fp| json_set.contains(fp)));
}

#[test]
fn written_baseline_is_schema_v2_and_portable_across_scan_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let baseline = dir.path().join("baseline.json");
    let baseline_arg = baseline.to_str().expect("utf-8");

    let output = run(&["scan", SSRF, "--write-baseline", baseline_arg]);
    assert!(output.status.code().is_some());
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).expect("read")).expect("json");
    assert_eq!(written["schema_version"], 2);

    let abs = absolute(SSRF);
    let findings = json_findings(&[
        "scan",
        abs.to_str().expect("utf-8"),
        "--format",
        "json",
        "--baseline",
        baseline_arg,
    ]);
    assert!(findings.is_empty(), "baseline must hide all: {findings:?}");
}

#[test]
fn schema_v1_baseline_with_legacy_fingerprints_still_suppresses() {
    let report = scan(Path::new(CMD_INJECT), &ScanOptions::default()).expect("scan");
    assert!(!report.findings.is_empty());
    let entries: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "fingerprint": f.legacy_fingerprint(&report.scan_root),
                "rule_id": f.rule_id,
                "first_seen": "2026-01-01T00:00:00Z",
            })
        })
        .collect();
    let legacy = serde_json::json!({
        "schema_version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "tool_version": "1.0.2",
        "entries": entries,
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let baseline = dir.path().join("v1.json");
    std::fs::write(&baseline, legacy.to_string()).expect("write");

    let output = run(&[
        "scan",
        CMD_INJECT,
        "--format",
        "json",
        "--baseline",
        baseline.to_str().expect("utf-8"),
    ]);
    assert_eq!(output.status.code(), Some(0), "all findings are baselined");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["findings"].as_array().expect("findings").len(), 0);
}

fn copy_fixture(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).expect("read fixture") {
        let entry = entry.expect("entry");
        let target = dst.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            std::fs::create_dir_all(&target).expect("mkdir");
            copy_fixture(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
}

#[test]
fn v2_suppression_hides_only_one_of_two_colliding_findings() {
    let dir = tempfile::tempdir().expect("tempdir");
    copy_fixture(Path::new(SSRF), dir.path());
    let root = dir.path().to_str().expect("utf-8");

    let before = json_findings(&["scan", root, "--format", "json"]);
    // Pick a pair that the legacy scheme could not tell apart.
    let report = scan(dir.path(), &ScanOptions::default()).expect("scan");
    let legacy: Vec<String> = report
        .findings
        .iter()
        .map(|f| f.legacy_fingerprint(&report.scan_root))
        .collect();
    let colliding = legacy
        .iter()
        .find(|fp| legacy.iter().filter(|other| other == fp).count() > 1)
        .expect("fixture has colliding legacy fingerprints");
    let index = legacy.iter().position(|fp| fp == colliding).expect("index");
    let target = compute_fingerprints(&report.findings, &report.scan_root)[index].clone();

    let config = dir.path().join(".agentshield.toml");
    std::fs::write(
        &config,
        format!("[[policy.suppressions]]\nfingerprint = \"{target}\"\nreason = \"accepted\"\n"),
    )
    .expect("config");

    // The suppression lives in the target's own config, which a scan from
    // another cwd applies only on opt-in.
    let after = json_findings(&["scan", root, "--format", "json", "--trust-target-config"]);
    assert_eq!(after.len() + 1, before.len(), "exactly one suppressed");
    assert!(fingerprints(&after).iter().all(|fp| fp != &target));
}

#[test]
fn legacy_suppression_fingerprint_still_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    copy_fixture(Path::new(CMD_INJECT), dir.path());
    let root = dir.path().to_str().expect("utf-8");

    let report = scan(dir.path(), &ScanOptions::default()).expect("scan");
    let before = report.findings.len();
    let legacy = report.findings[0].legacy_fingerprint(&report.scan_root);
    let colliding = report
        .findings
        .iter()
        .filter(|f| f.legacy_fingerprint(&report.scan_root) == legacy)
        .count();
    std::fs::write(
        dir.path().join(".agentshield.toml"),
        format!("[[policy.suppressions]]\nfingerprint = \"{legacy}\"\nreason = \"old\"\n"),
    )
    .expect("config");

    // The suppression lives in the target's own config, which a scan from
    // another cwd applies only on opt-in.
    let after = json_findings(&["scan", root, "--format", "json", "--trust-target-config"]);
    assert_eq!(after.len(), before - colliding);
}
