//! A scanned target must not be able to dictate its own policy.
//!
//! The target's `.agentshield.toml` and `.agentshield/rules` are applied only
//! when the scan root is the current working directory or the caller opts in
//! explicitly. Explicit `--config` / `--rules-dir` paths are always honoured.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agentshield::{ScanOptions, scan};
use tempfile::TempDir;

const PACKAGE_JSON: &str = r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;

const VULNERABLE_TOOL: &str = r#"
import subprocess
from mcp import Server

server = Server("untrusted")

@server.tool("run")
def run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
"#;

/// A policy that would silence the command-injection finding entirely.
const SUPPRESSING_CONFIG: &str = r#"
[policy]
fail_on = "critical"
ignore_rules = ["SHIELD-001"]
"#;

/// A custom rule that fires on the vulnerable tool, proving the rules dir loaded.
const MARKER_RULE: &str = r#"
id: CUSTOM-TARGET-MARKER
name: Target marker
description: Fires when the target's own rules directory is loaded
severity: low
match:
  regex: "subprocess"
"#;

struct Target {
    dir: TempDir,
}

impl Target {
    fn new() -> Self {
        let target = Self {
            dir: TempDir::new().expect("create target dir"),
        };
        target.write("package.json", PACKAGE_JSON);
        target.write("server.py", VULNERABLE_TOOL);
        target
    }

    fn with_suppressing_config() -> Self {
        let target = Self::new();
        target.write(".agentshield.toml", SUPPRESSING_CONFIG);
        target
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.dir.path().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, contents).expect("write fixture file");
    }
}

fn has_rule(report: &agentshield::ScanReport, rule_id: &str) -> bool {
    report.findings.iter().any(|f| f.rule_id == rule_id)
}

fn run_cli(cwd: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .current_dir(cwd)
        .args(arguments)
        .env("NO_COLOR", "1")
        .output()
        .expect("run agentshield")
}

fn json_rule_ids(output: &Output) -> Vec<String> {
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must stay valid JSON");
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["rule_id"].as_str().map(str::to_owned))
        .collect()
}

fn path_str(path: &Path) -> String {
    path.to_str().expect("utf-8 temp path").to_owned()
}

// ---------------------------------------------------------------------------
// Library API
// ---------------------------------------------------------------------------

#[test]
fn library_ignores_untrusted_target_config_by_default() {
    // The test process cwd is the crate root, never the temp target.
    let target = Target::with_suppressing_config();

    let report = scan(target.path(), &ScanOptions::default()).unwrap();

    assert!(
        has_rule(&report, "SHIELD-001"),
        "a target-supplied ignore_rules must not silence findings"
    );
    assert!(
        !report.verdict.pass,
        "a target-supplied fail_on must not change the verdict"
    );
}

#[test]
fn library_applies_target_config_when_trusted() {
    let target = Target::with_suppressing_config();
    let options = ScanOptions {
        trust_target_config: true,
        ..ScanOptions::default()
    };

    let report = scan(target.path(), &options).unwrap();

    assert!(!has_rule(&report, "SHIELD-001"));
    assert!(report.verdict.pass);
}

#[test]
fn library_honours_explicit_config_path() {
    let target = Target::with_suppressing_config();
    let options = ScanOptions {
        config_path: Some(target.path().join(".agentshield.toml")),
        ..ScanOptions::default()
    };

    let report = scan(target.path(), &options).unwrap();

    assert!(!has_rule(&report, "SHIELD-001"));
    assert!(report.verdict.pass);
}

#[test]
fn library_ignores_untrusted_target_rules_dir() {
    let target = Target::new();
    target.write(".agentshield/rules/marker.yaml", MARKER_RULE);

    let untrusted = scan(target.path(), &ScanOptions::default()).unwrap();
    assert!(!has_rule(&untrusted, "CUSTOM-TARGET-MARKER"));

    let trusted = scan(
        target.path(),
        &ScanOptions {
            trust_target_config: true,
            ..ScanOptions::default()
        },
    )
    .unwrap();
    assert!(has_rule(&trusted, "CUSTOM-TARGET-MARKER"));
}

#[test]
fn library_ignores_custom_dir_named_by_untrusted_target_config() {
    let target = Target::new();
    target.write(".agentshield.toml", "[rules]\ncustom_dir = \"policy\"\n");
    target.write("policy/marker.yaml", MARKER_RULE);

    let report = scan(target.path(), &ScanOptions::default()).unwrap();

    assert!(!has_rule(&report, "CUSTOM-TARGET-MARKER"));
}

#[test]
fn library_honours_explicit_rules_dir() {
    let target = Target::new();
    let rules = TempDir::new().unwrap();
    std::fs::write(rules.path().join("marker.yaml"), MARKER_RULE).unwrap();

    let report = scan(
        target.path(),
        &ScanOptions {
            custom_rules_dir: Some(rules.path().to_path_buf()),
            ..ScanOptions::default()
        },
    )
    .unwrap();

    assert!(has_rule(&report, "CUSTOM-TARGET-MARKER"));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[test]
fn cli_scan_from_other_cwd_reports_finding_and_notices_on_stderr() {
    let target = Target::with_suppressing_config();
    target.write(".agentshield/rules/marker.yaml", MARKER_RULE);
    let elsewhere = TempDir::new().unwrap();

    let output = run_cli(
        elsewhere.path(),
        &["scan", &path_str(target.path()), "--format", "json"],
    );

    assert_eq!(output.status.code(), Some(1), "finding must fail the gate");
    let rule_ids = json_rule_ids(&output);
    assert!(rule_ids.iter().any(|id| id == "SHIELD-001"));
    assert!(!rule_ids.iter().any(|id| id == "CUSTOM-TARGET-MARKER"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--trust-target-config"), "stderr: {stderr}");
    assert!(stderr.contains(".agentshield.toml"), "stderr: {stderr}");
    assert!(stderr.contains("rules"), "stderr: {stderr}");
    assert_eq!(
        stderr.matches("--trust-target-config").count(),
        1,
        "exactly one notice expected, stderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("trust-target-config"));
}

#[test]
fn cli_notice_never_reaches_sarif_or_html_files() {
    let target = Target::with_suppressing_config();
    let elsewhere = TempDir::new().unwrap();

    for format in ["sarif", "html"] {
        let report_path: PathBuf = elsewhere.path().join(format!("report.{format}"));
        let output = run_cli(
            elsewhere.path(),
            &[
                "scan",
                &path_str(target.path()),
                "--format",
                format,
                "--output",
                &path_str(&report_path),
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        let written = std::fs::read_to_string(&report_path).unwrap();
        assert!(!written.contains("trust-target-config"));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--trust-target-config"),
            "notice expected on stderr for {format}"
        );
    }
}

#[test]
fn cli_trust_flag_applies_target_config() {
    let target = Target::with_suppressing_config();
    target.write(".agentshield/rules/marker.yaml", MARKER_RULE);
    let elsewhere = TempDir::new().unwrap();

    let output = run_cli(
        elsewhere.path(),
        &[
            "scan",
            &path_str(target.path()),
            "--format",
            "json",
            "--trust-target-config",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rule_ids = json_rule_ids(&output);
    assert!(!rule_ids.iter().any(|id| id == "SHIELD-001"));
    assert!(rule_ids.iter().any(|id| id == "CUSTOM-TARGET-MARKER"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("--trust-target-config"));
}

#[test]
fn cli_scan_with_cwd_equal_to_target_applies_config() {
    let target = Target::with_suppressing_config();

    let output = run_cli(target.path(), &["scan", ".", "--format", "json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!json_rule_ids(&output).iter().any(|id| id == "SHIELD-001"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("--trust-target-config"));
}

#[test]
fn cli_scan_with_cwd_equal_to_target_by_absolute_path_applies_config() {
    let target = Target::with_suppressing_config();

    let output = run_cli(
        target.path(),
        &["scan", &path_str(target.path()), "--format", "json"],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(!json_rule_ids(&output).iter().any(|id| id == "SHIELD-001"));
}

#[test]
fn cli_explicit_config_is_honoured() {
    let target = Target::new();
    let elsewhere = TempDir::new().unwrap();
    let config = elsewhere.path().join("policy.toml");
    std::fs::write(&config, SUPPRESSING_CONFIG).unwrap();

    let output = run_cli(
        elsewhere.path(),
        &[
            "scan",
            &path_str(target.path()),
            "--format",
            "json",
            "--config",
            &path_str(&config),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(!json_rule_ids(&output).iter().any(|id| id == "SHIELD-001"));
}

#[test]
fn cli_certify_ignores_untrusted_target_suppressions() {
    let target = Target::with_suppressing_config();
    let elsewhere = TempDir::new().unwrap();

    let output = run_cli(elsewhere.path(), &["certify", &path_str(target.path())]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    let payload = envelope["payload"].as_str().expect("payload");
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .expect("base64 payload");
    let decoded = String::from_utf8(decoded).expect("utf-8 payload");
    assert!(
        decoded.contains("SHIELD-001"),
        "attestation must include the finding the target tried to ignore"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("--trust-target-config"));
}
