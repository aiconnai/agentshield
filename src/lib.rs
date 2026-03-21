//! AgentShield — Security scanner for AI agent extensions.
//!
//! Offline-first, multi-framework, SARIF output. Scans MCP servers,
//! OpenClaw skills, and other agent extension formats for security issues.
//!
//! # Quick Start
//!
//! ```no_run
//! use std::path::Path;
//! use agentshield::{scan, ScanOptions};
//!
//! let options = ScanOptions::default();
//! let report = scan(Path::new("./my-mcp-server"), &options).unwrap();
//! println!("Pass: {}, Findings: {}", report.verdict.pass, report.findings.len());
//! ```

pub mod adapter;
pub mod analysis;
pub mod baseline;
pub mod config;
pub mod error;
pub mod ir;
pub mod output;
pub mod parser;
pub mod rules;

use std::path::Path;

use config::Config;
use error::Result;
use output::OutputFormat;
use rules::policy::PolicyVerdict;
use rules::{Finding, RuleEngine};

/// Options for a scan invocation.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Path to config file (defaults to `.agentshield.toml` in scan dir).
    pub config_path: Option<std::path::PathBuf>,
    /// Output format.
    pub format: OutputFormat,
    /// CLI override for fail_on threshold.
    pub fail_on_override: Option<rules::Severity>,
    /// Skip test files (test/, tests/, *.test.ts, *.spec.ts, etc.).
    pub ignore_tests: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            config_path: None,
            format: OutputFormat::Console,
            fail_on_override: None,
            ignore_tests: false,
        }
    }
}

/// Complete scan report.
#[derive(Debug)]
pub struct ScanReport {
    pub target_name: String,
    pub findings: Vec<Finding>,
    pub verdict: PolicyVerdict,
    /// Absolute (or canonicalized) path to the scanned directory.
    /// Passed to output renderers for stable fingerprint computation.
    pub scan_root: std::path::PathBuf,
}

/// Run a complete scan: detect framework, parse, analyze, evaluate policy.
pub fn scan(path: &Path, options: &ScanOptions) -> Result<ScanReport> {
    // Load config
    let config_path = options
        .config_path
        .clone()
        .unwrap_or_else(|| path.join(".agentshield.toml"));
    let mut config = Config::load(&config_path)?;

    // Apply CLI override
    if let Some(fail_on) = options.fail_on_override {
        config.policy.fail_on = fail_on;
    }

    // Auto-detect framework and load IR
    let ignore_tests = options.ignore_tests || config.scan.ignore_tests;
    let targets = adapter::auto_detect_and_load(path, ignore_tests)?;

    // Run detectors on all targets
    let engine = RuleEngine::new();
    let mut all_findings: Vec<Finding> = Vec::new();

    let target_name = if let Some(first) = targets.first() {
        first.name.clone()
    } else {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into())
    };

    for target in &targets {
        let findings = engine.run(target);
        all_findings.extend(findings);
    }

    // Canonicalize for stable fingerprints; fall back to the raw path on error.
    let scan_root = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    // Apply policy (ignore rules, overrides, suppressions)
    let effective_findings = config.policy.apply(&all_findings, &scan_root);
    let verdict = config.policy.evaluate(&all_findings);

    Ok(ScanReport {
        target_name,
        findings: effective_findings,
        verdict,
        scan_root,
    })
}

/// Render a scan report in the specified format.
pub fn render_report(report: &ScanReport, format: OutputFormat) -> Result<String> {
    output::render(
        &report.findings,
        &report.verdict,
        format,
        &report.target_name,
        &report.scan_root,
    )
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn safe_calculator_zero_findings() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/safe_calculator"),
            &opts,
        )
        .unwrap();
        // No code-level security findings (SHIELD-001 through SHIELD-006, SHIELD-011)
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.severity >= rules::Severity::High),
            "safe calculator should have no High+ findings"
        );
        assert!(report.verdict.pass);
    }

    #[test]
    fn vuln_cmd_inject_detected() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/vuln_cmd_inject"),
            &opts,
        )
        .unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-001"));
        assert!(!report.verdict.pass);
    }

    #[test]
    fn vuln_ssrf_detected() {
        let opts = ScanOptions::default();
        let report = scan(Path::new("tests/fixtures/mcp_servers/vuln_ssrf"), &opts).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-003"));
        assert!(!report.verdict.pass);
    }

    #[test]
    fn vuln_cred_exfil_detected() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/vuln_cred_exfil"),
            &opts,
        )
        .unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-002"));
        assert!(!report.verdict.pass);
    }

    #[test]
    fn baseline_write_and_filter_round_trip() {
        use crate::baseline::{BaselineEntry, BaselineFile};
        use tempfile::NamedTempFile;

        let fixture = Path::new("tests/fixtures/mcp_servers/vuln_cmd_inject");
        let opts = ScanOptions::default();

        // Step 1: scan and get findings
        let report = scan(fixture, &opts).unwrap();
        assert!(
            !report.findings.is_empty(),
            "vuln_cmd_inject should produce findings"
        );

        // Step 2: write baseline from findings
        let baseline_file = NamedTempFile::new().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let entries: Vec<BaselineEntry> = report
            .findings
            .iter()
            .map(|f| BaselineEntry {
                fingerprint: f.fingerprint(&report.scan_root),
                rule_id: f.rule_id.clone(),
                first_seen: now.clone(),
            })
            .collect();
        let baseline = BaselineFile::new(entries);
        baseline.save(baseline_file.path()).unwrap();

        // Step 3: re-scan and filter with baseline
        let report2 = scan(fixture, &opts).unwrap();
        let loaded_baseline = BaselineFile::load(baseline_file.path()).unwrap();
        let filtered: Vec<_> = report2
            .findings
            .into_iter()
            .filter(|f| {
                let fp = f.fingerprint(&report2.scan_root);
                !loaded_baseline.contains(&fp)
            })
            .collect();

        // Step 4: all findings should be filtered out
        assert!(
            filtered.is_empty(),
            "All findings should be filtered by baseline, but {} remain: {:?}",
            filtered.len(),
            filtered.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn suppress_command_roundtrip() {
        use crate::config::Config;
        use crate::rules::policy::Suppression;
        use tempfile::TempDir;

        // Use a temp dir so we don't pollute fixture directories
        let tmp = TempDir::new().unwrap();
        let fixture = Path::new("tests/fixtures/mcp_servers/vuln_cmd_inject");

        // Step 1: Scan the fixture to get a real fingerprint
        let opts = ScanOptions::default();
        let report = scan(fixture, &opts).unwrap();
        assert!(
            !report.findings.is_empty(),
            "vuln_cmd_inject should produce findings"
        );

        let first_finding = &report.findings[0];
        let fp = first_finding.fingerprint(&report.scan_root);
        let rule_id = first_finding.rule_id.clone();

        // Step 2: Write a config with the suppression into a temp dir
        let config_path = tmp.path().join(".agentshield.toml");
        let mut cfg = Config::default();
        cfg.policy.suppressions.push(Suppression {
            fingerprint: fp.clone(),
            reason: "Integration test suppression".into(),
            expires: None,
            created_at: Some("2026-03-21".into()),
        });
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&config_path, &toml_str).unwrap();

        // Step 3: Verify the config round-trips correctly
        let loaded = Config::load(&config_path).unwrap();
        assert_eq!(loaded.policy.suppressions.len(), 1);
        assert_eq!(loaded.policy.suppressions[0].fingerprint, fp);
        assert_eq!(
            loaded.policy.suppressions[0].reason,
            "Integration test suppression"
        );

        // Step 4: Re-scan using the config with the suppression
        let opts_with_config = ScanOptions {
            config_path: Some(config_path.clone()),
            ..ScanOptions::default()
        };
        let report2 = scan(fixture, &opts_with_config).unwrap();

        // The suppressed finding should no longer appear
        let still_present = report2
            .findings
            .iter()
            .any(|f| f.rule_id == rule_id && f.fingerprint(&report2.scan_root) == fp);

        assert!(
            !still_present,
            "Suppressed finding {} should not appear in re-scan",
            fp
        );
    }

    #[test]
    fn safe_filesystem_no_file_access_findings() {
        // This fixture has a handler that validates paths via validatePath()
        // before passing them to helper functions. Cross-file analysis should
        // downgrade the helpers' operations from tainted to sanitized.
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/safe_filesystem"),
            &opts,
        )
        .unwrap();

        let file_access_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "SHIELD-004")
            .collect();

        assert!(
            file_access_findings.is_empty(),
            "Expected 0 SHIELD-004 findings (cross-file sanitization should eliminate FPs), \
             but got {}: {:?}",
            file_access_findings.len(),
            file_access_findings
                .iter()
                .map(|f| &f.message)
                .collect::<Vec<_>>()
        );
    }
}
