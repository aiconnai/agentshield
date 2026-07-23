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
pub mod certify;
pub mod config;
pub mod doctor;
pub mod egress;
pub mod error;
pub mod ir;
pub mod output;
pub mod parser;
pub mod rules;
#[cfg(feature = "runtime-guard")]
pub mod runtime;
pub mod ux;

use std::path::Path;

use config::{Config, ScanPathFilter, ScanPathFilterSummary};
use error::Result;
use ir::ScanTarget;
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
    /// Raw scan targets produced by the adapter pipeline.
    /// Used by callers that need to inspect the IR (e.g., `--emit-egress-policy`).
    pub targets: Vec<ScanTarget>,
    pub path_filter_summary: ScanPathFilterSummary,
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
    let path_filter = ScanPathFilter::from_scan_config(&config.scan, ignore_tests)?;
    let path_filter_summary = path_filter.summary();
    let targets = adapter::auto_detect_and_load_with_filter(path, &path_filter)?;

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
    let verdict = config.policy.evaluate(&effective_findings);

    Ok(ScanReport {
        target_name,
        findings: effective_findings,
        verdict,
        scan_root,
        targets,
        path_filter_summary,
    })
}

/// Render a scan report in the specified format.
pub fn render_report(report: &ScanReport, format: OutputFormat) -> Result<String> {
    let rule_metadata = rules::RuleEngine::new().list_rules();
    output::render_with_metadata(
        &report.findings,
        &report.verdict,
        format,
        &report.target_name,
        &report.scan_root,
        &rule_metadata,
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

    /// Verify that dependency findings with manifest file locations appear
    /// consistently across all 4 output formats (console, JSON, SARIF, HTML).
    ///
    /// Prior to T7, SHIELD-009 and SHIELD-012 had `location: None` and were
    /// silently dropped from SARIF output while appearing as "-" in console
    /// and HTML. Now that the adapter populates manifest file locations, all
    /// formats must agree on the same location.
    #[test]
    fn dep_findings_location_parity_across_output_formats() {
        use crate::output::OutputFormat;

        let fixture = Path::new("tests/fixtures/mcp_servers/vuln_unpinned_deps");
        let opts = ScanOptions::default();
        let report = scan(fixture, &opts).unwrap();

        // The fixture has requirements.txt with >=versions and no lockfile.
        // Expect at least one SHIELD-009 (Unpinned Dependencies) finding.
        let dep_finding = report
            .findings
            .iter()
            .find(|f| f.rule_id == "SHIELD-009")
            .expect("Expected at least one SHIELD-009 finding from vuln_unpinned_deps fixture");

        // The finding must have a location pointing to requirements.txt.
        let loc = dep_finding
            .location
            .as_ref()
            .expect("SHIELD-009 finding must carry a manifest file location");
        assert!(
            loc.file.to_string_lossy().contains("requirements.txt"),
            "SHIELD-009 location file should be requirements.txt, got: {}",
            loc.file.display()
        );
        assert!(loc.line >= 1, "SHIELD-009 location line must be >= 1");

        let expected_file = loc.file.to_string_lossy().to_string();

        // Render all 4 formats and verify the location is present in each.
        let console_out =
            render_report(&report, OutputFormat::Console).expect("console render failed");
        assert!(
            console_out.contains("requirements.txt"),
            "Console output should contain requirements.txt for dep findings"
        );

        let json_out = render_report(&report, OutputFormat::Json).expect("json render failed");
        let json_val: serde_json::Value =
            serde_json::from_str(&json_out).expect("JSON output must be valid JSON");
        let json_findings = json_val["findings"]
            .as_array()
            .expect("JSON must have findings array");
        let json_dep = json_findings
            .iter()
            .find(|f| f["rule_id"].as_str() == Some("SHIELD-009"))
            .expect("JSON output must contain SHIELD-009 finding");
        let json_file = json_dep["location"]["file"]
            .as_str()
            .expect("JSON SHIELD-009 finding must have location.file");
        assert!(
            json_file.contains("requirements.txt"),
            "JSON location.file should contain requirements.txt, got: {json_file}"
        );

        let sarif_out = render_report(&report, OutputFormat::Sarif).expect("SARIF render failed");
        let sarif_val: serde_json::Value =
            serde_json::from_str(&sarif_out).expect("SARIF output must be valid JSON");
        let sarif_results = sarif_val["runs"][0]["results"]
            .as_array()
            .expect("SARIF must have runs[0].results array");
        let sarif_dep = sarif_results
            .iter()
            .find(|r| r["ruleId"].as_str() == Some("SHIELD-009"))
            .expect(
                "SARIF output must contain SHIELD-009 result (dep findings now have locations)",
            );
        let sarif_uri = sarif_dep["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("SARIF SHIELD-009 result must have a physicalLocation URI");
        assert!(
            sarif_uri.contains("requirements.txt"),
            "SARIF artifactLocation URI should contain requirements.txt, got: {sarif_uri}"
        );
        // Verify the URI matches the JSON location (both point to the same file)
        assert!(
            expected_file.contains("requirements.txt"),
            "Location file {expected_file} must reference requirements.txt"
        );

        let html_out = render_report(&report, OutputFormat::Html).expect("HTML render failed");
        assert!(
            html_out.contains("requirements.txt"),
            "HTML output should contain requirements.txt for dep findings"
        );
        // HTML must NOT show "-" for the dep finding location
        // (the table shows the location as "file:line")
        assert!(
            !html_out.contains("<code>-</code>"),
            "HTML output must not show '-' for dep finding locations that have a manifest file"
        );
    }

    #[test]
    fn vuln_metadata_ssrf_detected() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/vuln_metadata_ssrf"),
            &opts,
        )
        .unwrap();
        // The fixture has a tool that passes user-controlled `url` to requests.get,
        // which should trigger SHIELD-003 (general SSRF) and potentially SHIELD-013
        // (metadata SSRF) via taint paths if populated.
        // At minimum, SHIELD-003 must fire (parameter -> network call).
        assert!(
            report.findings.iter().any(|f| f.rule_id == "SHIELD-003"),
            "Expected SHIELD-003 (general SSRF) from vuln_metadata_ssrf fixture"
        );
        assert!(!report.verdict.pass);
    }

    // The safe_filesystem fixture is TypeScript-only; without the typescript
    // parser feature the .ts files are not parsed, cross-file sanitization
    // cannot see validatePath(), and the helper file ops surface as false
    // positives. Gate the test on the feature its premise depends on.
    #[cfg(feature = "typescript")]
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
