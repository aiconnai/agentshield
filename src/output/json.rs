use std::path::Path;

use chrono::Utc;
use serde::Serialize;

use crate::error::Result;
use crate::rules::Finding;
use crate::rules::policy::PolicyVerdict;

/// A finding entry with an attached fingerprint for JSON output.
#[derive(Serialize)]
struct FindingWithFingerprint<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    fingerprint: String,
}

use crate::rules::Severity;

/// Summary counts of findings by severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl JsonSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self {
            total: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: &'static str,
    tool_version: &'static str,
    target: &'a str,
    scan_root: String,
    generated_at: String,
    summary: JsonSummary,
    verdict: &'a PolicyVerdict,
    findings: Vec<FindingWithFingerprint<'a>>,
}

/// Render findings as a JSON report, with a `fingerprint` and scan metadata.
pub fn render(
    findings: &[Finding],
    verdict: &PolicyVerdict,
    target_name: &str,
    scan_root: &Path,
) -> Result<String> {
    let findings_with_fp: Vec<FindingWithFingerprint<'_>> = findings
        .iter()
        .map(|f| FindingWithFingerprint {
            finding: f,
            fingerprint: f.fingerprint(scan_root),
        })
        .collect();

    let summary = JsonSummary::from_findings(findings);

    let report = JsonReport {
        schema_version: "1.0.0",
        tool_version: env!("CARGO_PKG_VERSION"),
        target: target_name,
        scan_root: scan_root.to_string_lossy().into_owned(),
        generated_at: Utc::now().to_rfc3339(),
        summary,
        verdict,
        findings: findings_with_fp,
    };

    let json = serde_json::to_string_pretty(&report)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{AttackCategory, Confidence};
    use std::path::PathBuf;

    #[test]
    fn test_json_render_includes_metadata_and_summary() {
        let finding = Finding {
            rule_id: "SHIELD-001".into(),
            rule_name: "Command Injection".into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: "eval input".into(),
            location: None,
            evidence: vec![],
            taint_path: None,
            remediation: None,
            cwe_id: Some("CWE-78".into()),
        };

        let verdict = PolicyVerdict {
            pass: false,
            total_findings: 1,
            effective_findings: 1,
            highest_severity: Some(Severity::Critical),
            fail_threshold: Severity::High,
        };

        let output = render(&[finding], &verdict, "test_target", &PathBuf::from("/test")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["schema_version"], "1.0.0");
        assert_eq!(value["target"], "test_target");
        assert_eq!(value["summary"]["total"], 1);
        assert_eq!(value["summary"]["critical"], 1);
        assert_eq!(value["summary"]["high"], 0);
        assert_eq!(value["findings"].as_array().unwrap().len(), 1);
        assert!(value["findings"][0]["fingerprint"].is_string());
    }
}
