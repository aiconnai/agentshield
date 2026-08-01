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

#[derive(Serialize)]
struct JsonReport<'a> {
    findings: Vec<FindingWithFingerprint<'a>>,
    verdict: &'a PolicyVerdict,
    target: &'a str,
    scan_root: String,
    tool_version: &'static str,
    generated_at: String,
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

    let report = JsonReport {
        findings: findings_with_fp,
        verdict,
        target: target_name,
        scan_root: scan_root.to_string_lossy().into_owned(),
        tool_version: env!("CARGO_PKG_VERSION"),
        generated_at: Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&report)?;
    Ok(json)
}
