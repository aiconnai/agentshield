use std::path::Path;

use serde::Serialize;

use crate::error::Result;
use crate::rules::policy::PolicyVerdict;
use crate::rules::Finding;

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
}

/// Render findings as a JSON report, with a `fingerprint` field on each finding.
pub fn render(findings: &[Finding], verdict: &PolicyVerdict, scan_root: &Path) -> Result<String> {
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
    };

    let json = serde_json::to_string_pretty(&report)?;
    Ok(json)
}
