pub mod console;
pub mod html;
pub mod json;
pub mod sarif;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::rules::Finding;
use crate::rules::fingerprint::compute_fingerprints;
use crate::rules::policy::PolicyVerdict;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Console,
    Json,
    Sarif,
    Html,
}

impl OutputFormat {
    pub fn from_str_lenient(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "console" | "text" => Some(Self::Console),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "html" => Some(Self::Html),
            _ => None,
        }
    }
}

/// Render findings into the specified format.
///
/// `scan_root` is used to compute stable, portable fingerprints for each
/// finding (relative to the scan directory so they survive path changes).
pub fn render(
    findings: &[Finding],
    verdict: &PolicyVerdict,
    format: OutputFormat,
    target_name: &str,
    scan_root: &Path,
) -> Result<String> {
    render_with_metadata(findings, verdict, format, target_name, scan_root, &[])
}

/// Render findings with registry metadata for enriched formats such as SARIF.
///
/// Fingerprints are computed over `findings`; when rendering a filtered subset
/// of a scan, prefer [`render_with_fingerprints`] with the scan's fingerprints.
pub fn render_with_metadata(
    findings: &[Finding],
    verdict: &PolicyVerdict,
    format: OutputFormat,
    target_name: &str,
    scan_root: &Path,
    rule_metadata: &[crate::rules::RuleMetadata],
) -> Result<String> {
    let fingerprints = compute_fingerprints(findings, scan_root);
    render_with_fingerprints(
        findings,
        &fingerprints,
        verdict,
        format,
        target_name,
        scan_root,
        rule_metadata,
    )
}

/// Render findings with precomputed fingerprints aligned with `findings`
/// (for example [`crate::ScanReport::fingerprints`]). Misaligned fingerprints
/// are recomputed from `findings`.
pub fn render_with_fingerprints(
    findings: &[Finding],
    fingerprints: &[String],
    verdict: &PolicyVerdict,
    format: OutputFormat,
    target_name: &str,
    scan_root: &Path,
    rule_metadata: &[crate::rules::RuleMetadata],
) -> Result<String> {
    let recomputed;
    let fingerprints = if fingerprints.len() == findings.len() {
        fingerprints
    } else {
        recomputed = compute_fingerprints(findings, scan_root);
        &recomputed
    };
    match format {
        OutputFormat::Console => Ok(console::render_fingerprinted(
            findings,
            fingerprints,
            verdict,
        )),
        OutputFormat::Json => {
            json::render_fingerprinted(findings, fingerprints, verdict, target_name, scan_root)
        }
        OutputFormat::Sarif => sarif::render_fingerprinted(
            findings,
            fingerprints,
            target_name,
            rule_metadata,
            Some(verdict),
        ),
        OutputFormat::Html => {
            html::render_fingerprinted(findings, fingerprints, verdict, target_name)
        }
    }
}
