pub mod console;
pub mod html;
pub mod json;
pub mod sarif;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::rules::policy::PolicyVerdict;
use crate::rules::Finding;

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
    match format {
        OutputFormat::Console => Ok(console::render(findings, verdict, scan_root)),
        OutputFormat::Json => json::render(findings, verdict, scan_root),
        OutputFormat::Sarif => sarif::render(findings, target_name, scan_root),
        OutputFormat::Html => html::render(findings, verdict, target_name, scan_root),
    }
}
