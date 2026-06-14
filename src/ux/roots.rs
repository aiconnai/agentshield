use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::ScanReport;

pub(super) fn render(report: &ScanReport) -> String {
    let mut output = format!("- Scan root: {}\n", report.scan_root.display());
    let roots = metadata_roots(report);
    if !roots.is_empty() {
        output.push_str(&format!("- Metadata root: {}\n", roots.join(", ")));
    }
    output
}

fn metadata_roots(report: &ScanReport) -> Vec<String> {
    let scan_root = normalized_path(&report.scan_root);
    let roots: BTreeSet<String> = report
        .targets
        .iter()
        .map(|target| normalized_path(&target.root_path))
        .filter(|root| *root != scan_root)
        .map(|root| root.display().to_string())
        .collect();

    roots.into_iter().collect()
}

fn normalized_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
