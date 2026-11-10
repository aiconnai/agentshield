//! Scan coverage: which files and directories the file walker did not (fully)
//! read, so a gap in the scan is visible rather than silent.
//!
//! The scanned tree is untrusted. Anything that is pruned, truncated or
//! unreadable is recorded here and surfaced in the JSON report and on stderr.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;

/// Maximum number of entries serialized into reports. The total is always
/// reported separately.
pub const MAX_REPORTED_COVERAGE_ENTRIES: usize = 100;

/// Why a path was not (fully) scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    /// A well-known dependency, build or tooling directory that was pruned.
    /// Informational: it is excluded on purpose.
    Pruned,
    /// The file exceeds the size cap; only its head was scanned.
    Truncated,
    /// The walk stopped at the depth limit; deeper entries were not visited.
    DepthLimit,
    /// The file or directory could not be read.
    Unreadable,
}

impl CoverageReason {
    /// Stable machine-readable name, identical to the JSON value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pruned => "pruned",
            Self::Truncated => "truncated",
            Self::DepthLimit => "depth_limit",
            Self::Unreadable => "unreadable",
        }
    }

    /// True when the reason is a real gap in coverage rather than a
    /// deliberate, informational exclusion.
    pub const fn is_gap(self) -> bool {
        !matches!(self, Self::Pruned)
    }
}

/// One path that was not (fully) scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageEntry {
    /// Path relative to the scan root, with `/` separators.
    pub path: String,
    pub reason: CoverageReason,
    /// Human-readable detail, for example the size that was truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Paths the scan did not (fully) read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanCoverage {
    pub skipped: Vec<CoverageEntry>,
}

impl ScanCoverage {
    /// Entries that are real gaps (everything except deliberate pruning).
    pub fn gaps(&self) -> impl Iterator<Item = &CoverageEntry> {
        self.skipped.iter().filter(|entry| entry.reason.is_gap())
    }

    pub fn is_empty(&self) -> bool {
        self.skipped.is_empty()
    }
}

#[derive(Debug, Clone)]
struct RawEntry {
    path: PathBuf,
    detail: Option<String>,
}

/// Thread-safe collector shared by every adapter through the
/// [`ScanPathFilter`](crate::config::ScanPathFilter). Cloning shares the log.
#[derive(Debug, Clone, Default)]
pub struct CoverageRecorder {
    entries: Arc<Mutex<BTreeMap<(PathBuf, CoverageReason), RawEntry>>>,
}

impl CoverageRecorder {
    /// Record a skipped path. Recording the same path and reason again (several
    /// adapters can walk the same tree) keeps a single entry.
    pub fn record(&self, path: &Path, reason: CoverageReason, detail: Option<String>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .entry((path.to_path_buf(), reason))
            .or_insert_with(|| RawEntry {
                path: path.to_path_buf(),
                detail,
            });
    }

    /// Snapshot the log with paths made relative to `root`.
    pub fn snapshot(&self, root: &Path) -> ScanCoverage {
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut skipped: Vec<CoverageEntry> = entries
            .iter()
            .map(|((_, reason), raw)| CoverageEntry {
                path: relative_display(&canonical_root, root, &raw.path),
                reason: *reason,
                detail: raw.detail.clone(),
            })
            .collect();
        skipped.sort_by(|a, b| (&a.path, a.reason).cmp(&(&b.path, b.reason)));
        ScanCoverage { skipped }
    }
}

fn relative_display(canonical_root: &Path, root: &Path, path: &Path) -> String {
    let relative = path
        .strip_prefix(root)
        .or_else(|_| path.strip_prefix(canonical_root))
        .unwrap_or(path);
    let parts: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}
