//! Baseline schema for tracking known findings across scan runs.
//!
//! A baseline file records previously seen findings (by fingerprint) so that
//! subsequent scans can suppress already-known issues and surface only new ones.
//!
//! # Schema versions
//!
//! - `1`: entries hold legacy (scheme v1) fingerprints, see
//!   [`Finding::legacy_fingerprint`]. Still read; matched with the legacy
//!   algorithm, so colliding findings stay hidden exactly as before.
//! - `2` (written by this release): entries hold scheme-v2 fingerprints, see
//!   [`crate::rules::fingerprint`].

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShieldError};
use crate::rules::Finding;

const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Last schema version whose entries hold legacy (scheme v1) fingerprints.
pub const LEGACY_FINGERPRINT_SCHEMA_VERSION: u32 = 1;

/// A versioned file that records known findings by fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    /// Schema version — incremented when the format changes in a breaking way.
    pub schema_version: u32,
    /// RFC3339 timestamp of when this baseline was created.
    pub created_at: String,
    /// Version of agentshield that wrote this file.
    pub tool_version: String,
    /// Known finding entries.
    pub entries: Vec<BaselineEntry>,
}

/// A single known finding recorded in the baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Stable fingerprint that uniquely identifies this finding.
    pub fingerprint: String,
    /// Rule that produced this finding (e.g. `"SHIELD-001"`).
    pub rule_id: String,
    /// RFC3339 timestamp of when this finding was first observed.
    pub first_seen: String,
}

impl BaselineFile {
    /// Create a new baseline from a list of entries, stamped with the current time.
    pub fn new(entries: Vec<BaselineEntry>) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            created_at: chrono::Utc::now().to_rfc3339(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            entries,
        }
    }

    /// Load a baseline from a JSON file on disk.
    ///
    /// Returns an error if the file cannot be read, if the JSON is malformed,
    /// or if the `schema_version` is newer than this tool supports.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&content)?;
        if baseline.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(ShieldError::Internal(format!(
                "Baseline schema version {} is newer than supported version {}; \
                 please upgrade agentshield",
                baseline.schema_version, CURRENT_SCHEMA_VERSION
            )));
        }
        Ok(baseline)
    }

    /// Persist this baseline to a JSON file on disk (pretty-printed).
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Return `true` if the given fingerprint is recorded in this baseline.
    ///
    /// This compares raw strings only; use [`BaselineFile::matches`] to honour
    /// the fingerprint scheme of older baselines.
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.entries.iter().any(|e| e.fingerprint == fingerprint)
    }

    /// Return `true` if this baseline records the scheme-v1 fingerprints
    /// written by earlier releases.
    pub fn uses_legacy_fingerprints(&self) -> bool {
        self.schema_version <= LEGACY_FINGERPRINT_SCHEMA_VERSION
    }

    /// Return `true` if `finding`, whose scheme-v2 fingerprint is
    /// `fingerprint`, is recorded in this baseline.
    ///
    /// Schema-v1 baselines are matched with [`Finding::legacy_fingerprint`].
    pub fn matches(&self, finding: &Finding, fingerprint: &str, scan_root: &Path) -> bool {
        if self.uses_legacy_fingerprints() {
            self.contains(&finding.legacy_fingerprint(scan_root))
        } else {
            self.contains(fingerprint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_entry(fingerprint: &str, rule_id: &str) -> BaselineEntry {
        BaselineEntry {
            fingerprint: fingerprint.to_string(),
            rule_id: rule_id.to_string(),
            first_seen: "2026-03-20T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_round_trip_serialization() {
        let baseline = BaselineFile::new(vec![
            make_entry("abc123", "SHIELD-001"),
            make_entry("def456", "SHIELD-003"),
        ]);

        let tmp = NamedTempFile::new().unwrap();
        baseline.save(tmp.path()).unwrap();

        let loaded = BaselineFile::load(tmp.path()).unwrap();
        assert_eq!(loaded.schema_version, 2);
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].fingerprint, "abc123");
        assert_eq!(loaded.entries[1].rule_id, "SHIELD-003");
    }

    #[test]
    fn test_contains_present() {
        let baseline = BaselineFile::new(vec![make_entry("abc123", "SHIELD-001")]);
        assert!(baseline.contains("abc123"));
    }

    #[test]
    fn test_contains_absent() {
        let baseline = BaselineFile::new(vec![make_entry("abc123", "SHIELD-001")]);
        assert!(!baseline.contains("xyz789"));
    }

    #[test]
    fn test_empty_baseline_round_trip() {
        let baseline = BaselineFile::new(vec![]);
        let tmp = NamedTempFile::new().unwrap();
        baseline.save(tmp.path()).unwrap();
        let loaded = BaselineFile::load(tmp.path()).unwrap();
        assert_eq!(loaded.entries.len(), 0);
        assert_eq!(loaded.schema_version, 2);
    }

    #[test]
    fn test_future_schema_version_rejected() {
        let json = r#"{
            "schema_version": 99,
            "created_at": "2026-03-20T00:00:00Z",
            "tool_version": "0.2.4",
            "entries": []
        }"#;
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json).unwrap();
        let result = BaselineFile::load(tmp.path());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("newer than supported"),
            "error message should explain the version mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_current_schema_version_accepted() {
        let baseline = BaselineFile::new(vec![make_entry("fp1", "SHIELD-007")]);
        let tmp = NamedTempFile::new().unwrap();
        baseline.save(tmp.path()).unwrap();
        // schema_version == CURRENT_SCHEMA_VERSION must load without error
        assert!(BaselineFile::load(tmp.path()).is_ok());
    }

    #[test]
    fn test_schema_v1_baseline_matches_with_legacy_fingerprint() {
        use crate::ir::SourceLocation;
        use crate::rules::{AttackCategory, Confidence, Evidence, Severity};

        let root = Path::new("/project");
        let finding = Finding {
            rule_id: "SHIELD-001".into(),
            rule_name: "Command Injection".into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: "m".into(),
            location: Some(SourceLocation {
                file: "/project/a.py".into(),
                line: 1,
                column: 0,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: "d".into(),
                location: None,
                snippet: None,
            }],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        };
        let legacy = finding.legacy_fingerprint(root);
        let json = format!(
            r#"{{"schema_version":1,"created_at":"2026-03-20T00:00:00Z","tool_version":"1.0.2",
               "entries":[{{"fingerprint":"{legacy}","rule_id":"SHIELD-001","first_seen":"x"}}]}}"#
        );
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json).unwrap();
        let v1 = BaselineFile::load(tmp.path()).unwrap();
        assert!(v1.uses_legacy_fingerprints());
        assert!(v1.matches(&finding, "v2-value-not-recorded", root));

        let v2 = BaselineFile::new(vec![make_entry("v2fp", "SHIELD-001")]);
        assert!(!v2.uses_legacy_fingerprints());
        assert!(v2.matches(&finding, "v2fp", root));
        assert!(!v2.matches(&finding, &legacy, root));
    }

    #[test]
    fn test_tool_version_populated() {
        let baseline = BaselineFile::new(vec![]);
        assert!(!baseline.tool_version.is_empty());
    }

    #[test]
    fn test_created_at_is_rfc3339() {
        let baseline = BaselineFile::new(vec![]);
        // chrono should produce a valid RFC3339 string; verify it parses back
        chrono::DateTime::parse_from_rfc3339(&baseline.created_at)
            .expect("created_at must be valid RFC3339");
    }
}
