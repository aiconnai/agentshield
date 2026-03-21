//! Baseline schema for tracking known findings across scan runs.
//!
//! A baseline file records previously seen findings (by fingerprint) so that
//! subsequent scans can suppress already-known issues and surface only new ones.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShieldError};

const CURRENT_SCHEMA_VERSION: u32 = 1;

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
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.entries.iter().any(|e| e.fingerprint == fingerprint)
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
        assert_eq!(loaded.schema_version, 1);
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
        assert_eq!(loaded.schema_version, 1);
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
