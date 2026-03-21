use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ir::{data_surface::TaintPath, SourceLocation};

/// A security finding produced by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique rule identifier (e.g., "SHIELD-001").
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// Severity level.
    pub severity: Severity,
    /// Confidence level (how certain we are this is a real issue).
    pub confidence: Confidence,
    /// MITRE ATT&CK-style category.
    pub attack_category: AttackCategory,
    /// Human-readable description of the finding.
    pub message: String,
    /// Primary source location.
    pub location: Option<SourceLocation>,
    /// Evidence supporting the finding.
    pub evidence: Vec<Evidence>,
    /// Taint path (if applicable).
    pub taint_path: Option<TaintPath>,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// CWE identifier (if applicable).
    pub cwe_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str_lenient(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    CommandInjection,
    CodeInjection,
    CredentialExfiltration,
    Ssrf,
    ArbitraryFileAccess,
    SupplyChain,
    SelfModification,
    PromptInjectionSurface,
    ExcessivePermissions,
    DataExfiltration,
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandInjection => write!(f, "Command Injection"),
            Self::CodeInjection => write!(f, "Code Injection"),
            Self::CredentialExfiltration => write!(f, "Credential Exfiltration"),
            Self::Ssrf => write!(f, "SSRF"),
            Self::ArbitraryFileAccess => write!(f, "Arbitrary File Access"),
            Self::SupplyChain => write!(f, "Supply Chain"),
            Self::SelfModification => write!(f, "Self-Modification"),
            Self::PromptInjectionSurface => write!(f, "Prompt Injection Surface"),
            Self::ExcessivePermissions => write!(f, "Excessive Permissions"),
            Self::DataExfiltration => write!(f, "Data Exfiltration"),
        }
    }
}

/// Evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub location: Option<SourceLocation>,
    pub snippet: Option<String>,
}

impl Finding {
    /// Compute a stable fingerprint that survives line shifts.
    ///
    /// Hash of `(rule_id, relative_file_path, evidence_key, attack_category)`.
    /// Line and column numbers are intentionally excluded so that the
    /// fingerprint remains the same when surrounding code is edited.
    pub fn fingerprint(&self, scan_root: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.rule_id.as_bytes());
        hasher.update(b"|");

        // Use relative path so fingerprint is portable across machines
        if let Some(ref loc) = self.location {
            let rel = loc.file.strip_prefix(scan_root).unwrap_or(&loc.file);
            hasher.update(rel.to_string_lossy().as_bytes());
        }
        hasher.update(b"|");

        // Use first evidence description as the "what" component
        if let Some(ev) = self.evidence.first() {
            hasher.update(ev.description.as_bytes());
        }
        hasher.update(b"|");

        hasher.update(format!("{:?}", self.attack_category).as_bytes());

        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// Metadata about a detector rule, used for `list-rules` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_severity: Severity,
    pub attack_category: AttackCategory,
    pub cwe_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::ir::SourceLocation;

    /// Helper: build a minimal finding for tests.
    fn make_finding(
        rule_id: &str,
        file: &str,
        line: usize,
        column: usize,
        evidence_desc: &str,
        category: AttackCategory,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: "Test Rule".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            attack_category: category,
            message: "test".to_string(),
            location: Some(SourceLocation {
                file: PathBuf::from(file),
                line,
                column,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: evidence_desc.to_string(),
                location: None,
                snippet: None,
            }],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    #[test]
    fn fingerprint_stable_across_line_shifts() {
        let scan_root = Path::new("/project");

        let finding1 = make_finding(
            "SHIELD-001",
            "/project/src/main.py",
            10,
            0,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        // Same finding but at a different line and column
        let finding2 = make_finding(
            "SHIELD-001",
            "/project/src/main.py",
            25,
            5,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        assert_eq!(
            finding1.fingerprint(scan_root),
            finding2.fingerprint(scan_root),
            "Fingerprint should be stable across line shifts"
        );
    }

    #[test]
    fn fingerprint_different_for_different_rules() {
        let scan_root = Path::new("/project");

        let finding1 = make_finding(
            "SHIELD-001",
            "/project/src/main.py",
            10,
            0,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        let finding2 = make_finding(
            "SHIELD-003",
            "/project/src/main.py",
            10,
            0,
            "requests.get receives parameter",
            AttackCategory::Ssrf,
        );

        assert_ne!(
            finding1.fingerprint(scan_root),
            finding2.fingerprint(scan_root),
            "Different rules should produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_different_for_different_files() {
        let scan_root = Path::new("/project");

        let finding1 = make_finding(
            "SHIELD-001",
            "/project/src/main.py",
            10,
            0,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        let finding3 = make_finding(
            "SHIELD-001",
            "/project/src/other.py",
            10,
            0,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        assert_ne!(
            finding1.fingerprint(scan_root),
            finding3.fingerprint(scan_root),
            "Different files should produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_relative_path_portability() {
        let finding1 = make_finding(
            "SHIELD-001",
            "/project/src/main.py",
            10,
            0,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        let finding2 = make_finding(
            "SHIELD-001",
            "/other/src/main.py",
            10,
            0,
            "subprocess.run receives parameter",
            AttackCategory::CommandInjection,
        );

        let fp1 = finding1.fingerprint(Path::new("/project"));
        let fp2 = finding2.fingerprint(Path::new("/other"));

        assert_eq!(
            fp1, fp2,
            "Same relative paths from different roots should produce same fingerprint"
        );
    }

    #[test]
    fn fingerprint_no_location() {
        let scan_root = Path::new("/project");

        let finding = Finding {
            rule_id: "SHIELD-009".to_string(),
            rule_name: "No Location".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            attack_category: AttackCategory::ExcessivePermissions,
            message: "test".to_string(),
            location: None,
            evidence: vec![],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        };

        // Should not panic and should produce a valid hex string
        let fp = finding.fingerprint(scan_root);
        assert_eq!(fp.len(), 64, "SHA-256 hex digest should be 64 chars");
    }

    #[test]
    fn fingerprint_is_valid_hex() {
        let scan_root = Path::new("/project");
        let finding = make_finding(
            "SHIELD-001",
            "/project/src/main.py",
            1,
            0,
            "test evidence",
            AttackCategory::CommandInjection,
        );

        let fp = finding.fingerprint(scan_root);
        assert_eq!(fp.len(), 64);
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint should be valid hex"
        );
    }
}
