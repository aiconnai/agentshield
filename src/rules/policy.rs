use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{Finding, Severity};

/// Policy verdict — the final pass/fail decision after applying
/// ignore list and severity overrides to raw findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub pass: bool,
    pub total_findings: usize,
    pub effective_findings: usize,
    pub highest_severity: Option<Severity>,
    pub fail_threshold: Severity,
}

/// A suppression entry that silences a specific finding by fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// SHA-256 fingerprint of the finding to suppress.
    pub fingerprint: String,
    /// Mandatory reason explaining why this finding is suppressed.
    pub reason: String,
    /// Optional ISO-8601 date (YYYY-MM-DD) after which the suppression expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Optional ISO-8601 date when the suppression was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl Suppression {
    /// Returns `true` if this suppression has passed its expiration date.
    pub fn is_expired(&self) -> bool {
        if let Some(ref date_str) = self.expires {
            if let Ok(expires_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                return expires_date < Utc::now().date_naive();
            }
        }
        false
    }
}

/// Policy configuration loaded from `.agentshield.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Minimum severity to fail the scan.
    #[serde(default = "default_fail_on")]
    pub fail_on: Severity,
    /// Rule IDs to ignore entirely.
    #[serde(default)]
    pub ignore_rules: HashSet<String>,
    /// Per-rule severity overrides.
    #[serde(default)]
    pub overrides: HashMap<String, Severity>,
    /// Per-finding suppressions by fingerprint.
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
}

fn default_fail_on() -> Severity {
    Severity::High
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            ignore_rules: HashSet::new(),
            overrides: HashMap::new(),
            suppressions: Vec::new(),
        }
    }
}

impl Policy {
    /// Evaluate findings against this policy and produce a verdict.
    pub fn evaluate(&self, findings: &[Finding]) -> PolicyVerdict {
        let effective: Vec<Severity> = findings
            .iter()
            .filter(|f| !self.ignore_rules.contains(&f.rule_id))
            .map(|f| {
                self.overrides
                    .get(&f.rule_id)
                    .copied()
                    .unwrap_or(f.severity)
            })
            .collect();

        let highest = effective.iter().copied().max();
        let failed = effective.iter().any(|&sev| sev >= self.fail_on);

        PolicyVerdict {
            pass: !failed,
            total_findings: findings.len(),
            effective_findings: effective.len(),
            highest_severity: highest,
            fail_threshold: self.fail_on,
        }
    }

    /// Build a set of active (non-expired) suppression fingerprints.
    /// Logs a warning to stderr for each expired suppression.
    fn active_suppressions(&self) -> HashSet<&str> {
        let mut active = HashSet::new();
        for s in &self.suppressions {
            if s.is_expired() {
                eprintln!(
                    "warning: suppression for fingerprint {} has expired (expires: {})",
                    s.fingerprint,
                    s.expires.as_deref().unwrap_or("unknown"),
                );
            } else {
                active.insert(s.fingerprint.as_str());
            }
        }
        active
    }

    /// Filter findings: remove ignored rules, apply overrides,
    /// and filter out suppressed findings.
    pub fn apply(&self, findings: &[Finding], scan_root: &Path) -> Vec<Finding> {
        let suppressed = self.active_suppressions();

        findings
            .iter()
            .filter(|f| !self.ignore_rules.contains(&f.rule_id))
            .filter(|f| {
                if suppressed.is_empty() {
                    return true;
                }
                let fp = f.fingerprint(scan_root);
                !suppressed.contains(fp.as_str())
            })
            .map(|f| {
                let mut f = f.clone();
                if let Some(&override_sev) = self.overrides.get(&f.rule_id) {
                    f.severity = override_sev;
                }
                f
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ir::SourceLocation;
    use crate::rules::{AttackCategory, Confidence, Evidence};

    fn make_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            rule_name: "Test".into(),
            severity,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: "test".into(),
            location: None,
            evidence: vec![],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    fn make_finding_with_location(
        rule_id: &str,
        severity: Severity,
        file: &str,
        evidence_desc: &str,
    ) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            rule_name: "Test".into(),
            severity,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: "test".into(),
            location: Some(SourceLocation {
                file: PathBuf::from(file),
                line: 10,
                column: 0,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: evidence_desc.into(),
                location: None,
                snippet: None,
            }],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    #[test]
    fn default_policy_fails_on_high() {
        let policy = Policy::default();
        let findings = vec![make_finding("SHIELD-001", Severity::High)];
        let verdict = policy.evaluate(&findings);
        assert!(!verdict.pass);
    }

    #[test]
    fn default_policy_passes_on_medium() {
        let policy = Policy::default();
        let findings = vec![make_finding("SHIELD-009", Severity::Medium)];
        let verdict = policy.evaluate(&findings);
        assert!(verdict.pass);
    }

    #[test]
    fn ignore_rule_removes_finding() {
        let mut policy = Policy::default();
        policy.ignore_rules.insert("SHIELD-001".into());
        let findings = vec![make_finding("SHIELD-001", Severity::Critical)];
        let verdict = policy.evaluate(&findings);
        assert!(verdict.pass);
        assert_eq!(verdict.effective_findings, 0);
    }

    #[test]
    fn override_downgrades_severity() {
        let mut policy = Policy::default();
        policy.overrides.insert("SHIELD-001".into(), Severity::Info);
        let findings = vec![make_finding("SHIELD-001", Severity::Critical)];
        let verdict = policy.evaluate(&findings);
        assert!(verdict.pass);
    }

    #[test]
    fn suppression_filters_matching_finding() {
        let scan_root = Path::new("/project");
        let finding = make_finding_with_location(
            "SHIELD-001",
            Severity::Critical,
            "/project/src/main.py",
            "subprocess.run receives parameter",
        );
        let fp = finding.fingerprint(scan_root);

        let mut policy = Policy::default();
        policy.suppressions.push(Suppression {
            fingerprint: fp,
            reason: "False positive: validated by middleware".into(),
            expires: None,
            created_at: None,
        });

        let result = policy.apply(&[finding], scan_root);
        assert!(
            result.is_empty(),
            "Suppressed finding should be filtered out"
        );
    }

    #[test]
    fn expired_suppression_does_not_filter() {
        let scan_root = Path::new("/project");
        let finding = make_finding_with_location(
            "SHIELD-001",
            Severity::Critical,
            "/project/src/main.py",
            "subprocess.run receives parameter",
        );
        let fp = finding.fingerprint(scan_root);

        let mut policy = Policy::default();
        policy.suppressions.push(Suppression {
            fingerprint: fp,
            reason: "Was a false positive".into(),
            expires: Some("2020-01-01".into()),
            created_at: None,
        });

        let result = policy.apply(&[finding], scan_root);
        assert_eq!(
            result.len(),
            1,
            "Expired suppression should not filter the finding"
        );
    }

    #[test]
    fn unexpired_suppression_filters() {
        let scan_root = Path::new("/project");
        let finding = make_finding_with_location(
            "SHIELD-001",
            Severity::Critical,
            "/project/src/main.py",
            "subprocess.run receives parameter",
        );
        let fp = finding.fingerprint(scan_root);

        let mut policy = Policy::default();
        policy.suppressions.push(Suppression {
            fingerprint: fp,
            reason: "Accepted risk: internal tool".into(),
            expires: Some("2099-12-31".into()),
            created_at: None,
        });

        let result = policy.apply(&[finding], scan_root);
        assert!(
            result.is_empty(),
            "Unexpired suppression should filter the finding"
        );
    }

    #[test]
    fn suppression_no_expiry_always_filters() {
        let scan_root = Path::new("/project");
        let finding = make_finding_with_location(
            "SHIELD-001",
            Severity::Critical,
            "/project/src/main.py",
            "subprocess.run receives parameter",
        );
        let fp = finding.fingerprint(scan_root);

        let mut policy = Policy::default();
        policy.suppressions.push(Suppression {
            fingerprint: fp,
            reason: "Permanent suppression".into(),
            expires: None,
            created_at: None,
        });

        let result = policy.apply(&[finding], scan_root);
        assert!(
            result.is_empty(),
            "Suppression without expiry should always filter"
        );
    }

    #[test]
    fn suppression_without_reason_rejected() {
        let toml_str = r#"
[policy]
fail_on = "high"

[[policy.suppressions]]
fingerprint = "abc123"
reason = "  "
"#;
        let config: crate::config::Config = toml::from_str(toml_str).unwrap();
        let result = config.validate_for_test();
        assert!(
            result.is_err(),
            "Suppression with whitespace-only reason should be rejected"
        );
    }

    #[test]
    fn is_expired_with_past_date() {
        let s = Suppression {
            fingerprint: "abc".into(),
            reason: "test".into(),
            expires: Some("2020-01-01".into()),
            created_at: None,
        };
        assert!(s.is_expired());
    }

    #[test]
    fn is_expired_with_future_date() {
        let s = Suppression {
            fingerprint: "abc".into(),
            reason: "test".into(),
            expires: Some("2099-12-31".into()),
            created_at: None,
        };
        assert!(!s.is_expired());
    }

    #[test]
    fn is_expired_with_no_date() {
        let s = Suppression {
            fingerprint: "abc".into(),
            reason: "test".into(),
            expires: None,
            created_at: None,
        };
        assert!(!s.is_expired());
    }
}
