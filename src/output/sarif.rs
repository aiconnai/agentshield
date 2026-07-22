use std::path::Path;

use crate::error::Result;
use crate::rules::{Finding, Severity};

use serde_json::{json, Value};

/// Render findings as SARIF 2.1.0.
///
/// Produces a self-contained SARIF log compatible with GitHub Code Scanning
/// and other SARIF consumers. Each result includes a `fingerprint` in its
/// `properties` bag for stable deduplication across scan runs.
pub fn render(findings: &[Finding], target_name: &str, scan_root: &Path) -> Result<String> {
    let rules: Vec<Value> = findings
        .iter()
        .map(|f| &f.rule_id)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|rule_id| findings.iter().find(|f| &f.rule_id == rule_id))
        .map(|finding| {
            let mut rule = json!({
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": { "text": finding.rule_name },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(finding.severity),
                },
            });
            if let Some(cwe) = &finding.cwe_id {
                rule["properties"] = json!({
                    "tags": [cwe],
                });
            }
            rule
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .filter_map(|f| {
            // SARIF consumers (GitHub Code Scanning) require at least one
            // location per result. Skip findings without a source location.
            // SHIELD-008 (Excessive Permissions) has no meaningful code
            // location, so it is excluded from SARIF output. Dependency
            // findings (SHIELD-009, SHIELD-012) now carry manifest file
            // locations and pass through.
            let loc = f.location.as_ref()?;

            let mut region = json!({
                "startLine": loc.line,
                "startColumn": loc.column + 1,
            });
            if let (Some(end_line), Some(end_column)) = (loc.end_line, loc.end_column) {
                region["endLine"] = json!(end_line);
                region["endColumn"] = json!(end_column + 1);
            }

            let mut result = json!({
                "ruleId": f.rule_id,
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc.file.display().to_string(),
                        },
                        "region": region,
                    },
                }],
            });

            // Merge remediation and fingerprint into the properties bag.
            let fingerprint = f.fingerprint(scan_root);
            result["properties"] = match &f.remediation {
                Some(remediation) => json!({
                    "fingerprint": fingerprint,
                    "remediation": remediation,
                }),
                None => json!({ "fingerprint": fingerprint }),
            };

            Some(result)
        })
        .collect();

    let sarif = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentShield",
                    "informationUri": "https://github.com/aiconnai/agentshield",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                },
            },
            "results": results,
            "automationDetails": {
                "id": format!("agentshield/{}", target_name),
            },
        }],
    });

    let output = serde_json::to_string_pretty(&sarif)?;
    Ok(output)
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::render;
    use crate::ir::SourceLocation;
    use crate::rules::{AttackCategory, Confidence, Finding, Severity};

    #[test]
    fn renders_one_based_start_and_end_columns() {
        let finding = Finding {
            rule_id: "SHIELD-003".into(),
            rule_name: "SSRF".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            attack_category: AttackCategory::Ssrf,
            message: "tainted URL".into(),
            location: Some(SourceLocation {
                file: PathBuf::from("src/server.py"),
                line: 12,
                column: 4,
                end_line: Some(12),
                end_column: Some(20),
            }),
            evidence: vec![],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        };

        let rendered = render(&[finding], "fixture", Path::new(".")).unwrap();
        let region = &serde_json::from_str::<serde_json::Value>(&rendered).unwrap()["runs"][0]
            ["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startColumn"], 5);
        assert_eq!(region["endColumn"], 21);
        assert_eq!(region["endLine"], 12);
    }
}
