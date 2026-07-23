use std::collections::BTreeMap;
use std::path::Path;

use crate::error::Result;
use crate::rules::{Finding, OwaspMcp, RuleMetadata, Severity};

use serde_json::{json, Value};

/// Render findings as SARIF 2.1.0.
///
/// Produces a self-contained SARIF log compatible with GitHub Code Scanning
/// and other SARIF consumers. Each result includes a `fingerprint` in its
/// `properties` bag for stable deduplication across scan runs.
///
/// Rule metadata (including OWASP MCP Top 10 mappings) is taken from
/// `rule_metadata`; rules without metadata fall back to finding-derived
/// fields only (id/name/severity/CWE from the finding itself).
pub fn render(findings: &[Finding], target_name: &str, scan_root: &Path) -> Result<String> {
    render_with_metadata(findings, target_name, scan_root, &[])
}

/// Render SARIF enriched with rule-registry metadata.
pub fn render_with_metadata(
    findings: &[Finding],
    target_name: &str,
    scan_root: &Path,
    rule_metadata: &[RuleMetadata],
) -> Result<String> {
    let meta_by_id: BTreeMap<&str, &RuleMetadata> =
        rule_metadata.iter().map(|m| (m.id.as_str(), m)).collect();

    let rules: Vec<Value> = findings
        .iter()
        .map(|f| &f.rule_id)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|rule_id| findings.iter().find(|f| &f.rule_id == rule_id))
        .map(|finding| {
            let meta = meta_by_id.get(finding.rule_id.as_str()).copied();
            let owasp = meta.and_then(|m| m.owasp_mcp);

            let mut rule = json!({
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": { "text": finding.rule_name },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(finding.severity),
                },
            });

            let mut tags: Vec<Value> = Vec::new();
            if let Some(cwe) = &finding.cwe_id {
                tags.push(json!(cwe));
            }
            if let Some(cat) = owasp {
                tags.push(json!(cat.code()));
            }
            if !tags.is_empty() || owasp.is_some() {
                let mut props = json!({ "tags": tags });
                if let Some(cat) = owasp {
                    props["owasp_mcp"] = json!(cat.code());
                }
                rule["properties"] = props;
            }

            if let Some(cat) = owasp {
                rule["relationships"] = json!([{
                    "target": {
                        "id": cat.code(),
                        "toolComponent": { "name": "OWASP MCP Top 10" },
                    },
                    "kinds": ["superset"],
                }]);
            }

            rule
        })
        .collect();

    // Only declare the OWASP taxonomy if at least one rule references it.
    let any_owasp = rules.iter().any(|r| r.get("relationships").is_some());
    let taxonomies: Vec<Value> = if any_owasp {
        vec![json!({
            "name": "OWASP MCP Top 10",
            "version": "2025",
            "informationUri": "https://owasp.org/www-project-mcp-top-10/",
            "taxa": OwaspMcp::all()
                .iter()
                .map(|c| json!({ "id": c.code(), "name": c.name() }))
                .collect::<Vec<_>>(),
        })]
    } else {
        Vec::new()
    };

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

    let mut driver = json!({
        "name": "AgentShield",
        "informationUri": "https://github.com/aiconnai/agentshield",
        "version": env!("CARGO_PKG_VERSION"),
        "semanticVersion": env!("CARGO_PKG_VERSION"),
        "rules": rules,
    });
    if !taxonomies.is_empty() {
        driver["taxonomies"] = json!(taxonomies);
    }

    let sarif = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": driver },
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

    use super::{render, render_with_metadata};
    use crate::ir::SourceLocation;
    use crate::rules::{AttackCategory, Confidence, Finding, OwaspMcp, RuleMetadata, Severity};

    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
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
            cwe_id: Some("CWE-918".into()),
        }
    }

    fn make_meta(rule_id: &str, owasp: Option<OwaspMcp>) -> RuleMetadata {
        RuleMetadata {
            id: rule_id.into(),
            name: "SSRF".into(),
            description: "desc".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::Ssrf,
            cwe_id: Some("CWE-918".into()),
            owasp_mcp: owasp,
        }
    }

    #[test]
    fn renders_one_based_start_and_end_columns() {
        let finding = make_finding("SHIELD-003");
        let rendered = render(&[finding], "fixture", Path::new(".")).unwrap();
        let region = &serde_json::from_str::<serde_json::Value>(&rendered).unwrap()["runs"][0]
            ["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startColumn"], 5);
        assert_eq!(region["endColumn"], 21);
        assert_eq!(region["endLine"], 12);
    }

    #[test]
    fn rule_with_owasp_has_taxonomy_and_relationship() {
        let finding = make_finding("SHIELD-003");
        let meta = make_meta("SHIELD-003", Some(OwaspMcp::CommandExecution));
        let rendered =
            render_with_metadata(&[finding], "fixture", Path::new("."), &[meta]).unwrap();
        let log: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let driver = &log["runs"][0]["tool"]["driver"];

        let rule = &driver["rules"][0];
        assert_eq!(rule["properties"]["owasp_mcp"], "MCP05");
        assert_eq!(rule["properties"]["tags"][0], "CWE-918");
        assert_eq!(rule["properties"]["tags"][1], "MCP05");
        assert_eq!(rule["relationships"][0]["target"]["id"], "MCP05");
        assert_eq!(
            rule["relationships"][0]["target"]["toolComponent"]["name"],
            "OWASP MCP Top 10"
        );

        let taxonomies = &driver["taxonomies"];
        assert_eq!(taxonomies[0]["name"], "OWASP MCP Top 10");
        assert_eq!(taxonomies[0]["taxa"].as_array().unwrap().len(), 10);
        assert!(taxonomies[0]["taxa"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == "MCP05"));
    }

    #[test]
    fn rule_without_owasp_omits_relationships_and_taxonomy() {
        let finding = make_finding("SHIELD-003");
        let meta = make_meta("SHIELD-003", None);
        let rendered =
            render_with_metadata(&[finding], "fixture", Path::new("."), &[meta]).unwrap();
        let log: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let driver = &log["runs"][0]["tool"]["driver"];

        let rule = &driver["rules"][0];
        assert!(rule.get("relationships").is_none());
        assert!(rule["properties"].get("owasp_mcp").is_none());
        // CWE tag still present
        assert_eq!(rule["properties"]["tags"][0], "CWE-918");
        // No taxonomy declared when nothing references it
        assert!(driver.get("taxonomies").is_none());
    }

    #[test]
    fn results_and_fingerprints_unchanged_by_metadata() {
        let finding = make_finding("SHIELD-003");
        let fp = finding.fingerprint(Path::new("."));

        let rendered_bare = render_with_metadata(
            std::slice::from_ref(&finding),
            "fixture",
            Path::new("."),
            &[],
        )
        .unwrap();
        let rendered_meta = render_with_metadata(
            &[finding],
            "fixture",
            Path::new("."),
            &[make_meta("SHIELD-003", Some(OwaspMcp::CommandExecution))],
        )
        .unwrap();

        let results_bare = &serde_json::from_str::<serde_json::Value>(&rendered_bare).unwrap()
            ["runs"][0]["results"];
        let results_meta = &serde_json::from_str::<serde_json::Value>(&rendered_meta).unwrap()
            ["runs"][0]["results"];
        assert_eq!(results_bare, results_meta);
        assert_eq!(results_bare[0]["properties"]["fingerprint"], fp);
    }
}
