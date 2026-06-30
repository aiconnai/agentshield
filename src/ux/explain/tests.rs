use std::path::{Path, PathBuf};

use crate::config::ScanPathFilterSummary;
use crate::ir::{Framework, Language, ScanTarget, SourceFile};
use crate::rules::policy::PolicyVerdict;
use crate::rules::{AttackCategory, Confidence, Evidence, Finding, Severity};
use crate::ScanReport;

use super::*;

fn finding(rule_id: &str, severity: Severity, category: AttackCategory) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        rule_name: "Rule".into(),
        severity,
        confidence: Confidence::High,
        attack_category: category,
        message: "Dependency '@modelcontextprotocol/sdk' is not pinned: ^1.0.0".into(),
        location: Some(crate::ir::SourceLocation {
            file: PathBuf::from("package.json"),
            line: 1,
            column: 0,
            end_line: None,
            end_column: None,
        }),
        evidence: vec![Evidence {
            description: "evidence".into(),
            location: None,
            snippet: None,
        }],
        taint_path: None,
        remediation: Some("fix it".into()),
        cwe_id: None,
    }
}

fn report(findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        target_name: "fixture".into(),
        findings,
        verdict: PolicyVerdict {
            pass: true,
            total_findings: 2,
            effective_findings: 2,
            highest_severity: Some(Severity::Medium),
            fail_threshold: Severity::High,
        },
        scan_root: PathBuf::from("."),
        targets: vec![ScanTarget {
            name: "fixture".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from("server.py"),
                language: Language::Python,
                content: String::new(),
                size_bytes: 0,
                content_hash: String::new(),
            }],
        }],
        path_filter_summary: ScanPathFilterSummary::default(),
    }
}

#[test]
fn explain_separates_runtime_and_supply_chain_findings() {
    let output = render_explain(
        &report(vec![finding(
            "SHIELD-009",
            Severity::Medium,
            AttackCategory::SupplyChain,
        )]),
        &ExplainOptions { ignore_tests: true },
    );

    assert!(output.contains("Gate: PASS"));
    assert!(output.contains("Runtime-risk findings: none"));
    assert!(output.contains("Supply-chain hygiene: 1"));
    assert!(output.contains("Security confidence: High"));
    assert!(output.contains("npm install @modelcontextprotocol/sdk@<exact-version> --save-exact"));
}

#[test]
fn no_adapter_explain_is_inconclusive() {
    let output = render_no_adapter_explain(Path::new("."), true, &ScanPathFilterSummary::default());

    assert!(output.contains("Gate: INCONCLUSIVE"));
    assert!(output.contains("does not mean the project is safe"));
}

#[test]
fn quickstart_config_enables_project_defaults() {
    let config = quickstart_config_toml(Severity::High, true);

    assert!(config.contains("fail_on = \"high\""));
    assert!(config.contains("ignore_tests = true"));
    assert!(config.contains("[runtime.proxy]"));
}
