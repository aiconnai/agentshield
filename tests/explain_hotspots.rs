use std::path::PathBuf;

use agentshield::config::ScanPathFilterSummary;
use agentshield::ir::{Framework, Language, ScanTarget, SourceFile, SourceLocation, ToolSurface};
use agentshield::rules::policy::PolicyVerdict;
use agentshield::rules::{AttackCategory, Confidence, Evidence, Finding, Severity};
use agentshield::ux::{render_explain, ExplainOptions};
use agentshield::ScanReport;

#[test]
fn explain_shows_concentrated_blocking_hotspots() {
    let report = report(vec![
        finding(
            "SHIELD-001",
            Severity::High,
            AttackCategory::CommandInjection,
            "scripts/setup.py",
        ),
        finding(
            "SHIELD-001",
            Severity::High,
            AttackCategory::CommandInjection,
            "scripts/raw-lake/import.py",
        ),
        finding(
            "SHIELD-009",
            Severity::High,
            AttackCategory::SupplyChain,
            "package.json",
        ),
        finding(
            "SHIELD-003",
            Severity::Medium,
            AttackCategory::Ssrf,
            "src/mcp/server.ts",
        ),
    ]);

    let output = render_explain(
        &report,
        &ExplainOptions {
            ignore_tests: false,
        },
    );

    assert!(output.contains("Hotspots:"));
    assert!(output.contains("- Runtime-risk concentration: scripts/ (2 high)"));
    assert!(output.contains("- Supply-chain concentration: package.json (1 high)"));
    assert!(output.contains("- Rule concentration: SHIELD-001 (2), SHIELD-009 (1)"));
    assert!(output.contains("consider `[scan] include/exclude` or a baseline"));
}

#[test]
fn explain_reports_no_hotspots_when_there_are_no_findings() {
    let output = render_explain(
        &report(Vec::new()),
        &ExplainOptions {
            ignore_tests: false,
        },
    );

    assert!(output.contains("Hotspots:\n- Blocking findings: none"));
}

fn report(findings: Vec<Finding>) -> ScanReport {
    let pass = findings
        .iter()
        .all(|finding| finding.severity < Severity::High);
    let highest_severity = findings.iter().map(|finding| finding.severity).max();

    ScanReport {
        target_name: "fixture".into(),
        findings,
        verdict: PolicyVerdict {
            pass,
            total_findings: 0,
            effective_findings: 0,
            highest_severity,
            fail_threshold: Severity::High,
        },
        scan_root: PathBuf::from("/repo"),
        targets: vec![ScanTarget {
            name: "fixture".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/repo"),
            tools: vec![ToolSurface {
                name: "server_tool".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                declared_permissions: Vec::new(),
                defined_at: Some(location("src/mcp/server.ts")),
            }],
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from("/repo/src/mcp/server.ts"),
                language: Language::TypeScript,
                content: String::new(),
                size_bytes: 0,
                content_hash: String::new(),
            }],
        }],
        path_filter_summary: ScanPathFilterSummary::default(),
    }
}

fn finding(
    rule_id: &str,
    severity: Severity,
    attack_category: AttackCategory,
    relative_file: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        rule_name: "Rule".into(),
        severity,
        confidence: Confidence::High,
        attack_category,
        message: "finding".into(),
        location: Some(location(relative_file)),
        evidence: vec![Evidence {
            description: "evidence".into(),
            location: None,
            snippet: None,
        }],
        taint_path: None,
        remediation: None,
        cwe_id: None,
    }
}

fn location(relative_file: &str) -> SourceLocation {
    SourceLocation {
        file: PathBuf::from("/repo").join(relative_file),
        line: 1,
        column: 0,
        end_line: None,
        end_column: None,
    }
}
