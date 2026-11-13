use agentshield::{ScanOptions, scan};
use tempfile::TempDir;

/// These fixtures exercise `.agentshield.toml` semantics inside a temp
/// directory that is not the process cwd, so the target's own config is only
/// applied with an explicit opt-in (see `tests/target_config_trust.rs`).
fn trusted_target() -> ScanOptions {
    ScanOptions {
        trust_target_config: true,
        ..ScanOptions::default()
    }
}

#[test]
fn preserves_independent_same_line_filesystem_findings_after_policy_ignore() {
    let fixture = TempDir::new().unwrap();

    std::fs::write(
        fixture.path().join("package.json"),
        r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.path().join(".agentshield.toml"),
        "[policy]\nignore_rules = [\"SHIELD-004\"]\n",
    )
    .unwrap();
    std::fs::write(
        fixture.path().join("server.py"),
        r#"from mcp import Server

server = Server("line-overlap")

@server.tool("read")
def read(path: str):
    open(path); open("../secret")
"#,
    )
    .unwrap();

    let report = scan(fixture.path(), &trusted_target()).unwrap();
    let filesystem_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SHIELD-015")
        .collect();

    assert_eq!(filesystem_findings.len(), 1);
    assert!(
        !report.verdict.pass,
        "the independent traversal finding must remain effective"
    );
    assert_eq!(filesystem_findings[0].location.as_ref().unwrap().column, 16);
}
