use std::process::Command;

fn scan(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args(arguments)
        .output()
        .expect("run agentshield")
}

#[test]
fn default_json_contract_has_no_risk_assessment() {
    let output = scan(&[
        "scan",
        "tests/fixtures/mcp_servers/safe_calculator",
        "--format",
        "json",
    ]);
    assert!(output.status.success());

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse default JSON");
    assert!(report.get("risk_assessment").is_none());
}

#[test]
fn opt_in_json_is_informational_bounded_and_policy_neutral() {
    let output = scan(&[
        "scan",
        "tests/fixtures/mcp_servers/vuln_cmd_inject",
        "--format",
        "json",
        "--experimental-risk",
    ]);
    assert_eq!(output.status.code(), Some(1));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse experimental JSON");
    assert_eq!(report["verdict"]["pass"], false);
    assert_eq!(report["risk_assessment"]["status"], "informational");
    assert_eq!(
        report["risk_assessment"]["model_version"],
        "agentshield-risk-v1"
    );
    assert!(report["risk_assessment"]["score"].as_u64().is_some());
    assert!(
        report["risk_assessment"]["contributions"]
            .as_array()
            .expect("contributions array")
            .len()
            <= 50
    );
    assert_eq!(
        report["risk_assessment"]["interpretation"],
        "Prioritization index only; not a probability, percentage, grade, or policy verdict."
    );
}

#[test]
fn opt_in_console_keeps_verdict_primary_and_labels_risk_informational() {
    let output = scan(&[
        "scan",
        "tests/fixtures/mcp_servers/safe_calculator",
        "--experimental-risk",
    ]);
    assert!(output.status.success());

    let rendered = String::from_utf8_lossy(&output.stdout);
    let verdict_position = rendered.find("PASS").expect("console verdict");
    let risk_position = rendered
        .find("Experimental risk assessment (informational)")
        .expect("experimental risk heading");
    assert!(verdict_position < risk_position);
    assert!(rendered.contains("Model: agentshield-risk-v1"));
    assert!(rendered.contains("Interpretation: Prioritization index only"));
}

#[test]
fn unsupported_and_conflicting_output_modes_are_rejected() {
    let sarif = scan(&[
        "scan",
        "tests/fixtures/mcp_servers/safe_calculator",
        "--format",
        "sarif",
        "--experimental-risk",
    ]);
    assert_eq!(sarif.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&sarif.stderr).contains("supports only console and JSON output")
    );

    let explain = scan(&[
        "scan",
        "tests/fixtures/mcp_servers/safe_calculator",
        "--explain",
        "--experimental-risk",
    ]);
    assert_eq!(explain.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&explain.stderr).contains("separate output modes"));
}
