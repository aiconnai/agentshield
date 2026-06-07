use agentshield::runtime::{runtime_event_schema_json, runtime_guard_result_schema_json};

#[test]
fn runtime_event_schema_has_expected_title() {
    let schema = runtime_event_schema_json();
    assert_eq!(schema["title"], "AgentShield Runtime Event");
}

#[test]
fn runtime_guard_result_schema_has_expected_title() {
    let schema = runtime_guard_result_schema_json();
    assert_eq!(schema["title"], "AgentShield Runtime Guard Result");
}

#[test]
fn runtime_event_schema_requires_schema_version() {
    let schema = runtime_event_schema_json();
    let required = schema["required"].as_array().unwrap();

    assert!(required
        .iter()
        .any(|field| field.as_str() == Some("schema_version")));
}

#[test]
fn runtime_guard_result_schema_requires_schema_version() {
    let schema = runtime_guard_result_schema_json();
    let required = schema["required"].as_array().unwrap();

    assert!(required
        .iter()
        .any(|field| field.as_str() == Some("schema_version")));
}
