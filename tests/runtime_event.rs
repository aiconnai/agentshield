use agentshield::runtime::{
    RuntimeAction, RuntimeEvent, RuntimeEventSource, RuntimeGuardResult, RuntimeSchemaVersion,
    RuntimeVerdict,
};
use serde_json::json;

#[test]
fn runtime_schema_version_serializes_as_v1() {
    let serialized = serde_json::to_string(&RuntimeSchemaVersion::V1).unwrap();
    assert_eq!(serialized, "\"v1\"");
}

#[test]
fn runtime_verdict_allow_serializes_as_allow() {
    let serialized = serde_json::to_string(&RuntimeVerdict::Allow).unwrap();
    assert_eq!(serialized, "\"allow\"");
}

#[test]
fn runtime_event_round_trips_through_json() {
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("search".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({ "query": "agent policy" }),
        redacted: false,
    };

    let serialized = serde_json::to_string(&event).unwrap();
    let deserialized: RuntimeEvent = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized, event);
}

#[test]
fn runtime_guard_result_serializes_empty_findings_array() {
    let result = RuntimeGuardResult {
        schema_version: RuntimeSchemaVersion::V1,
        verdict: RuntimeVerdict::Allow,
        findings: Vec::new(),
        redacted: false,
    };

    let serialized = serde_json::to_value(result).unwrap();
    assert_eq!(serialized["findings"], json!([]));
}
