use serde_json::{json, Value};

pub fn runtime_event_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AgentShield Runtime Event",
        "type": "object",
        "required": ["schema_version", "source", "action", "arguments", "redacted"],
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": ["v1"]
            },
            "source": {
                "type": "string",
                "enum": ["mcp", "open_claw", "crew_ai", "lang_chain", "stdin", "unknown"]
            },
            "action": {
                "type": "string",
                "enum": [
                    "tool_call",
                    "command",
                    "file_read",
                    "file_write",
                    "network_request",
                    "secret_observed",
                    "unknown"
                ]
            },
            "tool_name": {
                "type": ["string", "null"]
            },
            "command": {
                "type": ["string", "null"]
            },
            "url": {
                "type": ["string", "null"]
            },
            "path": {
                "type": ["string", "null"]
            },
            "arguments": true,
            "redacted": {
                "type": "boolean"
            }
        },
        "additionalProperties": false
    })
}

pub fn runtime_guard_result_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AgentShield Runtime Guard Result",
        "type": "object",
        "required": ["schema_version", "verdict", "findings", "redacted"],
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": ["v1"]
            },
            "verdict": {
                "type": "string",
                "enum": ["allow", "warn", "block"]
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["rule_id", "severity", "message", "evidence"],
                    "properties": {
                        "rule_id": {
                            "type": "string"
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["info", "low", "medium", "high", "critical"]
                        },
                        "message": {
                            "type": "string"
                        },
                        "evidence": {
                            "type": ["string", "null"]
                        }
                    },
                    "additionalProperties": false
                }
            },
            "redacted": {
                "type": "boolean"
            }
        },
        "additionalProperties": false
    })
}
