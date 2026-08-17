use std::path::Path;

use crate::ir::execution_surface::{ExecutionSurface, NetworkOperation};
use crate::ir::tool_surface::ToolSurface;
use crate::ir::{ArgumentSource, SourceLocation};

/// Extract server URLs from the OpenAPI `servers` array and emit them as
/// `NetworkOperation` entries. This lets SSRF and data-exfiltration detectors
/// inspect the domains the action contacts.
pub(crate) fn extract_server_urls(
    spec: &serde_json::Value,
    spec_path: &Path,
    execution: &mut ExecutionSurface,
) {
    let servers = match spec.get("servers").and_then(|v| v.as_array()) {
        Some(s) => s,
        None => return,
    };

    for (idx, server) in servers.iter().enumerate() {
        let url = server
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if url.is_empty() {
            continue;
        }

        execution.network_operations.push(NetworkOperation {
            function: "openapi_server".to_string(),
            url_arg: ArgumentSource::Literal(url),
            method: None,
            sends_data: false,
            location: SourceLocation {
                file: spec_path.to_path_buf(),
                // Line numbers are not easily derivable from parsed JSON; use index as proxy
                line: idx + 1,
                column: 0,
                end_line: None,
                end_column: None,
            },
        });
    }
}

/// Extract each OpenAPI path+method as a `ToolSurface`.
///
/// Name format: `{method}_{path}` (e.g. `get_/forecast`).
/// Operation parameters are mapped to the input schema `properties`.
pub(crate) fn extract_path_tools(
    spec: &serde_json::Value,
    spec_path: &Path,
    tools: &mut Vec<ToolSurface>,
) {
    let paths = match spec.get("paths").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return,
    };

    const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

    for (path_str, path_item) in paths {
        let path_obj = match path_item.as_object() {
            Some(o) => o,
            None => continue,
        };

        for method in HTTP_METHODS {
            let operation = match path_obj.get(*method) {
                Some(op) => op,
                None => continue,
            };

            let tool_name = format!("{}_{}", method, path_str);
            let description = operation
                .get("summary")
                .or_else(|| operation.get("description"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let input_schema = build_input_schema_from_operation(operation);

            tools.push(ToolSurface {
                name: tool_name,
                description,
                input_schema: Some(input_schema),
                output_schema: None,
                declared_permissions: vec![],
                defined_at: Some(SourceLocation {
                    file: spec_path.to_path_buf(),
                    line: 1,
                    column: 0,
                    end_line: None,
                    end_column: None,
                }),
                declared_capabilities: Default::default(),
                capability_declarations: Vec::new(),
                observed_capabilities: Default::default(),
                capability_observation_complete: false,
                capability_evidence: Vec::new(),
            });
        }
    }
}

/// Build a JSON Schema `properties` object from the operation's `parameters`
/// and `requestBody`, mirroring the shape expected by downstream detectors.
pub(crate) fn build_input_schema_from_operation(
    operation: &serde_json::Value,
) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<serde_json::Value> = Vec::new();

    // Path / query / header parameters
    if let Some(params) = operation.get("parameters").and_then(|v| v.as_array()) {
        for param in params {
            let name = match param.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let schema = param
                .get("schema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"type": "string"}));
            properties.insert(name.to_string(), schema);

            if param
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                required.push(serde_json::Value::String(name.to_string()));
            }
        }
    }

    // requestBody (JSON only)
    if let Some(rb_schema) = operation
        .get("requestBody")
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|m| m.get("schema"))
    {
        if let Some(props) = rb_schema.get("properties").and_then(|v| v.as_object()) {
            for (k, v) in props {
                properties.insert(k.clone(), v.clone());
            }
        }
        if let Some(req_arr) = rb_schema.get("required").and_then(|v| v.as_array()) {
            required.extend(req_arr.iter().cloned());
        }
    }

    let mut schema = serde_json::json!({
        "type": "object",
        "properties": serde_json::Value::Object(properties)
    });
    if !required.is_empty() {
        schema["required"] = serde_json::Value::Array(required);
    }
    schema
}

pub(crate) fn extract_openai_tools_json(
    value: &serde_json::Value,
    file_path: &Path,
    tools: &mut Vec<ToolSurface>,
) {
    let items = if let Some(arr) = value.as_array() {
        arr.as_slice()
    } else if let Some(arr) = value.get("tools").and_then(|t| t.as_array()) {
        arr.as_slice()
    } else if let Some(arr) = value.get("functions").and_then(|f| f.as_array()) {
        arr.as_slice()
    } else {
        return;
    };

    for item in items {
        let func = if let Some(f) = item.get("function") {
            f
        } else {
            item
        };

        let Some(name) = func.get("name").and_then(|n| n.as_str()) else {
            continue;
        };

        let description = func
            .get("description")
            .and_then(|d| d.as_str())
            .map(str::to_string);
        let input_schema = func.get("parameters").cloned();

        tools.push(ToolSurface {
            name: name.to_string(),
            description,
            input_schema,
            output_schema: None,
            declared_permissions: Vec::new(),
            defined_at: Some(SourceLocation {
                file: file_path.to_path_buf(),
                line: 1,
                column: 0,
                end_line: None,
                end_column: None,
            }),
            declared_capabilities: Default::default(),
            capability_declarations: Vec::new(),
            observed_capabilities: Default::default(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
        });
    }
}
