use crate::ir::tool_surface::{DeclaredPermission, PermissionType, ToolSurface};

/// Extract tool definitions from an MCP-style JSON tool list.
pub fn parse_tools_from_json(value: &serde_json::Value) -> Vec<ToolSurface> {
    let mut tools = Vec::new();

    let items = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(arr) = value.get("tools").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        return tools;
    };

    for item in &items {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let description = item
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let input_schema = item
            .get("inputSchema")
            .or(item.get("input_schema"))
            .cloned();

        // Infer permissions from description text
        let desc_text = description.as_deref().unwrap_or("");
        let permissions = infer_permissions_from_description(desc_text);

        tools.push(ToolSurface {
            name,
            description,
            input_schema,
            output_schema: None,
            declared_permissions: permissions,
            defined_at: None,
            declared_capabilities: Default::default(),
            capability_declarations: Vec::new(),
            observed_capabilities: Default::default(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
        });
    }

    tools
}

fn infer_permissions_from_description(desc: &str) -> Vec<DeclaredPermission> {
    let lower = desc.to_lowercase();
    let mut perms = Vec::new();

    if lower.contains("file") || lower.contains("read") || lower.contains("directory") {
        perms.push(DeclaredPermission {
            permission_type: PermissionType::FileRead,
            target: None,
            description: Some("Inferred from description".into()),
        });
    }
    if lower.contains("write") || lower.contains("save") || lower.contains("create file") {
        perms.push(DeclaredPermission {
            permission_type: PermissionType::FileWrite,
            target: None,
            description: Some("Inferred from description".into()),
        });
    }
    if lower.contains("http")
        || lower.contains("url")
        || lower.contains("fetch")
        || lower.contains("request")
        || lower.contains("network")
    {
        perms.push(DeclaredPermission {
            permission_type: PermissionType::NetworkAccess,
            target: None,
            description: Some("Inferred from description".into()),
        });
    }
    if lower.contains("exec")
        || lower.contains("run")
        || lower.contains("command")
        || lower.contains("shell")
        || lower.contains("subprocess")
    {
        perms.push(DeclaredPermission {
            permission_type: PermissionType::ProcessExec,
            target: None,
            description: Some("Inferred from description".into()),
        });
    }

    perms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mcp_tools_list() {
        let json = serde_json::json!({
            "tools": [
                {
                    "name": "calculator_add",
                    "description": "Add two numbers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"}
                        }
                    }
                },
                {
                    "name": "fetch_url",
                    "description": "Fetch content from a URL",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"}
                        }
                    }
                }
            ]
        });
        let tools = parse_tools_from_json(&json);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "calculator_add");
        assert!(tools[0].declared_permissions.is_empty());
        assert_eq!(tools[1].name, "fetch_url");
        assert!(!tools[1].declared_permissions.is_empty());
    }
}
