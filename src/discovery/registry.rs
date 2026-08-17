use super::types::{ClientId, ConfigFormat, DiscoveryBase, DiscoveryDescriptor, DiscoveryScope};

const REGISTRY: &[DiscoveryDescriptor] = &[
    DiscoveryDescriptor {
        id: "cursor.user.mcp_json",
        client_id: ClientId::Cursor,
        base: DiscoveryBase::EffectiveProfile,
        relative_path: ".cursor/mcp.json",
        scope: DiscoveryScope::User,
        format: ConfigFormat::McpServersJson,
        descriptor_version: 1,
        documentation_url: "https://docs.cursor.com/context/model-context-protocol",
    },
    DiscoveryDescriptor {
        id: "cursor.workspace.mcp_json",
        client_id: ClientId::Cursor,
        base: DiscoveryBase::ExplicitRoot,
        relative_path: ".cursor/mcp.json",
        scope: DiscoveryScope::Workspace,
        format: ConfigFormat::McpServersJson,
        descriptor_version: 1,
        documentation_url: "https://docs.cursor.com/context/model-context-protocol",
    },
    DiscoveryDescriptor {
        id: "claude_code.workspace.mcp_json",
        client_id: ClientId::ClaudeCode,
        base: DiscoveryBase::ExplicitRoot,
        relative_path: ".mcp.json",
        scope: DiscoveryScope::Workspace,
        format: ConfigFormat::McpServersJson,
        descriptor_version: 1,
        documentation_url: "https://docs.anthropic.com/en/docs/claude-code/mcp",
    },
    DiscoveryDescriptor {
        id: "vscode.workspace.mcp_json",
        client_id: ClientId::VsCode,
        base: DiscoveryBase::ExplicitRoot,
        relative_path: ".vscode/mcp.json",
        scope: DiscoveryScope::Workspace,
        format: ConfigFormat::VsCodeServersJson,
        descriptor_version: 1,
        documentation_url: "https://code.visualstudio.com/docs/agents/reference/mcp-configuration",
    },
];

pub(crate) fn registry() -> &'static [DiscoveryDescriptor] {
    REGISTRY
}

pub(crate) fn valid_path_ref_prefix(value: &str) -> bool {
    if value.starts_with("~/") || value.starts_with("@SOURCE/") {
        return true;
    }
    let Some(root_suffix) = value.strip_prefix("$ROOT[") else {
        return false;
    };
    let Some((index, relative)) = root_suffix.split_once(']') else {
        return false;
    };
    !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit())
        && relative.starts_with('/')
}
