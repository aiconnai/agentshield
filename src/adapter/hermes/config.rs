use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::analysis::sensitivity::looks_sensitive_name;
use crate::ir::execution_surface::{
    CommandInvocation, EnvAccess, ExecutionSurface, NetworkOperation,
};
use crate::ir::tool_surface::ToolSurface;
use crate::ir::{ArgumentSource, SourceLocation};

static INTERPOLATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$\{[^}]+\}|\$\([^)]+\)|\$\w+|\{\{[^}]+\}\}|`[^`]+`")
        .expect("static regex pattern is valid")
});

pub(crate) fn contains_config_interpolation(value: &str) -> bool {
    INTERPOLATION_RE.is_match(value)
}

/// Classify a Hermes config scalar (a `command:`/`url:` value, after
/// argument-list expansion) as `Interpolated` when it contains a template
/// or environment placeholder, or `Literal` otherwise.
pub(crate) fn classify_config_value(value: &str) -> ArgumentSource {
    if contains_config_interpolation(value) {
        ArgumentSource::Interpolated
    } else {
        ArgumentSource::Literal(value.to_string())
    }
}

/// Does this YAML file look like a Hermes config?
///
/// `mcp_servers`/`skills`/`terminal`/`gateway`/`sessions` are strong,
/// Hermes-specific top-level keys. `model` alone is too generic (ML/CI
/// configs use it too) and is only trusted when `trust_model_alone` is set
/// by the caller — i.e. the path itself is Hermes-specific (`.hermes/`,
/// `profiles/*/`) or another Hermes artifact was already found.
pub(crate) fn looks_like_hermes_config(path: &Path, trust_model_alone: bool) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };

    has_top_level_key(&content, "mcp_servers")
        || has_top_level_key(&content, "skills")
        || has_top_level_key(&content, "terminal")
        || has_top_level_key(&content, "gateway")
        || has_top_level_key(&content, "sessions")
        || (trust_model_alone && has_top_level_key(&content, "model"))
}

/// Does `content` contain `key:` as an unindented, uncommented top-level
/// YAML mapping key? Avoids matching the key inside comments, nested
/// mappings, or string values.
pub(crate) fn has_top_level_key(content: &str, key: &str) -> bool {
    content.lines().any(|line| {
        !line.starts_with(' ')
            && !line.starts_with('\t')
            && line
                .trim_start()
                .strip_prefix(key)
                .is_some_and(|rest| rest.starts_with(':'))
    })
}

pub(crate) fn has_profile_config(root: &Path) -> bool {
    let profiles_dir = root.join("profiles");
    let Ok(entries) = std::fs::read_dir(profiles_dir) else {
        return false;
    };

    entries
        .flatten()
        .any(|entry| looks_like_hermes_config(&entry.path().join("config.yaml"), true))
}

pub(crate) fn has_hermes_skill_tree(root: &Path) -> bool {
    has_skill_md_under(&root.join("skills")) || has_skill_md_under(&root.join("optional-skills"))
}

pub(crate) fn has_optional_mcp_catalog(root: &Path) -> bool {
    let catalog_dir = root.join("optional-mcps");
    let Ok(entries) = std::fs::read_dir(catalog_dir) else {
        return false;
    };

    entries
        .flatten()
        .any(|entry| entry.path().join("manifest.yaml").exists())
}

pub(crate) fn has_skill_md_under(dir: &Path) -> bool {
    has_skill_md_under_depth(dir, 0)
}

fn has_skill_md_under_depth(dir: &Path, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };

    entries.flatten().any(|entry| {
        let path = entry.path();
        path.join("SKILL.md").exists()
            || (path.is_dir() && !path.is_symlink() && has_skill_md_under_depth(&path, depth + 1))
    })
}

#[derive(Debug, Default)]
pub(crate) struct HermesMcpServer {
    pub(crate) name: String,
    pub(crate) command: Option<String>,
    pub(crate) args: Vec<String>,
    pub(crate) url: Option<String>,
    pub(crate) env_vars: Vec<String>,
    pub(crate) headers: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) line: usize,
}

pub(crate) fn parse_mcp_servers_from_yaml(
    content: &str,
    path: &Path,
    tools: &mut Vec<ToolSurface>,
    execution: &mut ExecutionSurface,
) {
    let servers = parse_mcp_server_entries(content);

    for server in servers.into_iter().filter(|server| server.enabled) {
        let location = SourceLocation {
            file: path.to_path_buf(),
            line: server.line,
            column: 0,
            end_line: None,
            end_column: None,
        };

        tools.push(ToolSurface {
            name: server.name.clone(),
            description: Some(format!(
                "MCP server '{}' configured in Hermes Agent",
                server.name
            )),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {}
            })),
            output_schema: None,
            declared_permissions: vec![],
            defined_at: Some(location.clone()),
            declared_capabilities: Default::default(),
            capability_declarations: Vec::new(),
            observed_capabilities: Default::default(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
        });

        if let Some(command) = server.command {
            let full_command = if server.args.is_empty() {
                command.clone()
            } else {
                format!("{} {}", command, server.args.join(" "))
            };
            execution.commands.push(CommandInvocation {
                function: command,
                command_arg: classify_config_value(&full_command),
                location: location.clone(),
            });
        }

        if let Some(url) = server.url {
            execution.network_operations.push(NetworkOperation {
                function: "hermes.mcp.http".into(),
                url_arg: classify_config_value(&url),
                method: None,
                sends_data: true,
                location: location.clone(),
            });
        }

        for var_name in server.env_vars {
            execution.env_accesses.push(EnvAccess {
                is_sensitive: looks_sensitive_name(&var_name),
                var_name: ArgumentSource::Literal(var_name),
                location: location.clone(),
            });
        }

        for header_name in server.headers {
            execution.env_accesses.push(EnvAccess {
                is_sensitive: looks_sensitive_name(&header_name),
                var_name: ArgumentSource::Literal(format!("header:{header_name}")),
                location: location.clone(),
            });
        }
    }
}

pub(crate) fn parse_mcp_server_entries(content: &str) -> Vec<HermesMcpServer> {
    let mut servers = Vec::new();
    let mut in_mcp_servers = false;
    let mut mcp_indent = 0usize;
    let mut current: Option<HermesMcpServer> = None;
    let mut current_indent = 0usize;
    let mut section: Option<&str> = None;

    for (line_index, raw_line) in content.lines().enumerate() {
        let line_no = line_index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = raw_line.len() - raw_line.trim_start().len();
        if trimmed == "mcp_servers:" {
            in_mcp_servers = true;
            mcp_indent = indent;
            continue;
        }

        if !in_mcp_servers {
            continue;
        }

        if indent <= mcp_indent {
            break;
        }

        if indent == mcp_indent + 2 && trimmed.ends_with(':') && !trimmed.contains(' ') {
            if let Some(server) = current.take() {
                servers.push(server);
            }
            let name = clean_scalar(trimmed.trim_end_matches(':'));
            current = Some(HermesMcpServer {
                name,
                enabled: true,
                line: line_no,
                ..Default::default()
            });
            current_indent = indent;
            section = None;
            continue;
        }

        let Some(server) = current.as_mut() else {
            continue;
        };

        if indent <= current_indent {
            section = None;
            continue;
        }

        if trimmed == "env:" || trimmed == "headers:" || trimmed == "args:" {
            section = Some(trimmed.trim_end_matches(':'));
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("command:") {
            server.command = Some(clean_scalar(value));
            section = None;
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("url:") {
            server.url = Some(clean_scalar(value));
            section = None;
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("enabled:") {
            server.enabled = clean_scalar(value) != "false";
            section = None;
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("args:") {
            server.args.extend(parse_inline_list(value));
            section = Some("args");
            continue;
        }

        match section {
            Some("env") => {
                if let Some((key, _)) = trimmed.split_once(':') {
                    server.env_vars.push(clean_scalar(key));
                }
            }
            Some("headers") => {
                if let Some((key, _)) = trimmed.split_once(':') {
                    server.headers.push(clean_scalar(key));
                }
            }
            Some("args") => {
                if let Some(arg) = trimmed.strip_prefix('-') {
                    server.args.push(clean_scalar(arg));
                }
            }
            _ => {}
        }
    }

    if let Some(server) = current {
        servers.push(server);
    }

    servers
}

pub(crate) fn parse_inline_list(value: &str) -> Vec<String> {
    let value = value.trim();
    let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) else {
        return Vec::new();
    };

    inner
        .split(',')
        .map(clean_scalar)
        .filter(|item| !item.is_empty())
        .collect()
}

pub(crate) fn clean_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}
