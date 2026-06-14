//! Cursor Rules adapter.
//!
//! Detects Cursor IDE configuration files and loads them into the unified IR.
//!
//! Supported files:
//! - `.cursorrules` — project-level rules file (plain text)
//! - `.cursor/mcp.json` — MCP server definitions used by Cursor

use std::path::Path;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::execution_surface::{CommandInvocation, EnvAccess, ExecutionSurface};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::tool_surface::ToolSurface;
use crate::ir::*;

/// Cursor Rules adapter.
///
/// Detects Cursor IDE configuration by looking for:
/// - `.cursorrules` (project-level rules file)
/// - `.cursor/mcp.json` (Cursor MCP server config)
pub struct CursorRulesAdapter;

impl super::Adapter for CursorRulesAdapter {
    fn framework(&self) -> Framework {
        Framework::CursorRules
    }

    fn detect(&self, root: &Path) -> bool {
        root.join(".cursorrules").exists() || root.join(".cursor").join("mcp.json").exists()
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "cursor-project".into());

        let mut tools: Vec<ToolSurface> = Vec::new();
        let mut execution = ExecutionSurface::default();
        let mut source_files: Vec<SourceFile> = Vec::new();

        // Load .cursorrules as a plain-text source file (no structured parsing needed)
        let cursorrules_path = root.join(".cursorrules");
        if cursorrules_path.exists() && filter.allows_path(root, &cursorrules_path) {
            if let Some(sf) = read_as_source_file(&cursorrules_path) {
                source_files.push(sf);
            }
        }

        // Load .cursor/mcp.json — MCP server definitions
        let mcp_json_path = root.join(".cursor").join("mcp.json");
        if mcp_json_path.exists() && filter.allows_path(root, &mcp_json_path) {
            if let Some(sf) = read_as_source_file(&mcp_json_path) {
                source_files.push(sf);
            }

            if let Ok(content) = std::fs::read_to_string(&mcp_json_path) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                    parse_mcp_servers(&value, &mcp_json_path, &mut tools, &mut execution);
                }
            }
        }

        let dependencies = super::mcp::parse_dependencies(root);
        let provenance = super::mcp::parse_provenance(root);
        let data = build_data_surface(&tools, &execution);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::CursorRules,
            root_path: root.to_path_buf(),
            tools,
            execution,
            data,
            dependencies,
            provenance,
            source_files,
        }])
    }
}

/// Parse `mcpServers` entries from `.cursor/mcp.json`.
///
/// Each server entry becomes a `ToolSurface` (the server exposes tools to the agent)
/// and a `CommandInvocation` (the command that starts the server process).
/// Env vars in the `env` map are emitted as `EnvAccess` entries.
fn parse_mcp_servers(
    value: &serde_json::Value,
    mcp_path: &Path,
    tools: &mut Vec<ToolSurface>,
    execution: &mut ExecutionSurface,
) {
    let servers = match value.get("mcpServers").and_then(|v| v.as_object()) {
        Some(s) => s,
        None => return,
    };

    for (server_name, server_cfg) in servers {
        let command = server_cfg
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let args: Vec<String> = server_cfg
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        // Build full command string for the invocation
        let full_command = if args.is_empty() {
            command.clone()
        } else {
            format!("{} {}", command, args.join(" "))
        };

        let location = SourceLocation {
            file: mcp_path.to_path_buf(),
            line: 1,
            column: 0,
            end_line: None,
            end_column: None,
        };

        // Emit a ToolSurface representing the MCP server (it exposes tools to the agent)
        tools.push(ToolSurface {
            name: server_name.clone(),
            description: Some(format!("MCP server '{}' configured in Cursor", server_name)),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {}
            })),
            output_schema: None,
            declared_permissions: vec![],
            defined_at: Some(location.clone()),
        });

        // Emit a CommandInvocation for the process that starts the server
        if !command.is_empty() {
            execution.commands.push(CommandInvocation {
                function: command.clone(),
                command_arg: ArgumentSource::Literal(full_command),
                location: location.clone(),
            });
        }

        // Emit EnvAccess entries for every declared env var
        if let Some(env_map) = server_cfg.get("env").and_then(|v| v.as_object()) {
            for (var_name, _var_value) in env_map {
                let is_sensitive = looks_sensitive(var_name);
                execution.env_accesses.push(EnvAccess {
                    var_name: ArgumentSource::Literal(var_name.clone()),
                    is_sensitive,
                    location: location.clone(),
                });
            }
        }
    }
}

/// Heuristic: a variable name looks sensitive if it contains common secret keywords.
fn looks_sensitive(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.contains("KEY")
        || upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("PASSWORD")
        || upper.contains("CREDENTIAL")
        || upper.contains("AUTH")
        || upper.starts_with("AWS_")
        || upper.starts_with("GH_")
        || upper.starts_with("GITHUB_")
}

/// Read a file as a `SourceFile` entry. Returns `None` if the file cannot be read.
fn read_as_source_file(path: &Path) -> Option<SourceFile> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > 1_048_576 {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    let lang = if ext.is_empty() {
        // .cursorrules has no extension — treat as Markdown (plain text)
        Language::Markdown
    } else {
        Language::from_extension(&ext)
    };
    let hash = format!(
        "{:x}",
        sha2::Digest::finalize(sha2::Sha256::new().chain_update(content.as_bytes()))
    );
    Some(SourceFile {
        path: path.to_path_buf(),
        language: lang,
        size_bytes: metadata.len(),
        content_hash: hash,
        content,
    })
}

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Adapter;
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cursor_rules")
    }

    #[test]
    fn test_detect_cursor_rules() {
        let dir = fixture_dir();
        let adapter = CursorRulesAdapter;
        assert!(
            adapter.detect(&dir),
            "should detect Cursor Rules fixture via .cursorrules or .cursor/mcp.json"
        );
    }

    #[test]
    fn test_detect_non_cursor_project() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/safe_calculator");
        let adapter = CursorRulesAdapter;
        assert!(
            !adapter.detect(&dir),
            "should not detect Cursor Rules in an MCP calculator fixture"
        );
    }

    #[test]
    fn test_load_cursor_rules_framework() {
        let dir = fixture_dir();
        let adapter = CursorRulesAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].framework, Framework::CursorRules);
    }

    #[test]
    fn test_load_cursor_rules_mcp_servers_as_tools() {
        let dir = fixture_dir();
        let adapter = CursorRulesAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // Fixture .cursor/mcp.json has 2 servers: filesystem and github
        assert_eq!(
            target.tools.len(),
            2,
            "expected 2 tool entries (one per MCP server), got {}",
            target.tools.len()
        );

        let tool_names: Vec<&str> = target.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(
            tool_names.contains(&"filesystem"),
            "expected 'filesystem' server tool"
        );
        assert!(
            tool_names.contains(&"github"),
            "expected 'github' server tool"
        );
    }

    #[test]
    fn test_load_cursor_rules_command_invocations() {
        let dir = fixture_dir();
        let adapter = CursorRulesAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // Both servers use `npx` as command
        assert!(
            !target.execution.commands.is_empty(),
            "expected command invocations from MCP server configs"
        );

        let uses_npx = target
            .execution
            .commands
            .iter()
            .any(|c| c.function == "npx");
        assert!(uses_npx, "expected 'npx' command from MCP server config");
    }

    #[test]
    fn test_load_cursor_rules_env_accesses() {
        let dir = fixture_dir();
        let adapter = CursorRulesAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // github server has GITHUB_PERSONAL_ACCESS_TOKEN env var
        assert!(
            !target.execution.env_accesses.is_empty(),
            "expected env accesses from github MCP server env map"
        );

        let has_pat = target.execution.env_accesses.iter().any(|e| {
            matches!(&e.var_name, ArgumentSource::Literal(n) if n.contains("GITHUB_PERSONAL_ACCESS_TOKEN"))
        });
        assert!(has_pat, "expected GITHUB_PERSONAL_ACCESS_TOKEN env access");

        // PAT should be flagged as sensitive
        let pat_entry = target.execution.env_accesses.iter().find(|e| {
            matches!(&e.var_name, ArgumentSource::Literal(n) if n.contains("GITHUB_PERSONAL_ACCESS_TOKEN"))
        });
        assert!(
            pat_entry.map(|e| e.is_sensitive).unwrap_or(false),
            "GITHUB_PERSONAL_ACCESS_TOKEN should be marked sensitive"
        );
    }

    #[test]
    fn test_load_cursor_rules_source_files() {
        let dir = fixture_dir();
        let adapter = CursorRulesAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        assert!(
            !target.source_files.is_empty(),
            "expected source files from cursor fixture"
        );

        let file_names: Vec<String> = target
            .source_files
            .iter()
            .map(|sf| {
                sf.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        assert!(
            file_names.contains(&".cursorrules".to_string()),
            "expected .cursorrules in source files"
        );
        assert!(
            file_names.contains(&"mcp.json".to_string()),
            "expected mcp.json in source files"
        );
    }
}
