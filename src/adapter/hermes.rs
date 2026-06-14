//! Hermes Agent adapter.
//!
//! Detects Hermes Agent client configuration and skill trees, then loads:
//! - `config.yaml` / `.hermes/config.yaml` / profile configs with `mcp_servers`
//! - `.hermes.md` project context
//! - `skills/`, `optional-skills/`, and `optional-mcps/` artifacts

use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::execution_surface::{
    CommandInvocation, EnvAccess, ExecutionSurface, NetworkOperation,
};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::tool_surface::ToolSurface;
use crate::ir::*;
use crate::parser;

/// Hermes Agent client adapter.
///
/// Detection intentionally requires Hermes-specific artifacts. Generic context
/// files such as `AGENTS.md` and `CLAUDE.md` are not enough to avoid treating
/// ordinary coding-agent projects as Hermes projects.
pub struct HermesAgentAdapter;

impl super::Adapter for HermesAgentAdapter {
    fn framework(&self) -> Framework {
        Framework::HermesAgent
    }

    fn detect(&self, root: &Path) -> bool {
        root.join(".hermes.md").exists()
            || looks_like_hermes_config(&root.join("config.yaml"))
            || looks_like_hermes_config(&root.join(".hermes").join("config.yaml"))
            || has_profile_config(root)
            || has_hermes_skill_tree(root)
            || has_optional_mcp_catalog(root)
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "hermes-agent".into());

        let mut tools: Vec<ToolSurface> = Vec::new();
        let mut execution = ExecutionSurface::default();
        let mut source_files: Vec<SourceFile> = Vec::new();

        collect_hermes_source_files(root, filter, &mut source_files)?;

        for sf in &source_files {
            if is_yaml_file(&sf.path) {
                parse_mcp_servers_from_yaml(&sf.content, &sf.path, &mut tools, &mut execution);
            }
        }

        let mut parsed_files: Vec<(PathBuf, parser::ParsedFile)> = Vec::new();
        for sf in &source_files {
            if let Some(parser) = parser::parser_for_language(sf.language) {
                if let Ok(parsed) = parser.parse_file(&sf.path, &sf.content) {
                    parsed_files.push((sf.path.clone(), parsed));
                }
            }
        }

        apply_cross_file_sanitization(&mut parsed_files);

        for (_, parsed) in parsed_files {
            execution.commands.extend(parsed.commands);
            execution.file_operations.extend(parsed.file_operations);
            execution
                .network_operations
                .extend(parsed.network_operations);
            execution.env_accesses.extend(parsed.env_accesses);
            execution.dynamic_exec.extend(parsed.dynamic_exec);
        }

        let dependencies = super::mcp::parse_dependencies(root, filter);
        let provenance = super::mcp::parse_provenance(root, filter);
        let data = build_data_surface(&tools, &execution);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::HermesAgent,
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

fn looks_like_hermes_config(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };

    content.contains("mcp_servers:")
        || content.contains("skills:")
        || content.contains("terminal:")
        || content.contains("gateway:")
        || content.contains("sessions:")
        || content.contains("model:")
}

fn has_profile_config(root: &Path) -> bool {
    let profiles_dir = root.join("profiles");
    let Ok(entries) = std::fs::read_dir(profiles_dir) else {
        return false;
    };

    entries
        .flatten()
        .any(|entry| looks_like_hermes_config(&entry.path().join("config.yaml")))
}

fn has_hermes_skill_tree(root: &Path) -> bool {
    has_skill_md_under(&root.join("skills")) || has_skill_md_under(&root.join("optional-skills"))
}

fn has_optional_mcp_catalog(root: &Path) -> bool {
    let catalog_dir = root.join("optional-mcps");
    let Ok(entries) = std::fs::read_dir(catalog_dir) else {
        return false;
    };

    entries
        .flatten()
        .any(|entry| entry.path().join("manifest.yaml").exists())
}

fn has_skill_md_under(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };

    entries.flatten().any(|entry| {
        let path = entry.path();
        path.join("SKILL.md").exists() || has_skill_md_under(&path)
    })
}

fn collect_hermes_source_files(
    root: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    for path in [
        root.join("config.yaml"),
        root.join(".hermes").join("config.yaml"),
        root.join(".hermes.md"),
        root.join("SOUL.md"),
    ] {
        push_source_file_if_allowed(root, &path, filter, source_files)?;
    }

    collect_profile_configs(root, filter, source_files)?;

    for dir in [
        root.join("skills"),
        root.join("optional-skills"),
        root.join("optional-mcps"),
    ] {
        collect_artifact_tree(root, &dir, filter, source_files)?;
    }

    Ok(())
}

fn collect_profile_configs(
    root: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    let profiles_dir = root.join("profiles");
    let Ok(entries) = std::fs::read_dir(profiles_dir) else {
        return Ok(());
    };

    for entry in entries.flatten() {
        push_source_file_if_allowed(
            root,
            &entry.path().join("config.yaml"),
            filter,
            source_files,
        )?;
    }

    Ok(())
}

fn collect_artifact_tree(
    root: &Path,
    dir: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    let walker = ignore::WalkBuilder::new(dir)
        .hidden(true)
        .git_ignore(true)
        .max_depth(Some(6))
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if filter.ignore_tests() && super::mcp::is_test_file(path) {
            continue;
        }

        if !filter.allows_path(root, path) {
            continue;
        }

        let Some(file_name) = path.file_name().map(|n| n.to_string_lossy()) else {
            continue;
        };

        let language = language_for_path(path);
        let is_relevant = file_name == "SKILL.md"
            || file_name == "manifest.yaml"
            || matches!(
                language,
                Language::Python
                    | Language::Shell
                    | Language::JavaScript
                    | Language::TypeScript
                    | Language::Json
                    | Language::Yaml
                    | Language::Markdown
            );

        if is_relevant {
            push_source_file(path, source_files)?;
        }
    }

    Ok(())
}

fn push_source_file_if_allowed(
    root: &Path,
    path: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    if filter.allows_path(root, path) {
        push_source_file(path, source_files)?;
    }
    Ok(())
}

fn push_source_file(path: &Path, source_files: &mut Vec<SourceFile>) -> Result<()> {
    if !path.exists() || !path.is_file() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)?;
    if metadata.len() > 1_048_576 {
        return Ok(());
    }

    if let Ok(content) = std::fs::read_to_string(path) {
        let hash = format!(
            "{:x}",
            sha2::Digest::finalize(sha2::Sha256::new().chain_update(content.as_bytes()))
        );
        source_files.push(SourceFile {
            path: path.to_path_buf(),
            language: language_for_path(path),
            size_bytes: metadata.len(),
            content_hash: hash,
            content,
        });
    }

    Ok(())
}

fn language_for_path(path: &Path) -> Language {
    let Some(file_name) = path.file_name().map(|n| n.to_string_lossy()) else {
        return Language::Unknown;
    };

    if file_name == ".hermes.md" || file_name == "SKILL.md" || file_name == "SOUL.md" {
        return Language::Markdown;
    }

    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    Language::from_extension(&ext)
}

fn is_yaml_file(path: &Path) -> bool {
    matches!(language_for_path(path), Language::Yaml)
}

#[derive(Debug, Default)]
struct HermesMcpServer {
    name: String,
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    env_vars: Vec<String>,
    headers: Vec<String>,
    enabled: bool,
    line: usize,
}

fn parse_mcp_servers_from_yaml(
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
        });

        if let Some(command) = server.command {
            let full_command = if server.args.is_empty() {
                command.clone()
            } else {
                format!("{} {}", command, server.args.join(" "))
            };
            execution.commands.push(CommandInvocation {
                function: command,
                command_arg: ArgumentSource::Literal(full_command),
                location: location.clone(),
            });
        }

        if let Some(url) = server.url {
            execution.network_operations.push(NetworkOperation {
                function: "hermes.mcp.http".into(),
                url_arg: ArgumentSource::Literal(url),
                method: None,
                sends_data: true,
                location: location.clone(),
            });
        }

        for var_name in server.env_vars {
            execution.env_accesses.push(EnvAccess {
                is_sensitive: looks_sensitive(&var_name),
                var_name: ArgumentSource::Literal(var_name),
                location: location.clone(),
            });
        }

        for header_name in server.headers {
            execution.env_accesses.push(EnvAccess {
                is_sensitive: looks_sensitive(&header_name),
                var_name: ArgumentSource::Literal(format!("header:{header_name}")),
                location: location.clone(),
            });
        }
    }
}

fn parse_mcp_server_entries(content: &str) -> Vec<HermesMcpServer> {
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
            let name = trimmed.trim_end_matches(':').to_string();
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

fn parse_inline_list(value: &str) -> Vec<String> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Vec::new();
    }

    value
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(clean_scalar)
        .filter(|item| !item.is_empty())
        .collect()
}

fn clean_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

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

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Adapter;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hermes_agent")
    }

    #[test]
    fn test_detect_hermes_agent() {
        let adapter = HermesAgentAdapter;
        assert!(adapter.detect(&fixture_dir()));
    }

    #[test]
    fn test_detect_non_hermes_project() {
        let adapter = HermesAgentAdapter;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/safe_calculator");
        assert!(!adapter.detect(&dir));
    }

    #[test]
    fn test_load_hermes_framework() {
        let adapter = HermesAgentAdapter;
        let targets = adapter.load(&fixture_dir(), false).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].framework, Framework::HermesAgent);
    }

    #[test]
    fn test_load_hermes_mcp_servers() {
        let adapter = HermesAgentAdapter;
        let targets = adapter.load(&fixture_dir(), false).unwrap();
        let target = &targets[0];

        let tool_names: Vec<&str> = target.tools.iter().map(|tool| tool.name.as_str()).collect();
        assert!(tool_names.contains(&"filesystem"));
        assert!(tool_names.contains(&"company_api"));
        assert!(!tool_names.contains(&"legacy"));

        assert!(target
            .execution
            .commands
            .iter()
            .any(|command| command.function == "npx"));
        assert!(target
            .execution
            .network_operations
            .iter()
            .any(|network| matches!(&network.url_arg, ArgumentSource::Literal(url) if url == "https://mcp.internal.example.com")));
    }

    #[test]
    fn test_load_hermes_sensitive_env_and_headers() {
        let adapter = HermesAgentAdapter;
        let targets = adapter.load(&fixture_dir(), false).unwrap();
        let target = &targets[0];

        assert!(target.execution.env_accesses.iter().any(|env| {
            env.is_sensitive
                && matches!(&env.var_name, ArgumentSource::Literal(name) if name == "GITHUB_PERSONAL_ACCESS_TOKEN")
        }));
        assert!(target.execution.env_accesses.iter().any(|env| {
            env.is_sensitive
                && matches!(&env.var_name, ArgumentSource::Literal(name) if name == "header:Authorization")
        }));
    }
}
