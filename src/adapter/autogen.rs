use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{project_declared_description, project_declared_permissions};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

static AUTOGEN_REGISTER_FN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)(?:register_function|@user_proxy\.register_for_execution|@assistant\.register_for_llm)\s*\(\s*(?:(?:f=)?(\w+))?(?:[^\)]*?description\s*=\s*["'`]([^"'`]+)["'`])?"#)
        .expect("static regex pattern is valid")
});

static AUTOGEN_DEF_DOC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->[^:]+)?:\s*\n\s*["'`]([\s\S]*?)["'`]"#)
        .expect("static regex pattern is valid")
});

/// Microsoft AutoGen framework adapter (`autogen` and `pyautogen`).
///
/// Detects AutoGen projects by looking for:
/// - `pyproject.toml` / `requirements.txt` with `autogen` or `pyautogen`
/// - Python files importing `from autogen` or `import autogen`
pub struct AutoGenAdapter;

impl super::Adapter for AutoGenAdapter {
    fn framework(&self) -> Framework {
        Framework::AutoGen
    }

    fn detect(&self, root: &Path) -> bool {
        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() {
            if let Some(content) = super::read_file_capped(&pyproject) {
                if content.contains("autogen") || content.contains("pyautogen") {
                    return true;
                }
            }
        }

        let requirements = root.join("requirements.txt");
        if requirements.exists() {
            if let Some(content) = super::read_file_capped(&requirements) {
                if content.lines().any(|l| {
                    let trimmed = l.trim();
                    trimmed.starts_with("autogen")
                        || trimmed.starts_with("pyautogen")
                        || trimmed.starts_with("autogen-agentchat")
                        || trimmed.starts_with("autogen-ext")
                }) {
                    return true;
                }
            }
        }

        if super::mcp::has_recursive_python_import(
            root,
            &[
                "from autogen",
                "import autogen",
                "from autogen.agentchat",
                "from autogen_agentchat",
            ],
        ) {
            return true;
        }

        false
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "autogen-project".into());

        let mut source_files = Vec::new();
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        source_files.retain(|sf| sf.language == Language::Python);

        let mut tools = Vec::new();
        for sf in &source_files {
            tools.extend(extract_autogen_tools_from_source(&sf.path, &sf.content));
        }

        for tool in &mut tools {
            project_declared_permissions(tool);
            project_declared_description(tool);
        }

        let execution = super::pipeline::build_execution_surface(&source_files);
        let data = build_data_surface(&tools, &execution);
        let dependencies = super::mcp::parse_dependencies(root, filter);
        let provenance = super::mcp::parse_provenance(root, filter);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::AutoGen,
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

pub(crate) fn extract_autogen_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = Vec::new();
    let mut doc_map = std::collections::HashMap::new();

    for cap in AUTOGEN_DEF_DOC_RE.captures_iter(content) {
        let func_name = cap[1].to_string();
        let doc = cap[2].trim().to_string();
        doc_map.insert(func_name, doc);
    }

    for cap in AUTOGEN_REGISTER_FN_RE.captures_iter(content) {
        let func_name = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        if func_name.is_empty() {
            continue;
        }

        let explicit_desc = cap.get(2).map(|m| m.as_str().to_string());
        let description = explicit_desc.or_else(|| doc_map.get(&func_name).cloned());

        let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line = content[..match_start].lines().count() + 1;

        tools.push(ToolSurface {
            name: func_name,
            description,
            input_schema: None,
            output_schema: None,
            declared_permissions: Vec::new(),
            declared_capabilities: std::collections::BTreeSet::new(),
            capability_declarations: Vec::new(),
            observed_capabilities: std::collections::BTreeSet::new(),
            capability_evidence: Vec::new(),
            capability_observation_complete: false,
            defined_at: Some(SourceLocation {
                file: path.to_path_buf(),
                line,
                column: 0,
                end_line: Some(line),
                end_column: None,
            }),
        });
    }

    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Adapter;

    #[test]
    fn detects_autogen_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, "pyautogen>=0.2.0\n").unwrap();

        let adapter = AutoGenAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detects_autogen_import() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("agent.py");
        std::fs::write(&src, "from autogen import AssistantAgent\n").unwrap();

        let adapter = AutoGenAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn extracts_autogen_register_function() {
        let content = r#"
from autogen import register_function

def execute_command(cmd: str) -> str:
    """Run a shell command on host."""
    import subprocess
    return subprocess.check_output(cmd, shell=True).decode()

register_function(
    execute_command,
    caller=assistant,
    executor=user_proxy,
    name="execute_command",
    description="Run shell commands securely"
)
"#;
        let tools = extract_autogen_tools_from_source(Path::new("agent.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "execute_command");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("Run shell commands securely")
        );
    }
}
