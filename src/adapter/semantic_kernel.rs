use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{project_declared_description, project_declared_permissions};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

static SK_KERNEL_FN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)@kernel_function\s*(?:\(\s*(?:[^\)]*?name\s*=\s*["'`]([^"'`]+)["'`])?(?:[^\)]*?description\s*=\s*["'`]([^"'`]+)["'`])?[^\)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->[^:]+)?:\s*(?:\n\s*["'`]([\s\S]*?)["'`])?"#)
        .expect("static regex pattern is valid")
});

/// Microsoft Semantic Kernel framework adapter (`semantic-kernel`).
///
/// Detects Semantic Kernel projects by looking for:
/// - `pyproject.toml` / `requirements.txt` with `semantic-kernel`
/// - Python files importing `from semantic_kernel` or `import semantic_kernel`
pub struct SemanticKernelAdapter;

impl super::Adapter for SemanticKernelAdapter {
    fn framework(&self) -> Framework {
        Framework::SemanticKernel
    }

    fn detect(&self, root: &Path) -> bool {
        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() {
            if let Some(content) = super::read_file_capped(&pyproject) {
                if content.contains("semantic-kernel") || content.contains("semantic_kernel") {
                    return true;
                }
            }
        }

        let requirements = root.join("requirements.txt");
        if requirements.exists() {
            if let Some(content) = super::read_file_capped(&requirements) {
                if content.lines().any(|l| {
                    let trimmed = l.trim();
                    trimmed.starts_with("semantic-kernel")
                        || trimmed.starts_with("semantic_kernel")
                }) {
                    return true;
                }
            }
        }

        if super::mcp::has_recursive_python_import(
            root,
            &[
                "from semantic_kernel",
                "import semantic_kernel",
                "@kernel_function",
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
            .unwrap_or_else(|| "semantic-kernel-project".into());

        let mut source_files = Vec::new();
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        source_files.retain(|sf| sf.language == Language::Python);

        let mut tools = Vec::new();
        for sf in &source_files {
            tools.extend(extract_semantic_kernel_tools_from_source(&sf.path, &sf.content));
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
            framework: Framework::SemanticKernel,
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

pub(crate) fn extract_semantic_kernel_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = Vec::new();

    for cap in SK_KERNEL_FN_RE.captures_iter(content) {
        let explicit_name = cap.get(1).map(|m| m.as_str().to_string());
        let explicit_desc = cap.get(2).map(|m| m.as_str().to_string());
        let def_name = cap[3].to_string();
        let docstring = cap.get(4).map(|m| m.as_str().trim().to_string());

        let tool_name = explicit_name.unwrap_or(def_name);
        let description = explicit_desc.or(docstring);

        let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line = content[..match_start].lines().count() + 1;

        tools.push(ToolSurface {
            name: tool_name,
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
    fn detects_semantic_kernel_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, "semantic-kernel>=1.0.0\n").unwrap();

        let adapter = SemanticKernelAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detects_semantic_kernel_import() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("plugin.py");
        std::fs::write(&src, "from semantic_kernel.functions import kernel_function\n").unwrap();

        let adapter = SemanticKernelAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn extracts_semantic_kernel_tools() {
        let content = r#"
from semantic_kernel.functions import kernel_function

class DatabasePlugin:
    @kernel_function(name="query_db", description="Execute a database query")
    def execute_query(self, sql: str) -> str:
        """Run SQL query against data warehouse."""
        return db.query(sql)
"#;
        let tools = extract_semantic_kernel_tools_from_source(Path::new("plugin.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "query_db");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("Execute a database query")
        );
    }
}
