use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{project_declared_description, project_declared_permissions};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

static LLAMA_FUNCTION_TOOL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)FunctionTool\.from_defaults\s*\(\s*(?:fn\s*=\s*)?(\w+)(?:[^\)]*?name\s*=\s*["'`]([^"'`]+)["'`])?(?:[^\)]*?description\s*=\s*["'`]([^"'`]+)["'`])?"#)
        .expect("static regex pattern is valid")
});

static LLAMA_TOOL_METADATA_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)ToolMetadata\s*\(\s*(?:name\s*=\s*["'`]([^"'`]+)["'`])?[^\)]*?description\s*=\s*["'`]([^"'`]+)["'`]"#)
        .expect("static regex pattern is valid")
});

static LLAMA_DEF_DOC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->[^:]+)?:\s*\n\s*["'`]([\s\S]*?)["'`]"#)
        .expect("static regex pattern is valid")
});

/// LlamaIndex framework adapter (`llama-index` and `llama-index-core`).
///
/// Detects LlamaIndex projects by looking for:
/// - `pyproject.toml` / `requirements.txt` with `llama-index` or `llama_index`
/// - Python files importing `from llama_index` or `import llama_index`
pub struct LlamaIndexAdapter;

impl super::Adapter for LlamaIndexAdapter {
    fn framework(&self) -> Framework {
        Framework::LlamaIndex
    }

    fn detect(&self, root: &Path) -> bool {
        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() {
            if let Some(content) = super::read_file_capped(&pyproject) {
                if content.contains("llama-index") || content.contains("llama_index") {
                    return true;
                }
            }
        }

        let requirements = root.join("requirements.txt");
        if requirements.exists() {
            if let Some(content) = super::read_file_capped(&requirements) {
                if content.lines().any(|l| {
                    let trimmed = l.trim();
                    trimmed.starts_with("llama-index")
                        || trimmed.starts_with("llama_index")
                        || trimmed.starts_with("llama-index-core")
                }) {
                    return true;
                }
            }
        }

        if super::mcp::has_recursive_python_import(
            root,
            &[
                "from llama_index",
                "import llama_index",
                "from llama_index.core",
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
            .unwrap_or_else(|| "llama-index-project".into());

        let mut source_files = Vec::new();
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        source_files.retain(|sf| sf.language == Language::Python);

        let mut tools = Vec::new();
        for sf in &source_files {
            tools.extend(extract_llama_index_tools_from_source(&sf.path, &sf.content));
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
            framework: Framework::LlamaIndex,
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

pub(crate) fn extract_llama_index_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = Vec::new();
    let mut doc_map = std::collections::HashMap::new();

    for cap in LLAMA_DEF_DOC_RE.captures_iter(content) {
        let func_name = cap[1].to_string();
        let doc = cap[2].trim().to_string();
        doc_map.insert(func_name, doc);
    }

    for cap in LLAMA_FUNCTION_TOOL_RE.captures_iter(content) {
        let fn_ident = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let explicit_name = cap.get(2).map(|m| m.as_str().to_string());
        let tool_name = explicit_name.unwrap_or_else(|| fn_ident.clone());

        if tool_name.is_empty() {
            continue;
        }

        let explicit_desc = cap.get(3).map(|m| m.as_str().to_string());
        let description = explicit_desc.or_else(|| doc_map.get(&fn_ident).cloned());

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

    for cap in LLAMA_TOOL_METADATA_RE.captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| "query_tool".into());
        let description = cap.get(2).map(|m| m.as_str().to_string());

        let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line = content[..match_start].lines().count() + 1;

        tools.push(ToolSurface {
            name,
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
    fn detects_llama_index_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, "llama-index-core>=0.10.0\n").unwrap();

        let adapter = LlamaIndexAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detects_llama_index_import() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("rag.py");
        std::fs::write(&src, "from llama_index.core.tools import FunctionTool\n").unwrap();

        let adapter = LlamaIndexAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn extracts_llama_index_function_tool() {
        let content = r#"
from llama_index.core.tools import FunctionTool

def fetch_document(doc_id: str) -> str:
    """Fetch a document from the filesystem."""
    with open(f"/data/{doc_id}") as f:
        return f.read()

doc_tool = FunctionTool.from_defaults(
    fn=fetch_document,
    name="doc_fetcher",
    description="Fetch document content by ID"
)
"#;
        let tools = extract_llama_index_tools_from_source(Path::new("rag.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "doc_fetcher");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("Fetch document content by ID")
        );
    }
}
