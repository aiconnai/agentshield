use std::path::Path;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

/// LangChain framework adapter.
///
/// Detects LangChain projects by looking for:
/// - `pyproject.toml` with `langchain` dependency
/// - `requirements.txt` containing `langchain` or `langgraph`
/// - `langgraph.json` configuration file
/// - Python files importing `from langchain` / `from langchain_core` / `from langgraph`
pub struct LangChainAdapter;

impl super::Adapter for LangChainAdapter {
    fn framework(&self) -> Framework {
        Framework::LangChain
    }

    fn detect(&self, root: &Path) -> bool {
        // Check pyproject.toml for langchain dependency
        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() {
            if let Some(content) = super::read_file_capped(&pyproject) {
                if content.contains("langchain") || content.contains("langgraph") {
                    return true;
                }
            }
        }

        // Check requirements.txt for langchain/langgraph
        let requirements = root.join("requirements.txt");
        if requirements.exists() {
            if let Some(content) = super::read_file_capped(&requirements) {
                if content.lines().any(|l| {
                    let trimmed = l.trim();
                    trimmed.starts_with("langchain") || trimmed.starts_with("langgraph")
                }) {
                    return true;
                }
            }
        }

        // Check for langgraph.json configuration file
        if root.join("langgraph.json").exists() {
            return true;
        }

        // Check package.json for @langchain dependencies
        let package_json = root.join("package.json");
        if package_json.exists() {
            if let Some(content) = super::read_file_capped(&package_json) {
                if content.contains("@langchain/")
                    || content.contains("\"langchain\"")
                    || content.contains("@langchain/core")
                {
                    return true;
                }
            }
        }

        if super::mcp::has_recursive_python_import(
            root,
            &[
                "from langchain",
                "import langchain",
                "from langgraph",
                "import langgraph",
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
            .unwrap_or_else(|| "langchain-project".into());

        let mut source_files = Vec::new();
        // Phase 0: Collect source files (reuses MCP adapter's walker)
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        // Retain Python and TypeScript/JavaScript source files for LangChain
        source_files.retain(|sf| {
            matches!(
                sf.language,
                Language::Python | Language::TypeScript | Language::JavaScript
            )
        });

        let execution = super::pipeline::build_execution_surface(&source_files);

        // Parse dependencies from pyproject.toml / requirements.txt / package.json
        let dependencies = super::mcp::parse_dependencies(root, filter);

        // Parse provenance from pyproject.toml / package.json
        let provenance = super::mcp::parse_provenance(root, filter);

        let tools = vec![];
        let data = build_data_surface(&tools, &execution);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::LangChain,
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
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_detect_langchain_via_pyproject() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/langchain_project");
        let adapter = LangChainAdapter;
        assert!(adapter.detect(&dir));
    }

    #[test]
    fn test_detect_langchain_via_langgraph_json() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/langchain_project");
        let adapter = LangChainAdapter;
        // The fixture has pyproject.toml, but langgraph.json also triggers detection
        assert!(adapter.detect(&dir));
    }

    #[test]
    fn test_detect_non_langchain_project() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/safe_calculator");
        let adapter = LangChainAdapter;
        assert!(!adapter.detect(&dir));
    }

    #[test]
    fn test_load_langchain_finds_cmd_injection() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/langchain_project");
        let adapter = LangChainAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        assert_eq!(targets.len(), 1);

        let target = &targets[0];
        assert_eq!(target.framework, Framework::LangChain);
        assert_eq!(target.name, "langchain_project");

        // Should find command injection in shell_tool.py
        assert!(
            !target.execution.commands.is_empty(),
            "expected command execution findings from shell_tool.py"
        );
        // Should find tainted command args
        assert!(
            target
                .execution
                .commands
                .iter()
                .any(|c| c.command_arg.is_tainted()),
            "expected tainted command source from subprocess.run with user input"
        );
    }

    #[test]
    fn test_load_langchain_finds_ssrf() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/langchain_project");
        let adapter = LangChainAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // Should find network operations in fetch_tool.py
        assert!(
            !target.execution.network_operations.is_empty(),
            "expected network operation findings from fetch_tool.py"
        );
    }

    #[test]
    fn test_load_langchain_only_python_files() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/langchain_project");
        let adapter = LangChainAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // All source files should be Python
        for sf in &target.source_files {
            assert_eq!(
                sf.language,
                Language::Python,
                "non-Python file found: {:?}",
                sf.path
            );
        }
    }

    #[test]
    fn test_detect_langchain_nested_python_import() {
        let tmp_root = TempDir::new().unwrap();
        let nested_dir = tmp_root.path().join("src/pkg");
        std::fs::create_dir_all(&nested_dir).unwrap();

        let mut file = std::fs::File::create(nested_dir.join("tool.py")).unwrap();
        writeln!(file, "from langchain_core import chat_models").unwrap();

        let adapter = LangChainAdapter;
        assert!(adapter.detect(tmp_root.path()));
    }
}
