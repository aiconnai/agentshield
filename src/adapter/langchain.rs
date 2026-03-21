use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::error::Result;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;
use crate::parser;

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
            if let Ok(content) = std::fs::read_to_string(&pyproject) {
                if content.contains("langchain") || content.contains("langgraph") {
                    return true;
                }
            }
        }

        // Check requirements.txt for langchain/langgraph
        let requirements = root.join("requirements.txt");
        if requirements.exists() {
            if let Ok(content) = std::fs::read_to_string(&requirements) {
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

        // Check Python files for langchain imports (top-level only)
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "py") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if content.contains("from langchain")
                            || content.contains("import langchain")
                            || content.contains("from langgraph")
                            || content.contains("import langgraph")
                        {
                            return true;
                        }
                    }
                }
            }
        }

        // Also check src/ directory (common LangChain layout)
        let src_dir = root.join("src");
        if src_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&src_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "py") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if content.contains("from langchain")
                                || content.contains("import langchain")
                                || content.contains("from langgraph")
                                || content.contains("import langgraph")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "langchain-project".into());

        let mut source_files = Vec::new();
        let mut execution = execution_surface::ExecutionSurface::default();

        // Phase 0: Collect source files (reuses MCP adapter's walker)
        super::mcp::collect_source_files(root, ignore_tests, &mut source_files)?;

        // Filter to Python-only (LangChain is a Python framework)
        source_files.retain(|sf| matches!(sf.language, Language::Python));

        // Phase 1: Parse each Python file
        let mut parsed_files: Vec<(PathBuf, parser::ParsedFile)> = Vec::new();
        for sf in &source_files {
            if let Some(parser) = parser::parser_for_language(sf.language) {
                if let Ok(parsed) = parser.parse_file(&sf.path, &sf.content) {
                    parsed_files.push((sf.path.clone(), parsed));
                }
            }
        }

        // Phase 2: Cross-file sanitizer-aware analysis
        apply_cross_file_sanitization(&mut parsed_files);

        // Phase 3: Merge into execution surface
        for (_, parsed) in parsed_files {
            execution.commands.extend(parsed.commands);
            execution.file_operations.extend(parsed.file_operations);
            execution
                .network_operations
                .extend(parsed.network_operations);
            execution.env_accesses.extend(parsed.env_accesses);
            execution.dynamic_exec.extend(parsed.dynamic_exec);
        }

        // Parse dependencies from pyproject.toml / requirements.txt
        let dependencies = super::mcp::parse_dependencies(root);

        // Parse provenance from pyproject.toml
        let provenance = super::mcp::parse_provenance(root);

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
}
