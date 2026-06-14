use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;
use crate::parser;

/// CrewAI framework adapter.
///
/// Detects CrewAI projects by looking for:
/// - `pyproject.toml` with `crewai` dependency or `[tool.crewai]` section
/// - `requirements.txt` containing `crewai`
/// - Python files importing `from crewai` or `from crewai_tools`
pub struct CrewAiAdapter;

impl super::Adapter for CrewAiAdapter {
    fn framework(&self) -> Framework {
        Framework::CrewAi
    }

    fn detect(&self, root: &Path) -> bool {
        // Check pyproject.toml for crewai dependency or [tool.crewai] section
        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() {
            if let Ok(content) = std::fs::read_to_string(&pyproject) {
                if content.contains("crewai") {
                    return true;
                }
            }
        }

        // Check requirements.txt for crewai
        let requirements = root.join("requirements.txt");
        if requirements.exists() {
            if let Ok(content) = std::fs::read_to_string(&requirements) {
                if content.lines().any(|l| {
                    let trimmed = l.trim();
                    trimmed == "crewai"
                        || trimmed.starts_with("crewai==")
                        || trimmed.starts_with("crewai>=")
                        || trimmed.starts_with("crewai[")
                        || trimmed == "crewai-tools"
                        || trimmed.starts_with("crewai-tools==")
                        || trimmed.starts_with("crewai-tools>=")
                }) {
                    return true;
                }
            }
        }

        // Check Python files for crewai imports (only top-level, not recursive)
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "py") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if content.contains("from crewai")
                            || content.contains("import crewai")
                            || content.contains("from crewai_tools")
                            || content.contains("import crewai_tools")
                        {
                            return true;
                        }
                    }
                }
            }
        }

        // Also check src/ directory for imports (common CrewAI layout)
        let src_dir = root.join("src");
        if src_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&src_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "py") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if content.contains("from crewai")
                                || content.contains("import crewai")
                                || content.contains("from crewai_tools")
                                || content.contains("import crewai_tools")
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
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "crewai-project".into());

        let mut source_files = Vec::new();
        let mut execution = execution_surface::ExecutionSurface::default();

        // Phase 0: Collect source files (reuses MCP adapter's walker)
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        // Filter to Python-only (CrewAI is a Python framework)
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
            framework: Framework::CrewAi,
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
    fn test_detect_crewai_via_pyproject() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crewai_project");
        let adapter = CrewAiAdapter;
        assert!(adapter.detect(&dir));
    }

    #[test]
    fn test_detect_non_crewai_project() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/safe_calculator");
        let adapter = CrewAiAdapter;
        assert!(!adapter.detect(&dir));
    }

    #[test]
    fn test_load_crewai_finds_cmd_injection() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crewai_project");
        let adapter = CrewAiAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        assert_eq!(targets.len(), 1);

        let target = &targets[0];
        assert_eq!(target.framework, Framework::CrewAi);
        assert_eq!(target.name, "crewai_project");

        // Should find command injection in vuln_tool.py
        assert!(
            !target.execution.commands.is_empty(),
            "expected command execution findings from vuln_tool.py"
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
    fn test_load_crewai_finds_ssrf() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crewai_project");
        let adapter = CrewAiAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // Should find network operations in fetch_tool.py
        assert!(
            !target.execution.network_operations.is_empty(),
            "expected network operation findings from fetch_tool.py"
        );
    }

    #[test]
    fn test_load_crewai_parses_dependencies() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crewai_project");
        let adapter = CrewAiAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        assert!(
            target
                .dependencies
                .dependencies
                .iter()
                .any(|d| d.name == "crewai"),
            "expected crewai in dependencies"
        );
    }

    #[test]
    fn test_load_crewai_only_python_files() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crewai_project");
        let adapter = CrewAiAdapter;
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
