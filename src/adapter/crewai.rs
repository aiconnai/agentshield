use std::path::Path;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

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
        if super::mcp::has_recursive_python_import(
            root,
            &[
                "from crewai",
                "import crewai",
                "from crewai_tools",
                "import crewai_tools",
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
            .unwrap_or_else(|| "crewai-project".into());

        let mut source_files = Vec::new();
        // Phase 0: Collect source files (reuses MCP adapter's walker)
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        // Filter to Python-only (CrewAI is a Python framework)
        source_files.retain(|sf| matches!(sf.language, Language::Python));

        let execution = super::pipeline::build_execution_surface(&source_files);

        // Parse dependencies from pyproject.toml / requirements.txt
        let dependencies = super::mcp::parse_dependencies(root, filter);

        // Parse provenance from pyproject.toml
        let provenance = super::mcp::parse_provenance(root, filter);

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
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

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

    #[test]
    fn test_detect_crewai_nested_python_import() {
        let tmp_root = TempDir::new().unwrap();
        let nested_dir = tmp_root.path().join("src/pkg");
        std::fs::create_dir_all(&nested_dir).unwrap();

        let mut file = std::fs::File::create(nested_dir.join("tool.py")).unwrap();
        writeln!(file, "from crewai_tools import BaseTool").unwrap();

        let adapter = CrewAiAdapter;
        assert!(adapter.detect(tmp_root.path()));
    }
}
