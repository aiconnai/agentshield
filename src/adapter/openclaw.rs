use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::error::Result;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;
use crate::parser;

/// OpenClaw Skills adapter.
///
/// Detects by presence of `SKILL.md` file.
pub struct OpenClawAdapter;

impl super::Adapter for OpenClawAdapter {
    fn framework(&self) -> Framework {
        Framework::OpenClaw
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("SKILL.md").exists()
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "openclaw-skill".into());

        let mut source_files = Vec::new();
        let mut execution = execution_surface::ExecutionSurface::default();

        // Collect source files (Python and Shell scripts)
        let walker = ignore::WalkBuilder::new(root)
            .hidden(true)
            .git_ignore(true)
            .max_depth(Some(3))
            .build();

        for entry in walker.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if ignore_tests && super::mcp::is_test_file(path) {
                continue;
            }

            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default();
            let lang = Language::from_extension(&ext);

            if !matches!(
                lang,
                Language::Python | Language::Shell | Language::Markdown
            ) {
                continue;
            }

            let metadata = std::fs::metadata(path)?;
            if metadata.len() > 1_048_576 {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(path) {
                use sha2::Digest;
                let hash = format!(
                    "{:x}",
                    sha2::Sha256::new()
                        .chain_update(content.as_bytes())
                        .finalize()
                );
                source_files.push(SourceFile {
                    path: path.to_path_buf(),
                    language: lang,
                    size_bytes: metadata.len(),
                    content_hash: hash,
                    content,
                });
            }
        }

        // Phase 1: Parse source files
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

        let tools = vec![];
        let data = build_data_surface(&tools, &execution);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::OpenClaw,
            root_path: root.to_path_buf(),
            tools,
            execution,
            data,
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files,
        }])
    }
}
