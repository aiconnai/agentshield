use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::ir::{execution_surface::ExecutionSurface, SourceFile};
use crate::parser;

pub(super) fn build_execution_surface(source_files: &[SourceFile]) -> ExecutionSurface {
    let mut parsed_files = source_files
        .iter()
        .filter_map(|source| {
            parser::parser_for_language(source.language).and_then(|parser| {
                parser
                    .parse_file(&source.path, &source.content)
                    .ok()
                    .map(|parsed| (source.path.clone(), parsed))
            })
        })
        .collect::<Vec<_>>();

    apply_cross_file_sanitization(&mut parsed_files);

    let mut execution = ExecutionSurface::default();
    for (_, parsed) in parsed_files {
        execution.commands.extend(parsed.commands);
        execution.file_operations.extend(parsed.file_operations);
        execution
            .network_operations
            .extend(parsed.network_operations);
        execution.env_accesses.extend(parsed.env_accesses);
        execution.dynamic_exec.extend(parsed.dynamic_exec);
    }

    execution
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::ScanPathFilter;
    use crate::ir::Language;

    fn fixture_execution(fixture: &str) -> crate::ir::execution_surface::ExecutionSurface {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture);
        let mut source_files = Vec::new();
        super::super::mcp::collect_source_files_with_filter(
            &root,
            &ScanPathFilter::for_ignore_tests(false),
            &mut source_files,
        )
        .unwrap();
        source_files.retain(|source| source.language == Language::Python);

        super::build_execution_surface(&source_files)
    }

    #[test]
    fn crewai_fixture_preserves_execution_findings() {
        let execution = fixture_execution("crewai_project");

        assert!(execution
            .commands
            .iter()
            .any(|command| command.command_arg.is_tainted()));
        assert!(!execution.network_operations.is_empty());
    }

    #[test]
    fn langchain_fixture_preserves_execution_findings() {
        let execution = fixture_execution("langchain_project");

        assert!(execution
            .commands
            .iter()
            .any(|command| command.command_arg.is_tainted()));
        assert!(!execution.network_operations.is_empty());
    }
}
