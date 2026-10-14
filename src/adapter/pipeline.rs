use std::collections::BTreeSet;
use std::path::Path;

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{project_declared_description, project_declared_permissions};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::{
    Framework, Language, ScanTarget, SourceFile, SourceLocation, ToolSurface,
    execution_surface::ExecutionSurface,
};
use crate::parser;

pub(super) type ToolExtractor = fn(&Path, &str) -> Vec<ToolSurface>;

pub(super) fn detect_python_framework(
    root: &Path,
    pyproject_needles: &[&str],
    req_matcher: fn(&str) -> bool,
    import_needles: &[&str],
) -> bool {
    let pyproject = root.join("pyproject.toml");
    if pyproject.exists() {
        if let Some(content) = super::read_file_capped(&pyproject) {
            if pyproject_needles
                .iter()
                .any(|needle| content.contains(needle))
            {
                return true;
            }
        }
    }

    let requirements = root.join("requirements.txt");
    if requirements.exists() {
        if let Some(content) = super::read_file_capped(&requirements) {
            if content.lines().any(|line| req_matcher(line.trim())) {
                return true;
            }
        }
    }

    super::mcp::has_recursive_python_import(root, import_needles)
}

pub(super) fn build_extracted_tool(
    name: String,
    description: Option<String>,
    path: &Path,
    line: usize,
) -> ToolSurface {
    ToolSurface {
        name,
        description,
        input_schema: None,
        output_schema: None,
        declared_permissions: Vec::new(),
        declared_capabilities: BTreeSet::new(),
        capability_declarations: Vec::new(),
        observed_capabilities: BTreeSet::new(),
        capability_evidence: Vec::new(),
        capability_observation_complete: false,
        defined_at: Some(SourceLocation {
            file: path.to_path_buf(),
            line,
            column: 0,
            end_line: Some(line),
            end_column: None,
        }),
    }
}

pub(super) fn load_framework_target(
    root: &Path,
    filter: &ScanPathFilter,
    framework: Framework,
    default_name: &str,
    keep_lang: fn(Language) -> bool,
    extractor: Option<ToolExtractor>,
) -> Result<Vec<ScanTarget>> {
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| default_name.into());

    let mut source_files = Vec::new();
    super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;
    source_files.retain(|sf| keep_lang(sf.language));

    let mut tools = Vec::new();
    if let Some(extract_fn) = extractor {
        for sf in &source_files {
            tools.extend(extract_fn(&sf.path, &sf.content));
        }
        for tool in &mut tools {
            project_declared_permissions(tool);
            project_declared_description(tool);
        }
    }

    let execution = build_execution_surface(&source_files);
    let data = build_data_surface(&tools, &execution);
    let dependencies = super::mcp::parse_dependencies(root, filter);
    let provenance = super::mcp::parse_provenance(root, filter);

    Ok(vec![ScanTarget {
        name,
        framework,
        root_path: root.to_path_buf(),
        tools,
        execution,
        data,
        dependencies,
        provenance,
        source_files,
    }])
}

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

        assert!(
            execution
                .commands
                .iter()
                .any(|command| command.command_arg.is_tainted())
        );
        assert!(!execution.network_operations.is_empty());
    }

    #[test]
    fn langchain_fixture_preserves_execution_findings() {
        let execution = fixture_execution("langchain_project");

        assert!(
            execution
                .commands
                .iter()
                .any(|command| command.command_arg.is_tainted())
        );
        assert!(!execution.network_operations.is_empty());
    }
}
