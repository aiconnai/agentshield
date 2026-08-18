use std::path::{Path, PathBuf};
use sha2::Digest;

use crate::analysis::AnalysisBundle;
use crate::analysis::composite_flow::{SourceUnit, ToolFlowInput, build_composite_flow_candidates};
use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{
    project_declared_description, project_declared_permissions, project_observed_execution,
};
use crate::ir::execution_surface::ExecutionSurface;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;
use crate::parser;

use super::binding::bind_mcp_tool_operations;
use super::dependencies::parse_dependencies;
use super::filter::is_test_file;
use super::provenance::parse_provenance;
use super::tools::{
    dedupe_tools_by_name, extract_mcp_tool_declarations_from_source, extract_mcp_tools_from_source,
};

pub(crate) struct ToolDeclForComposite {
    pub(crate) tool_name: String,
    pub(crate) handler_location: Option<SourceLocation>,
}

pub(crate) fn load_mcp_analysis(root: &Path, filter: &ScanPathFilter) -> Result<Vec<AnalysisBundle>> {
    let (target, composite_tools) = load_mcp_target(root, filter)?;

    let source_for_composite = target
        .source_files
        .iter()
        .filter_map(|source_file| match source_file.language {
            Language::TypeScript | Language::JavaScript => Some(SourceUnit {
                path: &source_file.path,
                content: &source_file.content,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut tool_flow_inputs = Vec::new();
    for tool in &composite_tools {
        let Some(location) = &tool.handler_location else {
            continue;
        };
        tool_flow_inputs.push(ToolFlowInput {
            tool_name: tool.tool_name.clone(),
            handler: location.clone(),
        });
    }

    let composite_flows = build_composite_flow_candidates(&tool_flow_inputs, &source_for_composite);

    Ok(vec![AnalysisBundle {
        target,
        composite_flows,
    }])
}

pub(crate) fn load_mcp_target(
    root: &Path,
    filter: &ScanPathFilter,
) -> Result<(ScanTarget, Vec<ToolDeclForComposite>)> {
    let metadata_root =
        crate::adapter::mcp_metadata::metadata_root_for_scan(root).unwrap_or_else(|| root.to_path_buf());
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "mcp-server".into());

    let mut source_files = Vec::new();
    let mut execution = ExecutionSurface::default();
    let mut tool_declarations = Vec::new();
    let mut python_tools = Vec::new();

    // Collect source files
    collect_source_files_with_filter(root, filter, &mut source_files)?;
    for source_file in &source_files {
        match source_file.language {
            Language::TypeScript | Language::JavaScript => {
                tool_declarations.extend(extract_mcp_tool_declarations_from_source(
                    &source_file.path,
                    &source_file.content,
                ));
            }
            Language::Python => {
                python_tools.extend(extract_mcp_tools_from_source(
                    &source_file.path,
                    &source_file.content,
                ));
            }
            _ => {}
        }
    }

    // Phase 1: Parse each source file, collecting results for cross-file analysis.
    let mut parsed_files: Vec<(PathBuf, parser::ParsedFile)> = Vec::new();
    for sf in &source_files {
        if let Some(parser) = parser::parser_for_language(sf.language) {
            if let Ok(parsed) = parser.parse_file(&sf.path, &sf.content) {
                parsed_files.push((sf.path.clone(), parsed));
            }
        }
    }

    // Phase 2: Cross-file sanitizer-aware analysis — downgrade operations
    // in functions that are only called with sanitized arguments.
    apply_cross_file_sanitization(&mut parsed_files);

    let operation_bindings = bind_mcp_tool_operations(&tool_declarations, &parsed_files);
    debug_assert_eq!(operation_bindings.len(), tool_declarations.len());
    debug_assert!(
        operation_bindings
            .iter()
            .all(super::binding::McpToolOperationBinding::is_consistent)
    );

    let mut tool_decls_for_composite = Vec::with_capacity(tool_declarations.len());
    let mut tools = python_tools;
    tools.reserve(tool_declarations.len());

    for (declaration, binding) in tool_declarations.into_iter().zip(operation_bindings) {
        let mut tool = declaration.tool;
        if binding.handler_resolved {
            project_observed_execution(&mut tool, &binding.execution);
        }
        tool.capability_observation_complete = binding.observation_complete;
        tool_decls_for_composite.push(ToolDeclForComposite {
            tool_name: tool.name.clone(),
            handler_location: binding.handler_location.clone(),
        });
        tools.push(tool);
    }

    // Phase 3: Merge parsed results into execution surface.
    for (_, mut parsed) in parsed_files {
        execution.commands.append(&mut parsed.commands);
        execution
            .file_operations
            .append(&mut parsed.file_operations);
        execution
            .network_operations
            .append(&mut parsed.network_operations);
        execution.env_accesses.append(&mut parsed.env_accesses);
        execution.dynamic_exec.append(&mut parsed.dynamic_exec);
    }

    // Parse tool definitions from JSON if available
    let tools_json = root.join("tools.json");
    if tools_json.exists() && filter.allows_path(root, &tools_json) {
        if let Some(content) = crate::adapter::read_file_capped(&tools_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                tools.extend(parser::json_schema::parse_tools_from_json(&value));
                tools = dedupe_tools_by_name(tools);
            }
        }
    }
    for tool in &mut tools {
        project_declared_permissions(tool);
        project_declared_description(tool);
    }

    let (dependencies, provenance) = if crate::adapter::mcp_metadata::same_path(root, &metadata_root) {
        (
            parse_dependencies(root, filter),
            parse_provenance(root, filter),
        )
    } else {
        (
            parse_dependencies(&metadata_root, filter),
            parse_provenance(&metadata_root, filter),
        )
    };

    let data = build_data_surface(&tools, &execution);

    let target = ScanTarget {
        name,
        framework: Framework::Mcp,
        root_path: metadata_root,
        tools,
        execution,
        data,
        dependencies,
        provenance,
        source_files,
    };

    Ok((target, tool_decls_for_composite))
}

pub(crate) fn has_recursive_python_import(root: &Path, needles: &[&str]) -> bool {
    let walker = ignore::WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("py") {
            continue;
        }

        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > 1_048_576 {
                continue;
            }
        }

        if let Ok(content) = std::fs::read_to_string(path) {
            if needles.iter().any(|needle| content.contains(needle)) {
                return true;
            }
        }
    }

    false
}

pub(crate) fn collect_source_files_with_filter(
    root: &Path,
    filter: &ScanPathFilter,
    files: &mut Vec<SourceFile>,
) -> Result<()> {
    let walker = ignore::WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .max_depth(Some(5))
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if filter.ignore_tests() && is_test_file(path) {
            continue;
        }

        if !filter.allows_path(root, path) {
            continue;
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let lang = Language::from_extension(&ext);

        if matches!(lang, Language::Unknown) {
            continue;
        }

        // Skip files larger than 1MB
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        if metadata.len() > 1_048_576 {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(path) {
            let hash = format!(
                "{:x}",
                sha2::Digest::finalize(sha2::Sha256::new().chain_update(content.as_bytes()))
            );
            files.push(SourceFile {
                path: path.to_path_buf(),
                language: lang,
                size_bytes: metadata.len(),
                content_hash: hash,
                content,
            });
        }
    }

    Ok(())
}
