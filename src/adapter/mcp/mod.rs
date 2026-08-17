pub(crate) mod binding;
pub(crate) mod dependencies;
pub(crate) mod provenance;
pub(crate) mod tools;

use std::path::{Path, PathBuf};

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

pub use dependencies::parse_dependencies;
pub use provenance::parse_provenance;

use binding::bind_mcp_tool_operations;
#[cfg(test)]
use tools::{McpToolHandler, parse_mcp_tool_handler};
use tools::{
    dedupe_tools_by_name, extract_mcp_tool_declarations_from_source, extract_mcp_tools_from_source,
};

/// MCP Server adapter.
///
/// Detects MCP servers by looking for:
/// - package.json with `@modelcontextprotocol/sdk` dependency
/// - Python files importing `mcp` or `mcp.server`
/// - mcp.json / mcp-config.json manifest
pub struct McpAdapter;

impl super::Adapter for McpAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        Ok(load_mcp_target(root, filter)
            .into_iter()
            .map(|(target, _)| target)
            .collect())
    }
}

impl super::AnalysisAdapter for McpAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>> {
        load_mcp_analysis(root, filter)
    }
}

pub(crate) struct McpAnalysisAdapter;

impl super::AnalysisAdapter for McpAnalysisAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>> {
        load_mcp_analysis(root, filter)
    }
}

fn load_mcp_analysis(root: &Path, filter: &ScanPathFilter) -> Result<Vec<AnalysisBundle>> {
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

fn load_mcp_target(
    root: &Path,
    filter: &ScanPathFilter,
) -> Result<(ScanTarget, Vec<ToolDeclForComposite>)> {
    let metadata_root =
        super::mcp_metadata::metadata_root_for_scan(root).unwrap_or_else(|| root.to_path_buf());
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
            .all(binding::McpToolOperationBinding::is_consistent)
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

    let (dependencies, provenance) = if super::mcp_metadata::same_path(root, &metadata_root) {
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

struct ToolDeclForComposite {
    tool_name: String,
    handler_location: Option<SourceLocation>,
}

/// Check if a file path belongs to a test file or test directory.
///
/// Matches common conventions across Python, TypeScript, and JavaScript:
/// - Directories: `test/`, `tests/`, `__tests__/`, `__pycache__/`
/// - Suffixes: `.test.{ts,js,tsx,jsx,py,sh}`, `.spec.{ts,js,tsx,jsx,py,sh}`
/// - Python conventions: `test_*.py`, `*_test.py`
/// - Config files: `conftest.py`, `jest.config.*`, `vitest.config.*`, `pytest.ini`, `setup.cfg`
pub fn is_test_file(path: &Path) -> bool {
    // Check if any path component is a test directory
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                "test" | "tests" | "__tests__" | "__pycache__"
            ) {
                return true;
            }
        }
    }

    let file_name = match path.file_name() {
        Some(n) => n.to_string_lossy(),
        None => return false,
    };
    let file_name = file_name.as_ref();

    // Test config files
    if matches!(file_name, "conftest.py" | "pytest.ini" | "setup.cfg")
        || file_name.starts_with("jest.config.")
        || file_name.starts_with("vitest.config.")
    {
        return true;
    }

    // pytest conventions: test_*.py and *_test.py
    if file_name.ends_with(".py")
        && (file_name.starts_with("test_") || file_name.ends_with("_test.py"))
    {
        return true;
    }

    // Suffix conventions: *.test.{ts,js,tsx,jsx,py,sh}, *.spec.{ts,js,tsx,jsx,py,sh}
    for suffix in [
        ".test.ts",
        ".test.js",
        ".test.tsx",
        ".test.jsx",
        ".test.py",
        ".test.sh",
        ".spec.ts",
        ".spec.js",
        ".spec.tsx",
        ".spec.jsx",
        ".spec.py",
        ".spec.sh",
    ] {
        if file_name.ends_with(suffix) {
            return true;
        }
    }

    false
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

pub(super) fn collect_source_files_with_filter(
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

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_detection_covers_shell_and_suffix_python_tests() {
        assert!(is_test_file(Path::new("scripts/check.test.sh")));
        assert!(is_test_file(Path::new("scripts/check.spec.sh")));
        assert!(is_test_file(Path::new("scripts/import_data_test.py")));
        assert!(is_test_file(Path::new("tests/unit.py")));
        assert!(!is_test_file(Path::new("scripts/load.py")));
    }

    #[test]
    fn extracts_typescript_mcp_server_tool_declarations() {
        let content = r#"
const server = new McpServer({ name: "demo" })

server.tool(
  'search_party',
  'Busca fuzzy por nome.',
  {},
  async () => ({ content: [] })
)

server.registerTool("create_report", { description: "Create report" }, async () => {})
"#;

        let tools =
            extract_mcp_tool_declarations_from_source(Path::new("src/mcp/server.ts"), content)
                .into_iter()
                .map(|declaration| declaration.tool)
                .collect::<Vec<_>>();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "search_party");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("Busca fuzzy por nome.")
        );
        assert_eq!(tools[0].defined_at.as_ref().map(|loc| loc.line), Some(5));
        assert_eq!(tools[1].name, "create_report");
        assert_eq!(tools[1].description.as_deref(), Some("Create report"));
    }

    #[test]
    fn extracts_config_description_and_inline_handler_binding() {
        let content = r#"
server.registerTool(
  "create_report",
  {
    description: "Create a local report",
    inputSchema: { path: { type: "string", description: "Output path" } },
  },
  async ({ path }) => {
    await writeFile(path, "report");
  },
)
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].tool.name, "create_report");
        assert_eq!(
            declarations[0].tool.description.as_deref(),
            Some("Create a local report")
        );
        assert!(matches!(
            declarations[0].handler,
            Some(McpToolHandler::Inline { .. })
        ));
    }

    #[test]
    fn extracts_named_handler_binding_without_using_nested_descriptions() {
        let content = r#"
server.registerTool(
  "fetch_report",
  {
    inputSchema: { url: { type: "string", description: "Remote URL" } },
    description: "Fetch a report from a URL",
  },
  fetchReport,
)
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(
            declarations[0].tool.description.as_deref(),
            Some("Fetch a report from a URL")
        );
        assert!(matches!(
            declarations[0].handler,
            Some(McpToolHandler::Named { ref symbol }) if symbol == "fetchReport"
        ));
    }

    #[test]
    fn extracts_tool_callback_after_description_and_schema_arguments() {
        let content = r#"
server.tool(
  "read_file",
  "Read a local file",
  { path: z.string() },
  handleReadFile,
)
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(
            declarations[0].tool.description.as_deref(),
            Some("Read a local file")
        );
        assert!(matches!(
            declarations[0].handler,
            Some(McpToolHandler::Named { ref symbol }) if symbol == "handleReadFile"
        ));
    }

    #[test]
    fn duplicate_tool_prefers_declaration_with_handler_binding() {
        let content = r#"
server.registerTool("report", { description: "Incomplete declaration" })
server.registerTool(
  "report",
  { description: "Bound declaration" },
  async () => ({ content: [] }),
)
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(
            declarations[0].tool.description.as_deref(),
            Some("Bound declaration")
        );
        assert!(matches!(
            declarations[0].handler,
            Some(McpToolHandler::Inline { .. })
        ));
    }

    #[test]
    fn schema_arrow_function_is_not_misclassified_as_handler() {
        let content = r#"
server.tool(
  "read_file",
  "Read a local file",
  { path: z.string().transform(value => value.trim()) },
)
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].handler, None);
    }

    #[test]
    fn arrow_text_in_config_description_is_not_misclassified_as_handler() {
        let content = r#"
server.registerTool("map_value", {
  description: "Maps a => b",
  inputSchema: { value: { type: "string" } },
})
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(
            declarations[0].tool.description.as_deref(),
            Some("Maps a => b")
        );
        assert_eq!(declarations[0].handler, None);
    }

    #[test]
    fn reserved_literals_are_not_named_handlers() {
        for candidate in ["async", "true", "false", "null", "undefined", "this"] {
            assert_eq!(
                parse_mcp_tool_handler(Path::new("src/server.ts"), candidate, 0, candidate.len()),
                None,
                "{candidate} must not be classified as a named handler"
            );
        }
    }

    #[test]
    fn handler_names_with_function_prefix_remain_named() {
        let candidate = "functionHandler";
        assert!(matches!(
            parse_mcp_tool_handler(Path::new("src/server.ts"), candidate, 0, candidate.len()),
            Some(McpToolHandler::Named { ref symbol }) if symbol == candidate
        ));

        let inline = "async() => ({ content: [] })";
        assert!(matches!(
            parse_mcp_tool_handler(Path::new("src/server.ts"), inline, 0, inline.len()),
            Some(McpToolHandler::Inline { .. })
        ));
    }

    #[test]
    fn ignores_tool_calls_inside_comments_and_strings() {
        let content = r#"
// server.tool("commented", "Nope", async () => {})
const docs = 'call server.registerTool("string", {}, handler)'
/* server.registerTool("blocked", {}, handler) */
server.registerTool("real", { description: "Real tool" }, handlers.run)
"#;

        let declarations =
            extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].tool.name, "real");
        assert!(matches!(
            declarations[0].handler,
            Some(McpToolHandler::Named { ref symbol }) if symbol == "handlers.run"
        ));
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn binds_named_handlers_without_cross_tool_operation_leakage() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool("read_file", { description: "Read a file" }, handleRead)
server.registerTool("fetch_url", { description: "Fetch a URL" }, handleFetch)

async function handleRead(path: string) {
  return readFile(path)
}

async function handleFetch(url: string) {
  return fetch(url)
}
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 2);
        assert!(bindings[0].handler_resolved);
        assert!(bindings[0].observation_complete);
        assert_eq!(bindings[0].execution.file_operations.len(), 1);
        assert!(bindings[0].execution.network_operations.is_empty());
        assert!(bindings[1].handler_resolved);
        assert!(bindings[1].observation_complete);
        assert!(bindings[1].execution.file_operations.is_empty());
        assert_eq!(bindings[1].execution.network_operations.len(), 1);
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn binds_inline_handler_and_one_hop_in_project_callee() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool(
  "fetch_report",
  { description: "Fetch a report" },
  async (url: string) => {
    await writeFile("audit.log", "started")
    return fetchThroughClient(url)
  },
)

async function fetchThroughClient(url: string) {
  return fetch(url)
}
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].handler_resolved);
        assert!(bindings[0].observation_complete);
        assert_eq!(bindings[0].resolved_callees, vec!["fetchThroughClient"]);
        assert_eq!(bindings[0].execution.file_operations.len(), 1);
        assert_eq!(bindings[0].execution.network_operations.len(), 1);
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn operation_binding_stops_after_one_callee_hop() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool("report", { description: "Build report" }, handleReport)

async function handleReport() {
  return firstHop()
}

async function firstHop() {
  return secondHop()
}

async function secondHop() {
  return fetch("https://example.com")
}
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].handler_resolved);
        assert!(!bindings[0].observation_complete);
        assert_eq!(bindings[0].resolved_callees, vec!["firstHop"]);
        assert!(
            bindings[0].execution.network_operations.is_empty(),
            "depth-2 operations must not be attributed to the tool"
        );
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn opaque_call_keeps_operation_observation_incomplete() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool("report", { description: "Fetch URLs" }, handleReport)

async function handleReport(url: string) {
  return externalClient(url)
}
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].handler_resolved);
        assert!(!bindings[0].observation_complete);
        assert!(bindings[0].execution.network_operations.is_empty());
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn dynamic_execution_keeps_operation_observation_incomplete() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool("evaluate", { description: "Evaluate arbitrary code" }, handleEval)
function handleEval(code: string) { return eval(code) }
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].handler_resolved);
        assert!(!bindings[0].observation_complete);
        assert_eq!(bindings[0].execution.dynamic_exec.len(), 1);
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn uncalled_nested_function_operations_are_not_attributed_to_handler() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool("report", { description: "Build report" }, handleReport)

async function handleReport() {
  async function unusedNetworkHelper() {
    return fetch("https://example.com")
  }
  return "local report"
}
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].handler_resolved);
        assert!(bindings[0].observation_complete);
        assert!(bindings[0].resolved_callees.is_empty());
        assert!(
            bindings[0].execution.network_operations.is_empty(),
            "an uncalled nested function is not part of handler execution"
        );
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn ambiguous_named_handler_stays_unresolved() {
        use crate::parser::LanguageParser;

        let registration_path = Path::new("src/server.ts");
        let registration =
            r#"server.registerTool("report", { description: "Report" }, handleReport)"#;
        let first_path = Path::new("src/first.ts");
        let first = "function handleReport() { return readFile('report.txt') }";
        let second_path = Path::new("src/second.ts");
        let second = "function handleReport() { return fetch('https://example.com') }";

        let declarations =
            extract_mcp_tool_declarations_from_source(registration_path, registration);
        let parsed_files = vec![
            (
                first_path.to_path_buf(),
                parser::typescript::TypeScriptParser
                    .parse_file(first_path, first)
                    .unwrap(),
            ),
            (
                second_path.to_path_buf(),
                parser::typescript::TypeScriptParser
                    .parse_file(second_path, second)
                    .unwrap(),
            ),
        ];

        let bindings = bind_mcp_tool_operations(&declarations, &parsed_files);

        assert_eq!(bindings.len(), 1);
        assert!(!bindings[0].handler_resolved);
        assert!(!bindings[0].observation_complete);
        assert!(bindings[0].execution.file_operations.is_empty());
        assert!(bindings[0].execution.network_operations.is_empty());
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn resolves_named_handler_across_source_files() {
        use crate::parser::LanguageParser;

        let registration_path = Path::new("src/server.ts");
        let registration =
            r#"server.registerTool("report", { description: "Report" }, handleReport)"#;
        let handler_path = Path::new("src/handlers.ts");
        let handler = "function handleReport() { return readFile('report.txt') }";

        let declarations =
            extract_mcp_tool_declarations_from_source(registration_path, registration);
        let parsed_files = vec![(
            handler_path.to_path_buf(),
            parser::typescript::TypeScriptParser
                .parse_file(handler_path, handler)
                .unwrap(),
        )];

        let bindings = bind_mcp_tool_operations(&declarations, &parsed_files);

        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].handler_resolved);
        assert!(bindings[0].observation_complete);
        assert_eq!(bindings[0].execution.file_operations.len(), 1);
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn dotted_named_handler_stays_unresolved_without_member_resolution() {
        use crate::parser::LanguageParser;

        let path = Path::new("src/server.ts");
        let content = r#"
server.registerTool("report", { description: "Report" }, handlers.run)
function run() { return readFile("report.txt") }
"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);
        let parsed = parser::typescript::TypeScriptParser
            .parse_file(path, content)
            .unwrap();

        let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

        assert_eq!(bindings.len(), 1);
        assert!(!bindings[0].handler_resolved);
        assert!(!bindings[0].observation_complete);
        assert!(bindings[0].execution.file_operations.is_empty());
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn adapter_load_projects_per_tool_observed_capabilities() {
        use crate::adapter::Adapter;

        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("read_file", { description: "Read a file" }, handleRead)
server.registerTool("fetch_url", { description: "Fetch a URL" }, handleFetch)

function handleRead(path: string) { return readFile(path) }
function handleFetch(url: string) { return fetch(url) }
"#,
        )
        .unwrap();

        let target = McpAdapter.load(fixture.path(), false).unwrap().remove(0);
        let read = target
            .tools
            .iter()
            .find(|tool| tool.name == "read_file")
            .unwrap();
        let fetch = target
            .tools
            .iter()
            .find(|tool| tool.name == "fetch_url")
            .unwrap();

        assert_eq!(
            read.observed_capabilities,
            std::collections::BTreeSet::from([Capability::FsRead])
        );
        assert!(
            read.capability_evidence
                .iter()
                .all(|evidence| evidence.capability == Capability::FsRead)
        );
        assert_eq!(
            fetch.observed_capabilities,
            std::collections::BTreeSet::from([Capability::NetworkEgress])
        );
        assert!(read.capability_observation_complete);
        assert!(fetch.capability_observation_complete);
    }

    #[cfg(not(feature = "typescript"))]
    #[test]
    fn adapter_load_without_typescript_keeps_observed_capabilities_empty() {
        use crate::adapter::Adapter;

        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("server.ts"),
            r#"
server.registerTool("fetch_url", { description: "Fetch a URL" }, handleFetch)
function handleFetch(url: string) { return fetch(url) }
"#,
        )
        .unwrap();

        let target = McpAdapter.load(fixture.path(), false).unwrap().remove(0);
        let tool = target
            .tools
            .iter()
            .find(|tool| tool.name == "fetch_url")
            .unwrap();

        assert!(tool.observed_capabilities.is_empty());
        assert!(tool.capability_evidence.is_empty());
        assert!(!tool.capability_observation_complete);
    }

    #[test]
    fn adapter_load_projects_permissions_but_not_input_schema() {
        use crate::adapter::Adapter;

        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("tools.json"),
            r#"{
  "tools": [
    {
      "name": "fetch_url",
      "description": "Fetch URLs",
      "inputSchema": {"properties": {"url": {"type": "string"}}}
    },
    {
      "name": "schema_only",
      "inputSchema": {"properties": {"url": {"type": "string"}}}
    }
  ]
}"#,
        )
        .unwrap();

        let target = McpAdapter.load(fixture.path(), false).unwrap().remove(0);
        let fetch = target
            .tools
            .iter()
            .find(|tool| tool.name == "fetch_url")
            .unwrap();
        let schema_only = target
            .tools
            .iter()
            .find(|tool| tool.name == "schema_only")
            .unwrap();

        assert_eq!(
            fetch.declared_capabilities,
            std::collections::BTreeSet::from([Capability::NetworkEgress])
        );
        assert_eq!(
            fetch
                .capability_declarations
                .iter()
                .filter(|declaration| {
                    declaration.source == CapabilityDeclarationSource::Description
                })
                .count(),
            1
        );
        assert_eq!(
            fetch
                .capability_declarations
                .iter()
                .filter(|declaration| {
                    declaration.source == CapabilityDeclarationSource::Permission
                })
                .count(),
            1
        );
        assert!(schema_only.declared_capabilities.is_empty());
        assert!(schema_only.capability_declarations.is_empty());
    }

    #[cfg(not(feature = "typescript"))]
    #[test]
    fn no_typescript_feature_keeps_operation_binding_unresolved() {
        let path = Path::new("src/server.ts");
        let content = r#"server.registerTool("fetch", { description: "Fetch" }, handleFetch)"#;
        let declarations = extract_mcp_tool_declarations_from_source(path, content);

        let bindings = bind_mcp_tool_operations(&declarations, &[]);

        assert_eq!(bindings.len(), 1);
        assert!(!bindings[0].handler_resolved);
        assert!(bindings[0].execution.network_operations.is_empty());
        assert!(bindings[0].resolved_callees.is_empty());
    }

    #[test]
    fn extracts_python_mcp_tool_decorators() {
        let content = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool(name="search", description="Search web")
async def search(query: str):
    return []

@mcp.tool()
def status():
    return {}
"#;

        let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.py"), content);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "search");
        assert_eq!(tools[0].description.as_deref(), Some("Search web"));
        assert_eq!(tools[1].name, "status");
    }

    #[test]
    fn extracts_python_mcp_tool_call_syntax() {
        let content = r#"
server = FastMCP("demo")

server.tool("echo", "Run echo command")
"#;

        let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description.as_deref(), Some("Run echo command"));
    }

    #[test]
    fn extracts_python_bare_mcp_tool_decorators() {
        let content = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool
def calculate(expr: str):
    return eval(expr)
"#;

        let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "calculate");
    }
}
