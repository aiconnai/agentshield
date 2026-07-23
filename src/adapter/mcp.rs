use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{project_declared_permissions, project_observed_execution};
use crate::ir::execution_surface::ExecutionSurface;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;
use crate::parser;

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
        let metadata_root =
            super::mcp_metadata::metadata_root_for_scan(root).unwrap_or_else(|| root.to_path_buf());
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "mcp-server".into());

        let mut source_files = Vec::new();
        let mut execution = ExecutionSurface::default();
        let mut tool_declarations = Vec::new();

        // Collect source files
        collect_source_files_with_filter(root, filter, &mut source_files)?;
        for source_file in &source_files {
            if matches!(
                source_file.language,
                Language::TypeScript | Language::JavaScript
            ) {
                tool_declarations.extend(extract_mcp_tool_declarations_from_source(
                    &source_file.path,
                    &source_file.content,
                ));
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
        debug_assert!(operation_bindings
            .iter()
            .all(McpToolOperationBinding::is_consistent));
        let mut tools = tool_declarations
            .into_iter()
            .zip(operation_bindings)
            .map(|(declaration, binding)| {
                let mut tool = declaration.tool;
                if binding.handler_resolved {
                    project_observed_execution(&mut tool, &binding.execution);
                }
                // Positive evidence is usable for stealth detection, but B.0.1
                // does not prove observation completeness for overclaim.
                tool.capability_observation_complete = false;
                tool
            })
            .collect::<Vec<_>>();

        // Phase 3: Merge parsed results into execution surface.
        for (_, parsed) in parsed_files {
            execution.commands.extend(parsed.commands);
            execution.file_operations.extend(parsed.file_operations);
            execution
                .network_operations
                .extend(parsed.network_operations);
            execution.env_accesses.extend(parsed.env_accesses);
            execution.dynamic_exec.extend(parsed.dynamic_exec);
        }

        // Parse tool definitions from JSON if available
        let tools_json = root.join("tools.json");
        if tools_json.exists() && filter.allows_path(root, &tools_json) {
            if let Ok(content) = std::fs::read_to_string(&tools_json) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                    tools.extend(parser::json_schema::parse_tools_from_json(&value));
                    tools = dedupe_tools_by_name(tools);
                }
            }
        }
        for tool in &mut tools {
            project_declared_permissions(tool);
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

        Ok(vec![ScanTarget {
            name,
            framework: Framework::Mcp,
            root_path: metadata_root,
            tools,
            execution,
            data,
            dependencies,
            provenance,
            source_files,
        }])
    }
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

#[derive(Debug, Clone)]
struct McpToolDeclaration {
    tool: ToolSurface,
    handler: Option<McpToolHandler>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum McpToolHandler {
    Named { symbol: String },
    Inline { location: SourceLocation },
}

#[derive(Debug, Clone)]
struct McpToolOperationBinding {
    execution: ExecutionSurface,
    handler_resolved: bool,
    resolved_callees: Vec<String>,
}

impl McpToolOperationBinding {
    fn is_consistent(&self) -> bool {
        self.handler_resolved
            || (self.execution.commands.is_empty()
                && self.execution.file_operations.is_empty()
                && self.execution.network_operations.is_empty()
                && self.execution.env_accesses.is_empty()
                && self.execution.dynamic_exec.is_empty()
                && self.resolved_callees.is_empty())
    }
}

#[cfg(feature = "typescript")]
struct ResolvedMcpHandler {
    span: SourceLocation,
    caller: Option<String>,
}

fn extract_mcp_tool_declarations_from_source(
    path: &Path,
    content: &str,
) -> Vec<McpToolDeclaration> {
    let mut declarations = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = find_next_mcp_tool_call(&content[offset..]) {
        let call_start = offset + relative_start;
        let Some(open_paren) = content[call_start..].find('(').map(|pos| call_start + pos) else {
            break;
        };
        let Some(close_paren) = find_matching_delimiter(content, open_paren, b'(', b')') else {
            break;
        };
        let arguments = top_level_segments(content, open_paren + 1, close_paren);
        let Some(&(name_start, _)) = arguments.first() else {
            offset = close_paren + 1;
            continue;
        };
        let Some((name, _)) = parse_string_literal_at(content, name_start) else {
            offset = close_paren + 1;
            continue;
        };
        let description = arguments.get(1).and_then(|&(start, end)| {
            parse_string_literal_at(content, start)
                .filter(|(_, after)| *after <= end)
                .map(|(value, _)| value)
                .or_else(|| parse_object_string_property(content, start, end, "description"))
        });
        let handler = arguments
            .last()
            .and_then(|&(start, end)| parse_mcp_tool_handler(path, content, start, end));
        let line = content[..call_start].lines().count() + 1;

        declarations.push(McpToolDeclaration {
            tool: ToolSurface {
                name,
                description,
                input_schema: None,
                output_schema: None,
                declared_permissions: Vec::new(),
                defined_at: Some(source_loc(path, line)),
                declared_capabilities: Default::default(),
                capability_declarations: Vec::new(),
                observed_capabilities: Default::default(),
                capability_observation_complete: false,
                capability_evidence: Vec::new(),
            },
            handler,
        });

        offset = close_paren + 1;
    }

    dedupe_mcp_tool_declarations(declarations)
}

#[cfg(feature = "typescript")]
fn bind_mcp_tool_operations(
    declarations: &[McpToolDeclaration],
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Vec<McpToolOperationBinding> {
    declarations
        .iter()
        .map(|declaration| {
            let Some(handler) = resolve_handler(declaration, parsed_files) else {
                return McpToolOperationBinding {
                    execution: ExecutionSurface::default(),
                    handler_resolved: false,
                    resolved_callees: Vec::new(),
                };
            };

            let mut resolved_callees = call_sites_for_handler(parsed_files, &handler)
                .filter_map(|call_site| {
                    resolve_unique_function_span(&call_site.callee, parsed_files)
                        .map(|span| (call_site.callee.clone(), span))
                })
                .collect::<Vec<_>>();
            resolved_callees.sort_by(|left, right| left.0.cmp(&right.0));
            resolved_callees.dedup_by(|left, right| left.0 == right.0);

            let mut scopes = Vec::with_capacity(resolved_callees.len() + 1);
            scopes.push((handler.span, handler.caller));
            scopes.extend(
                resolved_callees
                    .iter()
                    .map(|(name, span)| (span.clone(), Some(name.clone()))),
            );

            McpToolOperationBinding {
                execution: execution_within_scopes(parsed_files, &scopes),
                handler_resolved: true,
                resolved_callees: resolved_callees.into_iter().map(|(name, _)| name).collect(),
            }
        })
        .collect()
}

#[cfg(not(feature = "typescript"))]
fn bind_mcp_tool_operations(
    declarations: &[McpToolDeclaration],
    _parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Vec<McpToolOperationBinding> {
    declarations
        .iter()
        .map(|_| McpToolOperationBinding {
            execution: ExecutionSurface::default(),
            handler_resolved: false,
            resolved_callees: Vec::new(),
        })
        .collect()
}

#[cfg(feature = "typescript")]
fn resolve_handler(
    declaration: &McpToolDeclaration,
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Option<ResolvedMcpHandler> {
    match declaration.handler.as_ref()? {
        McpToolHandler::Inline { location } => parsed_files
            .iter()
            .any(|(path, _)| path == &location.file)
            .then(|| ResolvedMcpHandler {
                span: location.clone(),
                caller: None,
            }),
        McpToolHandler::Named { symbol } => {
            resolve_unique_function_span(symbol, parsed_files).map(|span| ResolvedMcpHandler {
                span,
                caller: Some(symbol.clone()),
            })
        }
    }
}

#[cfg(feature = "typescript")]
fn resolve_unique_function_span(
    symbol: &str,
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Option<SourceLocation> {
    let mut matches = parsed_files.iter().flat_map(|(_, parsed)| {
        parsed
            .function_defs
            .iter()
            .filter(move |definition| definition.name == symbol)
    });
    let location = matches.next()?.location.clone();
    matches.next().is_none().then_some(location)
}

#[cfg(feature = "typescript")]
fn call_sites_for_handler<'a>(
    parsed_files: &'a [(PathBuf, parser::ParsedFile)],
    handler: &'a ResolvedMcpHandler,
) -> impl Iterator<Item = &'a parser::CallSite> {
    parsed_files
        .iter()
        .flat_map(|(_, parsed)| parsed.call_sites.iter())
        .filter(|call_site| {
            location_within_span(&call_site.location, &handler.span)
                && match handler.caller.as_deref() {
                    Some(caller) => call_site.caller.as_deref() == Some(caller),
                    None => call_site.caller.is_none(),
                }
        })
}

#[cfg(feature = "typescript")]
fn execution_within_scopes(
    parsed_files: &[(PathBuf, parser::ParsedFile)],
    scopes: &[(SourceLocation, Option<String>)],
) -> ExecutionSurface {
    let contains = |location: &SourceLocation| {
        scopes.iter().any(|(span, function_name)| {
            operation_belongs_to_scope(location, span, function_name.as_deref(), parsed_files)
        })
    };
    let mut execution = ExecutionSurface::default();
    for (_, parsed) in parsed_files {
        execution.commands.extend(
            parsed
                .commands
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.file_operations.extend(
            parsed
                .file_operations
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.network_operations.extend(
            parsed
                .network_operations
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.env_accesses.extend(
            parsed
                .env_accesses
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.dynamic_exec.extend(
            parsed
                .dynamic_exec
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
    }
    execution
}

#[cfg(feature = "typescript")]
fn operation_belongs_to_scope(
    location: &SourceLocation,
    span: &SourceLocation,
    function_name: Option<&str>,
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> bool {
    if !location_within_span(location, span) {
        return false;
    }

    let innermost = parsed_files
        .iter()
        .flat_map(|(_, parsed)| parsed.function_defs.iter())
        .filter(|definition| {
            location_within_span(&definition.location, span)
                && location_within_span(location, &definition.location)
        })
        .max_by_key(|definition| (definition.location.line, definition.location.column));

    match (function_name, innermost) {
        (Some(expected), Some(definition)) => definition.name == expected,
        (Some(_), None) => false,
        (None, None) => true,
        (None, Some(_)) => false,
    }
}

#[cfg(feature = "typescript")]
fn location_within_span(location: &SourceLocation, span: &SourceLocation) -> bool {
    if location.file != span.file {
        return false;
    }
    let start = (location.line, location.column);
    let span_start = (span.line, span.column);
    let span_end = (
        span.end_line.unwrap_or(span.line),
        span.end_column.unwrap_or(usize::MAX),
    );
    start >= span_start && start < span_end
}

fn find_next_mcp_tool_call(content: &str) -> Option<usize> {
    let mut cursor = 0;
    while cursor < content.len() {
        if let Some(next) = skip_js_string_or_comment(content, cursor, content.len()) {
            cursor = next;
            continue;
        }
        if content[cursor..].starts_with(".tool(")
            || content[cursor..].starts_with(".registerTool(")
        {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn parse_mcp_tool_handler(
    path: &Path,
    content: &str,
    start: usize,
    end: usize,
) -> Option<McpToolHandler> {
    let (start, end) = trim_range(content, start, end);
    let candidate = &content[start..end];
    if is_inline_handler(candidate) {
        return Some(McpToolHandler::Inline {
            location: source_loc_span(path, content, start, end),
        });
    }

    is_js_symbol(candidate).then(|| McpToolHandler::Named {
        symbol: candidate.to_string(),
    })
}

fn is_inline_handler(candidate: &str) -> bool {
    if candidate.starts_with('{') || candidate.starts_with('[') {
        return false;
    }
    if is_function_expression(candidate) {
        return true;
    }

    let arrow_candidate = candidate
        .strip_prefix("async")
        .filter(|rest| {
            rest.starts_with('(') || rest.chars().next().is_some_and(char::is_whitespace)
        })
        .map(str::trim_start)
        .unwrap_or(candidate);

    if arrow_candidate.starts_with('(') {
        return find_matching_delimiter(arrow_candidate, 0, b'(', b')')
            .is_some_and(|close| arrow_candidate[close + 1..].trim_start().starts_with("=>"));
    }

    arrow_candidate
        .split_once("=>")
        .is_some_and(|(parameter, _)| is_js_identifier(parameter.trim()))
}

fn is_function_expression(candidate: &str) -> bool {
    let candidate = candidate
        .strip_prefix("async")
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        .map(str::trim_start)
        .unwrap_or(candidate);
    candidate.strip_prefix("function").is_some_and(|rest| {
        rest.is_empty()
            || rest.starts_with('(')
            || rest.starts_with('*')
            || rest.chars().next().is_some_and(char::is_whitespace)
    })
}

fn is_js_symbol(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    !is_js_reserved_word(first) && is_js_identifier(first) && segments.all(is_js_identifier)
}

fn is_js_identifier(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || matches!(ch, '_' | '$'))
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
}

fn is_js_reserved_word(candidate: &str) -> bool {
    matches!(
        candidate,
        "async"
            | "await"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "let"
            | "new"
            | "null"
            | "return"
            | "static"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "undefined"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
    )
}

fn parse_object_string_property(
    content: &str,
    start: usize,
    end: usize,
    property: &str,
) -> Option<String> {
    let (start, end) = trim_range(content, start, end);
    if content.as_bytes().get(start) != Some(&b'{')
        || content.as_bytes().get(end.saturating_sub(1)) != Some(&b'}')
    {
        return None;
    }

    for (property_start, property_end) in top_level_segments(content, start + 1, end - 1) {
        let Some(colon) = find_top_level_byte(content, property_start, property_end, b':') else {
            continue;
        };
        let (key_start, key_end) = trim_range(content, property_start, colon);
        let key = parse_string_literal_at(content, key_start)
            .filter(|(_, after)| *after <= key_end)
            .map(|(value, _)| value)
            .unwrap_or_else(|| content[key_start..key_end].to_string());
        if key != property {
            continue;
        }

        let (value_start, value_end) = trim_range(content, colon + 1, property_end);
        return parse_string_literal_at(content, value_start)
            .filter(|(_, after)| *after <= value_end)
            .map(|(value, _)| value);
    }

    None
}

fn top_level_segments(content: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut segments = Vec::new();
    let mut segment_start = start;
    let mut cursor = start;
    let mut depths = [0usize; 3];

    while cursor < end {
        if let Some(next) = skip_js_string_or_comment(content, cursor, end) {
            cursor = next;
            continue;
        }

        match content.as_bytes()[cursor] {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'{' => depths[1] += 1,
            b'}' => depths[1] = depths[1].saturating_sub(1),
            b'[' => depths[2] += 1,
            b']' => depths[2] = depths[2].saturating_sub(1),
            b',' if depths == [0, 0, 0] => {
                let segment = trim_range(content, segment_start, cursor);
                if segment.0 < segment.1 {
                    segments.push(segment);
                }
                segment_start = cursor + 1;
            }
            _ => {}
        }
        cursor += 1;
    }

    let segment = trim_range(content, segment_start, end);
    if segment.0 < segment.1 {
        segments.push(segment);
    }
    segments
}

fn find_matching_delimiter(
    content: &str,
    open: usize,
    open_byte: u8,
    close_byte: u8,
) -> Option<usize> {
    let mut depth = 0usize;
    let mut cursor = open;
    while cursor < content.len() {
        if let Some(next) = skip_js_string_or_comment(content, cursor, content.len()) {
            cursor = next;
            continue;
        }

        let byte = content.as_bytes()[cursor];
        if byte == open_byte {
            depth += 1;
        } else if byte == close_byte {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(cursor);
            }
        }
        cursor += 1;
    }
    None
}

fn find_top_level_byte(content: &str, start: usize, end: usize, needle: u8) -> Option<usize> {
    let mut cursor = start;
    let mut depths = [0usize; 3];
    while cursor < end {
        if let Some(next) = skip_js_string_or_comment(content, cursor, end) {
            cursor = next;
            continue;
        }

        let byte = content.as_bytes()[cursor];
        if byte == needle && depths == [0, 0, 0] {
            return Some(cursor);
        }
        match byte {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'{' => depths[1] += 1,
            b'}' => depths[1] = depths[1].saturating_sub(1),
            b'[' => depths[2] += 1,
            b']' => depths[2] = depths[2].saturating_sub(1),
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn skip_js_string_or_comment(content: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let quote = *bytes.get(start)?;
    if matches!(quote, b'\'' | b'"' | b'`') {
        // Template literals are treated as opaque strings. Nested backticks
        // inside `${...}` are intentionally unsupported in this lightweight
        // extractor; handler-to-body resolution remains AST-backed follow-up work.
        let mut cursor = start + 1;
        while cursor < end {
            if bytes[cursor] == b'\\' {
                cursor = (cursor + 2).min(end);
            } else if bytes[cursor] == quote {
                return Some(cursor + 1);
            } else {
                cursor += 1;
            }
        }
        return Some(end);
    }

    if quote == b'/' && bytes.get(start + 1) == Some(&b'/') {
        let mut cursor = start + 2;
        while cursor < end && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        return Some(cursor);
    }
    if quote == b'/' && bytes.get(start + 1) == Some(&b'*') {
        let mut cursor = start + 2;
        while cursor + 1 < end {
            if bytes[cursor] == b'*' && bytes[cursor + 1] == b'/' {
                return Some(cursor + 2);
            }
            cursor += 1;
        }
        return Some(end);
    }

    None
}

fn trim_range(content: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && content.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && content.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn parse_string_literal_at(content: &str, offset: usize) -> Option<(String, usize)> {
    let offset = skip_whitespace(content, offset);
    let quote = content[offset..].chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }

    let mut value = String::new();
    let mut escaped = false;
    for (relative_index, ch) in content[offset + quote.len_utf8()..].char_indices() {
        let absolute_index = offset + quote.len_utf8() + relative_index;
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some((value, absolute_index + quote.len_utf8()));
        }
        value.push(ch);
    }

    None
}

fn skip_whitespace(content: &str, mut offset: usize) -> usize {
    while let Some(ch) = content[offset..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

fn dedupe_tools_by_name(tools: Vec<ToolSurface>) -> Vec<ToolSurface> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for tool in tools {
        if seen.insert(tool.name.clone()) {
            deduped.push(tool);
        }
    }
    deduped
}

fn dedupe_mcp_tool_declarations(declarations: Vec<McpToolDeclaration>) -> Vec<McpToolDeclaration> {
    let mut deduped: Vec<McpToolDeclaration> = Vec::new();
    for declaration in declarations {
        if let Some(existing) = deduped
            .iter_mut()
            .find(|existing| existing.tool.name == declaration.tool.name)
        {
            let existing_score = (
                usize::from(existing.handler.is_some()),
                usize::from(existing.tool.description.is_some()),
            );
            let new_score = (
                usize::from(declaration.handler.is_some()),
                usize::from(declaration.tool.description.is_some()),
            );
            if new_score > existing_score {
                *existing = declaration;
            }
        } else {
            deduped.push(declaration);
        }
    }
    deduped
}

fn source_loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

fn source_loc_span(file: &Path, content: &str, start: usize, end: usize) -> SourceLocation {
    // Columns are UTF-8 byte offsets and `end` is exclusive, matching the
    // half-open span produced by the source segment scanner.
    let start_line = content[..start].lines().count() + 1;
    let start_column = content[..start]
        .rsplit_once('\n')
        .map_or(start, |(_, line)| line.len());
    let end_line = content[..end].lines().count() + 1;
    let end_column = content[..end]
        .rsplit_once('\n')
        .map_or(end, |(_, line)| line.len());
    SourceLocation {
        file: file.to_path_buf(),
        line: start_line,
        column: start_column,
        end_line: Some(end_line),
        end_column: Some(end_column),
    }
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
        let metadata = std::fs::metadata(path)?;
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

pub(super) fn parse_dependencies(
    root: &Path,
    filter: &ScanPathFilter,
) -> dependency_surface::DependencySurface {
    use crate::ir::dependency_surface::*;
    let mut surface = DependencySurface::default();

    // Parse requirements.txt as a dependency manifest (NOT a lockfile)
    let req_file = root.join("requirements.txt");
    if req_file.exists() && filter.allows_path(root, &req_file) {
        if let Ok(content) = std::fs::read_to_string(&req_file) {
            for (idx, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                    continue;
                }
                let (name, version) = if let Some(pos) = line.find("==") {
                    (
                        line[..pos].trim().to_string(),
                        Some(line[pos + 2..].trim().to_string()),
                    )
                } else if let Some(pos) = line.find(">=") {
                    (
                        line[..pos].trim().to_string(),
                        Some(line[pos..].trim().to_string()),
                    )
                } else {
                    (line.to_string(), None)
                };

                surface.dependencies.push(Dependency {
                    name,
                    version_constraint: version,
                    locked_version: None,
                    locked_hash: None,
                    registry: "pypi".into(),
                    is_dev: false,
                    location: Some(SourceLocation {
                        file: req_file.clone(),
                        line: idx + 1,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    }),
                });
            }
        }
    }

    // Check for actual Python lockfiles
    for (filename, format) in [
        ("Pipfile.lock", LockfileFormat::PipenvLock),
        ("poetry.lock", LockfileFormat::PoetryLock),
        ("uv.lock", LockfileFormat::UvLock),
    ] {
        let lock_path = root.join(filename);
        if lock_path.exists() && filter.allows_path(root, &lock_path) {
            surface.lockfile = Some(LockfileInfo {
                path: lock_path,
                format,
                all_pinned: true,
                all_hashed: false,
            });
            break;
        }
    }

    // Parse package.json dependencies
    let pkg_json = root.join("package.json");
    if pkg_json.exists() && filter.allows_path(root, &pkg_json) {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                for (key, is_dev) in [("dependencies", false), ("devDependencies", true)] {
                    if let Some(deps) = value.get(key).and_then(|v| v.as_object()) {
                        for (name, version) in deps {
                            let line = find_json_key_line(&content, name);
                            surface.dependencies.push(Dependency {
                                name: name.clone(),
                                version_constraint: version.as_str().map(|s| s.to_string()),
                                locked_version: None,
                                locked_hash: None,
                                registry: "npm".into(),
                                is_dev,
                                location: Some(SourceLocation {
                                    file: pkg_json.clone(),
                                    line,
                                    column: 0,
                                    end_line: None,
                                    end_column: None,
                                }),
                            });
                        }
                    }
                }
            }
        }

        // Check for lockfile
        let lock = root.join("package-lock.json");
        if lock.exists() {
            surface.lockfile = Some(LockfileInfo {
                path: lock,
                format: dependency_surface::LockfileFormat::NpmLock,
                all_pinned: true,
                all_hashed: false,
            });
        }
    }

    surface
}

/// Find the 1-based line number where a JSON key (e.g. `"package-name"`) appears.
/// Falls back to line 1 if the key is not found.
fn find_json_key_line(content: &str, key: &str) -> usize {
    let needle = format!("\"{}\"", key);
    for (idx, line) in content.lines().enumerate() {
        if line.contains(&needle) {
            return idx + 1;
        }
    }
    1
}

pub(super) fn parse_provenance(
    root: &Path,
    filter: &ScanPathFilter,
) -> provenance_surface::ProvenanceSurface {
    let mut prov = provenance_surface::ProvenanceSurface::default();

    // From package.json
    let pkg_json = root.join("package.json");
    if pkg_json.exists() && filter.allows_path(root, &pkg_json) {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                prov.author = value
                    .get("author")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                prov.repository = value
                    .get("repository")
                    .and_then(|v| v.get("url").or(Some(v)))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                prov.license = value
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
    }

    // From pyproject.toml
    let pyproject = root.join("pyproject.toml");
    if pyproject.exists() && filter.allows_path(root, &pyproject) {
        if let Ok(content) = std::fs::read_to_string(&pyproject) {
            if let Ok(value) = content.parse::<toml::Value>() {
                if let Some(project) = value.get("project") {
                    prov.license = project
                        .get("license")
                        .and_then(|v| v.get("text").or(Some(v)))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let Some(authors) = project.get("authors").and_then(|v| v.as_array()) {
                        if let Some(first) = authors.first() {
                            prov.author = first
                                .get("name")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                }
                if let Some(urls) = value.get("project").and_then(|p| p.get("urls")) {
                    prov.repository = urls
                        .get("Repository")
                        .or(urls.get("repository"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    prov
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
        assert_eq!(bindings[0].execution.file_operations.len(), 1);
        assert!(bindings[0].execution.network_operations.is_empty());
        assert!(bindings[1].handler_resolved);
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
        assert_eq!(bindings[0].resolved_callees, vec!["firstHop"]);
        assert!(
            bindings[0].execution.network_operations.is_empty(),
            "depth-2 operations must not be attributed to the tool"
        );
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
        assert!(read
            .capability_evidence
            .iter()
            .all(|evidence| evidence.capability == Capability::FsRead));
        assert_eq!(
            fetch.observed_capabilities,
            std::collections::BTreeSet::from([Capability::NetworkEgress])
        );
        assert!(!read.capability_observation_complete);
        assert!(!fetch.capability_observation_complete);
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
      "description": "Fetch content from a URL",
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
        assert!(fetch
            .capability_declarations
            .iter()
            .all(|declaration| { declaration.source == CapabilityDeclarationSource::Permission }));
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
}
