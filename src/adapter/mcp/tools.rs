use std::path::Path;

use crate::ir::SourceLocation;
use crate::ir::tool_surface::ToolSurface;

#[derive(Debug, Clone)]
pub(crate) struct McpToolDeclaration {
    pub(crate) tool: ToolSurface,
    pub(crate) handler: Option<McpToolHandler>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum McpToolHandler {
    Named { symbol: String },
    Inline { location: SourceLocation },
}

pub(crate) fn extract_mcp_tool_declarations_from_source(
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

pub(crate) fn extract_mcp_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = if path.extension().and_then(|ext| ext.to_str()) == Some("py") {
        extract_mcp_python_decorators(path, content)
    } else {
        Vec::new()
    };

    tools.extend(
        extract_mcp_tool_declarations_from_source(path, content)
            .into_iter()
            .map(|declaration| declaration.tool),
    );
    dedupe_tools_by_name(tools)
}

pub(crate) fn find_next_mcp_tool_call(content: &str) -> Option<usize> {
    let mut cursor = 0;
    while cursor < content.len() {
        if let Some(next) = skip_js_string_or_comment(content, cursor, content.len()) {
            cursor = next;
            continue;
        }
        if let Some(rest) = content.get(cursor..) {
            if rest.starts_with(".tool(") || rest.starts_with(".registerTool(") {
                return Some(cursor);
            }
            if let Some(ch) = rest.chars().next() {
                cursor += ch.len_utf8();
                continue;
            }
        }
        cursor += 1;
    }
    None
}

pub(crate) fn parse_mcp_tool_handler(
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

pub(crate) fn is_inline_handler(candidate: &str) -> bool {
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

pub(crate) fn is_function_expression(candidate: &str) -> bool {
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

pub(crate) fn is_js_symbol(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    !is_js_reserved_word(first) && is_js_identifier(first) && segments.all(is_js_identifier)
}

pub(crate) fn is_js_identifier(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || matches!(ch, '_' | '$'))
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
}

pub(crate) fn is_js_reserved_word(candidate: &str) -> bool {
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

pub(crate) fn parse_object_string_property(
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

pub(crate) fn top_level_segments(content: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
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

pub(crate) fn find_matching_delimiter(
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

pub(crate) fn find_top_level_byte(
    content: &str,
    start: usize,
    end: usize,
    needle: u8,
) -> Option<usize> {
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

pub(crate) fn skip_js_string_or_comment(content: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let quote = *bytes.get(start)?;
    if matches!(quote, b'\'' | b'"' | b'`') {
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

pub(crate) fn trim_range(content: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && content.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && content.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

pub(crate) fn parse_string_literal_at(content: &str, offset: usize) -> Option<(String, usize)> {
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

pub(crate) fn extract_mcp_python_decorators(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = Vec::new();

    let mut pending_tool_name: Option<String> = None;
    let mut pending_description: Option<String> = None;
    let mut pending_line: Option<usize> = None;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if let Some((explicit_name, description)) = parse_python_decorator_tool(trimmed) {
            pending_tool_name = explicit_name;
            pending_description = description;
            pending_line = Some(line_idx + 1);
            continue;
        }

        // A decorator applies to the next top-level function definition.
        if pending_line.is_some() {
            if let Some(name) = parse_python_function_name(trimmed) {
                let tool_name = pending_tool_name.take().unwrap_or_else(|| name.to_string());
                let description = pending_description.take();
                tools.push(ToolSurface {
                    name: tool_name,
                    description,
                    input_schema: None,
                    output_schema: None,
                    declared_permissions: Vec::new(),
                    defined_at: Some(source_loc(path, pending_line.unwrap_or(line_idx + 1))),
                    declared_capabilities: Default::default(),
                    capability_declarations: Vec::new(),
                    observed_capabilities: Default::default(),
                    capability_observation_complete: false,
                    capability_evidence: Vec::new(),
                });
                pending_line = None;
                continue;
            }

            if !trimmed.is_empty() && !trimmed.starts_with('@') && !trimmed.starts_with("\"\"\"") {
                pending_tool_name = None;
                pending_description = None;
                pending_line = None;
            }
        }
    }

    dedupe_tools_by_name(tools)
}

pub(crate) fn parse_python_decorator_tool(line: &str) -> Option<(Option<String>, Option<String>)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('@') {
        return None;
    }

    if trimmed.ends_with(".tool") || trimmed == "@tool" {
        return Some((None, None));
    }

    let call_idx = trimmed.find(".tool(").or_else(|| trimmed.find("tool("))?;
    let open_paren = trimmed[call_idx..]
        .find('(')
        .and_then(|idx| call_idx.checked_add(idx + 1))?;
    let Some((name, after_name)) = parse_string_literal_at(trimmed, open_paren) else {
        let arg_slice = &trimmed[open_paren..];
        return Some((
            parse_python_kwarg_string_arg(arg_slice, "name"),
            parse_python_kwarg_string_arg(arg_slice, "description"),
        ));
    };
    Some((Some(name), parse_next_string_argument(trimmed, after_name)))
}

pub(crate) fn parse_next_string_argument(content: &str, offset: usize) -> Option<String> {
    let mut index = skip_whitespace(content, offset);
    if content[index..].starts_with(',') {
        index += 1;
    } else {
        return None;
    }

    let index = skip_whitespace(content, index);
    parse_string_literal_at(content, index).map(|(value, _)| value)
}

pub(crate) fn parse_python_kwarg_string_arg(args: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let idx = args.find(&needle)?;
    let rest = &args[idx + needle.len()..];
    let rest = rest.trim_start();
    parse_string_literal_at(rest, 0).map(|(value, _)| value)
}

pub(crate) fn parse_python_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("def ") && !trimmed.starts_with("async def ") {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix("def ") {
        let func = rest.split('(').next()?.trim();
        if func.is_empty() {
            return None;
        }
        return Some(func.to_string());
    }

    let rest = trimmed.strip_prefix("async def ")?;
    let func = rest.split('(').next()?.trim();
    if func.is_empty() {
        return None;
    }
    Some(func.to_string())
}

pub(crate) fn skip_whitespace(content: &str, mut offset: usize) -> usize {
    while let Some(ch) = content[offset..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

pub(crate) fn dedupe_tools_by_name(tools: Vec<ToolSurface>) -> Vec<ToolSurface> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for tool in tools {
        if seen.insert(tool.name.clone()) {
            deduped.push(tool);
        }
    }
    deduped
}

pub(crate) fn dedupe_mcp_tool_declarations(
    declarations: Vec<McpToolDeclaration>,
) -> Vec<McpToolDeclaration> {
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

pub(crate) fn source_loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

pub(crate) fn source_loc_span(
    file: &Path,
    content: &str,
    start: usize,
    end: usize,
) -> SourceLocation {
    let start_line = content.as_bytes()[..start]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1;
    let start_column = content[..start]
        .rsplit_once('\n')
        .map_or(start, |(_, line)| line.len());
    let end_line = content.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1;
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
