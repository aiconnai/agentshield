use std::path::Path;

use crate::ir::tool_surface::ToolSurface;

use super::scan::{parse_string_literal_at, skip_whitespace};
use super::{dedupe_tools_by_name, source_loc};

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
