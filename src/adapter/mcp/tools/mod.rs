pub(crate) mod python;
pub(crate) mod scan;

use std::path::Path;

use crate::ir::SourceLocation;
use crate::ir::tool_surface::ToolSurface;

pub(crate) use python::extract_mcp_python_decorators;
pub(crate) use scan::{
    find_matching_delimiter, find_next_mcp_tool_call, parse_mcp_tool_handler,
    parse_object_string_property, parse_string_literal_at, top_level_segments,
};

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
        let line = content.as_bytes()[..call_start]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1;

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

pub fn extract_mcp_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parse_python_mcp_tool_decorator() {
        let content = r#"
@mcp.tool("my_tool", "my description")
def my_tool():
    pass
        "#;
        let tools = extract_mcp_python_decorators(Path::new("test.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "my_tool");
        assert_eq!(tools[0].description.as_deref(), Some("my description"));
    }

    #[test]
    fn parse_python_fastmcp_decorator() {
        let content = r#"
@mcp.tool
def simple_tool():
    pass
        "#;
        let tools = extract_mcp_python_decorators(Path::new("test.py"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "simple_tool");
        assert_eq!(tools[0].description, None);
    }

    #[test]
    fn ignores_non_tool_decorators() {
        let content = r#"
@mcp.resource("my_resource")
def my_resource():
    pass
        "#;
        let tools = extract_mcp_python_decorators(Path::new("test.py"), content);
        assert!(tools.is_empty());
    }
}
