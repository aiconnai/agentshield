use std::collections::HashSet;
use std::path::Path;

use crate::analysis::cross_file::{SanitizerCategory, sanitizer_category, sanitizer_label};
use crate::parser::{FunctionDef, FunctionParam, ParsedFile};

use super::classify::{loc, sanitized_var_marker};
use super::patterns::{FUNC_DEF_RE, HTTP_CLIENT_CTX_RE, SANITIZER_ASSIGN_RE};

pub(crate) fn collect_sanitizer_vars(content: &str, parsed: &mut ParsedFile) {
    for cap in SANITIZER_ASSIGN_RE.captures_iter(content) {
        let var_name = &cap[1];
        let func_name = &cap[2];
        if sanitizer_category(func_name)
            .is_some_and(|category| !matches!(category, SanitizerCategory::Redaction))
        {
            parsed.sanitized_vars.insert(var_name.to_string());
            if let Some(label) = sanitizer_label(func_name) {
                parsed
                    .sanitized_vars
                    .insert(sanitized_var_marker(var_name, &label));
            }
        }
    }
}

pub(crate) fn collect_function_defs_and_params(
    content: &str,
    file_path: &Path,
    parsed: &mut ParsedFile,
) -> HashSet<String> {
    let mut param_names = HashSet::new();
    for cap in FUNC_DEF_RE.captures_iter(content) {
        let func_name = &cap[1];
        let params_str = &cap[2];
        // In Python, functions starting with _ are conventionally private
        let is_exported = !func_name.starts_with('_');
        let func_line = content[..cap.get(0).map(|m| m.start()).unwrap_or(0)]
            .lines()
            .count()
            + 1;
        let function_location = loc(file_path, func_line);

        let mut func_params = Vec::new();
        for param in params_str.split(',') {
            let param = param.trim().split(':').next().unwrap_or("").trim();
            let param = param.split('=').next().unwrap_or("").trim();
            if !param.is_empty() && param != "self" && param != "cls" {
                param_names.insert(param.to_string());
                func_params.push(param.to_string());
                parsed.function_params.push(FunctionParam {
                    function_name: func_name.to_string(),
                    param_name: param.to_string(),
                    location: function_location.clone(),
                });
            }
        }

        parsed.function_defs.push(FunctionDef {
            name: func_name.to_string(),
            params: func_params,
            is_exported,
            location: function_location,
        });
    }
    param_names
}

pub(crate) fn collect_http_client_vars(content: &str) -> HashSet<String> {
    let mut http_client_vars = HashSet::new();
    for cap in HTTP_CLIENT_CTX_RE.captures_iter(content) {
        http_client_vars.insert(cap[1].to_string());
    }
    http_client_vars
}

/// Final segments of decorator names that expose a function to the agent or
/// MCP client (MCP, FastMCP, CrewAI, LangChain, OpenAI Agents, pydantic-ai,
/// Semantic Kernel, AutoGen).
const TOOL_DECORATORS: &[&str] = &[
    "tool",
    "tool_plain",
    "function_tool",
    "call_tool",
    "resource",
    "prompt",
    "kernel_function",
    "register_tool",
    "register_for_llm",
    "register_for_execution",
];

/// Record functions decorated as agent tools in `parsed.entry_points`.
///
/// Decorators may span several lines and stack; any tool decorator in the
/// stack marks the next `def`. String literals and comments are masked first
/// so their contents cannot hide a decorator or unbalance its parentheses.
pub(crate) fn collect_entry_points(content: &str, parsed: &mut ParsedFile) {
    let masked = mask_strings_and_comments(content);
    let mut pending = false;
    let mut depth: i32 = 0;
    for line in masked.lines() {
        let trimmed = line.trim();
        if depth > 0 {
            depth += paren_delta(trimmed);
            continue;
        }
        if let Some(decorator) = trimmed.strip_prefix('@') {
            pending |= is_tool_decorator(decorator);
            depth = paren_delta(decorator).max(0);
            continue;
        }
        if let Some(name) = def_name(trimmed) {
            if pending {
                parsed.entry_points.insert(name.to_string());
            }
        }
        if !trimmed.is_empty() {
            pending = false;
        }
    }
}

fn is_tool_decorator(decorator: &str) -> bool {
    let head_len = decorator
        .trim_start()
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .unwrap_or(decorator.trim_start().len());
    let head = &decorator.trim_start()[..head_len];
    let last = head.rsplit('.').next().unwrap_or(head);
    TOOL_DECORATORS.contains(&last)
}

fn def_name(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("async ")
        .map(str::trim_start)
        .unwrap_or(line);
    let rest = rest.strip_prefix("def ")?.trim_start();
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    (end > 0).then(|| &rest[..end])
}

fn paren_delta(text: &str) -> i32 {
    text.chars().fold(0, |delta, c| match c {
        '(' => delta + 1,
        ')' => delta - 1,
        _ => delta,
    })
}

/// Replace the contents of string literals and comments with spaces, keeping
/// quotes and newlines so line structure is preserved.
fn mask_strings_and_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '#' => {
                out.push(' ');
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    out.push(' ');
                    chars.next();
                }
            }
            '"' | '\'' => {
                out.push(c);
                let triple = chars.clone().take(2).all(|next| next == c);
                if triple {
                    chars.next();
                    chars.next();
                    out.push(c);
                    out.push(c);
                }
                mask_string_body(&mut chars, &mut out, c, triple);
            }
            _ => out.push(c),
        }
    }
    out
}

fn mask_string_body(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
    quote: char,
    triple: bool,
) {
    while let Some(c) = chars.next() {
        if c == '\\' {
            out.push(' ');
            if let Some(escaped) = chars.next() {
                out.push(if escaped == '\n' { '\n' } else { ' ' });
            }
        } else if c == quote && (!triple || chars.clone().take(2).all(|next| next == quote)) {
            out.push(c);
            if triple {
                chars.next();
                chars.next();
                out.push(c);
                out.push(c);
            }
            return;
        } else if c == '\n' {
            out.push('\n');
            // A single-quoted string cannot span lines; stop masking so an
            // unterminated quote does not swallow the rest of the file.
            if !triple {
                return;
            }
        } else {
            out.push(' ');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_points(content: &str) -> Vec<String> {
        let mut parsed = ParsedFile::default();
        collect_entry_points(content, &mut parsed);
        let mut names: Vec<_> = parsed.entry_points.into_iter().collect();
        names.sort();
        names
    }

    #[test]
    fn marks_functions_under_tool_decorators() {
        let content = "@mcp.tool()\ndef a(x): ...\n\n@tool\nasync def b(x): ...\n\n@kernel_function(name=\"c\")\ndef c(x): ...\n";
        assert_eq!(entry_points(content), ["a", "b", "c"]);
    }

    #[test]
    fn handles_multiline_and_stacked_decorators() {
        let content = "@server.tool(\n    name=\"run\",\n    description=\"(x)\",\n)\n@functools.wraps(other)\ndef run(cmd): ...\n";
        assert_eq!(entry_points(content), ["run"]);
    }

    #[test]
    fn strings_and_comments_cannot_hide_tool_decorators() {
        let content = "@server.tool  # exposed\ndef a(x): ...\n\n@server.tool(\"a\", description=\"(\")\ndef b(x): ...\n\n@server.tool(  # (\n    \"c\",\n)\ndef c(x): ...\n";
        assert_eq!(entry_points(content), ["a", "b", "c"]);
    }

    #[test]
    fn masking_preserves_line_structure() {
        let content = "x = \"\"\"a\n(b\"\"\"  # c(\ny = 'it\\'s'\n";
        let masked = mask_strings_and_comments(content);
        assert_eq!(masked.lines().count(), content.lines().count());
        assert!(!masked.contains('('));
        assert!(masked.starts_with("x = \"\"\""));
    }

    #[test]
    fn ignores_plain_functions_and_other_decorators() {
        let content = "@functools.cache\ndef cached(x): ...\n\ndef plain(x): ...\n\n@tool\nx = 1\ndef after_statement(x): ...\n";
        assert!(entry_points(content).is_empty());
    }
}
