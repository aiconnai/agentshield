#[cfg(feature = "typescript")]
use std::collections::HashSet;
#[cfg(feature = "typescript")]
use std::path::Path;

#[cfg(feature = "typescript")]
use crate::analysis::sensitivity::looks_sensitive_name;
#[cfg(feature = "typescript")]
use crate::ir::execution_surface::*;
#[cfg(feature = "typescript")]
use crate::ir::{ArgumentSource, SourceLocation};
#[cfg(feature = "typescript")]
use crate::parser::{CallSite, FunctionDef, FunctionParam, ParsedFile};

#[cfg(feature = "typescript")]
use super::classify::classify_all_arguments;
#[cfg(feature = "typescript")]
use super::patterns::{
    DYNAMIC_EXEC_PATTERNS, EXEC_PATTERNS, FILE_PATTERNS, NETWORK_PATTERNS, matches_pattern,
};

/// Recursively collect function/method/arrow parameter names + FunctionDef entries.
#[cfg(feature = "typescript")]
pub(super) fn collect_params(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    param_names: &mut HashSet<String>,
    parsed: &mut ParsedFile,
) {
    let kind = node.kind();

    // Function declarations, arrow functions, method definitions
    if kind == "function_declaration"
        || kind == "function"
        || kind == "arrow_function"
        || kind == "method_definition"
        || kind == "function_expression"
    {
        let func_name = extract_function_name(node, source).unwrap_or_default();
        let mut func_params = Vec::new();

        if let Some(params_node) = node.child_by_field_name("parameters") {
            for i in 0..params_node.named_child_count() {
                if let Some(param) = params_node.named_child(i) {
                    for name in extract_param_names(param, source) {
                        if name != "this" {
                            param_names.insert(name.clone());
                            func_params.push(name.clone());
                            parsed.function_params.push(FunctionParam {
                                function_name: func_name.clone(),
                                param_name: name,
                                location: loc(file_path, param),
                            });
                        }
                    }
                }
            }
        }

        // Record FunctionDef if we have a name
        if !func_name.is_empty() {
            let is_exported = is_exported_node(node, source);
            parsed.function_defs.push(FunctionDef {
                name: func_name,
                params: func_params,
                is_exported,
                location: loc(file_path, node),
            });
        }
    }

    // Recurse
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            collect_params(child, source, file_path, param_names, parsed);
        }
    }
}

/// Check if a function node is exported (has `export` keyword in ancestors or declaration).
#[cfg(feature = "typescript")]
pub(super) fn is_exported_node(node: tree_sitter::Node, source: &[u8]) -> bool {
    // Check if the function/arrow is inside an export_statement
    let mut current = node;
    while let Some(parent) = current.parent() {
        let pk = parent.kind();
        if pk == "export_statement" {
            return true;
        }
        // Stop at top-level statements
        if pk == "program" || pk == "statement_block" {
            break;
        }
        current = parent;
    }
    // Check for `module.exports` pattern — look at the parent variable_declarator
    // e.g., module.exports.func = function(...) {}
    if let Some(parent) = node.parent() {
        let parent_text = node_text(parent, source);
        if parent_text.contains("module.exports") || parent_text.contains("exports.") {
            return true;
        }
    }
    false
}

/// Extract a function's name from its AST node.
#[cfg(feature = "typescript")]
pub(super) fn extract_function_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // For function_declaration/method_definition: name field
    if let Some(name_node) = node.child_by_field_name("name") {
        return Some(node_text(name_node, source).to_string());
    }

    // For arrow functions assigned to variables: look at parent
    // const handler = async (params) => { ... }
    if node.kind() == "arrow_function" || node.kind() == "function_expression" {
        if let Some(parent) = node.parent() {
            if parent.kind() == "variable_declarator" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    return Some(node_text(name_node, source).to_string());
                }
            }
        }
    }

    None
}

/// Extract parameter name(s) from a formal_parameters child node.
/// Returns a Vec because destructured patterns yield multiple names.
#[cfg(feature = "typescript")]
pub(super) fn extract_param_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    match node.kind() {
        // required_parameter or optional_parameter: has "pattern" field
        "required_parameter" | "optional_parameter" => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                if pattern.kind() == "identifier" {
                    return vec![node_text(pattern, source).to_string()];
                }
                // Destructured object pattern: { url, name } => ["url", "name"]
                if pattern.kind() == "object_pattern" {
                    return extract_object_pattern_names(pattern, source);
                }
                // Destructured array pattern: [a, b] => ["a", "b"]
                if pattern.kind() == "array_pattern" {
                    return extract_array_pattern_names(pattern, source);
                }
            }
            vec![]
        }
        // Rest parameter: ...args
        "rest_pattern" => {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    if child.kind() == "identifier" {
                        return vec![node_text(child, source).to_string()];
                    }
                }
            }
            vec![]
        }
        // Plain identifier (JS-style params without type annotations)
        "identifier" => vec![node_text(node, source).to_string()],
        _ => vec![],
    }
}

/// Extract property names from an object destructuring pattern: { url, name }
#[cfg(feature = "typescript")]
pub(super) fn extract_object_pattern_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            match child.kind() {
                // shorthand_property_identifier_pattern: { url } => "url"
                "shorthand_property_identifier_pattern" => {
                    names.push(node_text(child, source).to_string());
                }
                // pair_pattern: { url: myUrl } => "myUrl"
                "pair_pattern" => {
                    if let Some(value) = child.child_by_field_name("value") {
                        if value.kind() == "identifier" {
                            names.push(node_text(value, source).to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    names
}

/// Extract names from an array destructuring pattern: [a, b]
#[cfg(feature = "typescript")]
pub(super) fn extract_array_pattern_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            if child.kind() == "identifier" {
                names.push(node_text(child, source).to_string());
            }
        }
    }
    names
}

/// Walk the AST looking for call_expression and member_expression (for env access).
#[cfg(feature = "typescript")]
pub(super) fn walk_node(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    param_names: &HashSet<String>,
    parsed: &mut ParsedFile,
) {
    let kind = node.kind();

    // Check for process.env access: process.env.VAR or process.env["VAR"]
    if kind == "member_expression" || kind == "subscript_expression" {
        let text = node_text(node, source);
        if text.starts_with("process.env") {
            let var_name = extract_env_var_name(node, source);
            if let Some(name) = &var_name {
                let is_sensitive = looks_sensitive_name(name);
                parsed.env_accesses.push(EnvAccess {
                    var_name: ArgumentSource::Literal(name.clone()),
                    is_sensitive,
                    location: loc(file_path, node),
                });
            }
        }
    }

    // Check for call_expression
    if kind == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let func_name = resolve_call_name(func_node, source);

            // Classify all arguments (not just the first) for CallSite recording
            let args_node = node.child_by_field_name("arguments");
            let all_arg_sources =
                classify_all_arguments(args_node, source, param_names, &parsed.sanitized_vars);

            // First argument source for existing detector logic
            let arg_source = all_arg_sources
                .first()
                .cloned()
                .unwrap_or(ArgumentSource::Unknown);

            // Record CallSite for cross-file analysis
            let caller_name = find_enclosing_function(node, source);
            parsed.call_sites.push(CallSite {
                callee: func_name.clone(),
                arguments: all_arg_sources,
                caller: caller_name,
                location: loc(file_path, node),
            });

            // Command execution
            if matches_pattern(&func_name, &EXEC_PATTERNS) {
                parsed.commands.push(CommandInvocation {
                    function: func_name.clone(),
                    command_arg: arg_source.clone(),
                    location: loc(file_path, node),
                });
            }

            // Network operations
            if matches_pattern(&func_name, &NETWORK_PATTERNS) {
                let full_args_text = node
                    .child_by_field_name("arguments")
                    .map(|a| node_text(a, source).to_string())
                    .unwrap_or_default();
                let sends_data = func_name.contains("post")
                    || func_name.contains("put")
                    || func_name.contains("patch")
                    || full_args_text.contains("body:")
                    || full_args_text.contains("data:");
                let method = if func_name.contains("get") {
                    Some("GET".into())
                } else if func_name.contains("post") {
                    Some("POST".into())
                } else if func_name.contains("put") {
                    Some("PUT".into())
                } else {
                    None
                };
                parsed.network_operations.push(NetworkOperation {
                    function: func_name.clone(),
                    url_arg: arg_source.clone(),
                    method,
                    sends_data,
                    location: loc(file_path, node),
                });
            }

            // Dynamic execution
            if DYNAMIC_EXEC_PATTERNS.contains(&func_name.as_str()) {
                parsed.dynamic_exec.push(DynamicExec {
                    function: func_name.clone(),
                    code_arg: arg_source.clone(),
                    location: loc(file_path, node),
                });
            }

            // File operations
            if matches_pattern(&func_name, &FILE_PATTERNS) {
                let op_type = if func_name.contains("write") || func_name.contains("append") {
                    FileOpType::Write
                } else if func_name.contains("unlink") {
                    FileOpType::Delete
                } else if func_name.contains("readdir") {
                    FileOpType::List
                } else {
                    FileOpType::Read
                };
                parsed.file_operations.push(FileOperation {
                    operation: op_type,
                    path_arg: arg_source.clone(),
                    location: loc(file_path, node),
                });
            }
        }
    }

    // Constructors are executable too. Record every `new` expression as a call
    // site so capability observation cannot be marked complete when an
    // unmodeled constructor remains in a bound handler. `new Function(...)` is
    // additionally a modeled dynamic-execution operation.
    if kind == "new_expression" {
        if let Some(constructor_node) = node.child_by_field_name("constructor") {
            let constructor_name = resolve_call_name(constructor_node, source);
            let args_node = node.child_by_field_name("arguments");
            let all_arg_sources =
                classify_all_arguments(args_node, source, param_names, &parsed.sanitized_vars);
            let code_arg = all_arg_sources
                .first()
                .cloned()
                .unwrap_or(ArgumentSource::Unknown);
            let location = loc(file_path, node);

            parsed.call_sites.push(CallSite {
                callee: constructor_name.clone(),
                arguments: all_arg_sources,
                caller: find_enclosing_function(node, source),
                location: location.clone(),
            });

            if constructor_name == "Function" {
                parsed.dynamic_exec.push(DynamicExec {
                    function: constructor_name,
                    code_arg,
                    location,
                });
            }
        }
    }

    // Recurse into children (skip already-processed subtrees)
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            walk_node(child, source, file_path, param_names, parsed);
        }
    }
}

/// Find the enclosing function name for a node (for caller tracking).
#[cfg(feature = "typescript")]
pub(super) fn find_enclosing_function(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        let pk = parent.kind();
        if pk == "function_declaration"
            || pk == "function"
            || pk == "arrow_function"
            || pk == "method_definition"
            || pk == "function_expression"
        {
            return extract_function_name(parent, source);
        }
        current = parent;
    }
    None
}

/// Resolve a call expression's function name from its AST node.
/// Handles: identifier, member_expression chains (a.b.c), optional_chain.
#[cfg(feature = "typescript")]
pub(super) fn resolve_call_name(node: tree_sitter::Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" => node_text(node, source).to_string(),
        "member_expression" | "optional_chain_expression" => {
            // Flatten the member chain: a.b.c
            node_text(node, source).replace(['\n', ' '], "").to_string()
        }
        _ => node_text(node, source).to_string(),
    }
}

/// Extract environment variable name from process.env access.
#[cfg(feature = "typescript")]
pub(super) fn extract_env_var_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let text = node_text(node, source);
    // process.env.VAR_NAME
    if let Some(rest) = text.strip_prefix("process.env.") {
        return Some(rest.to_string());
    }
    // process.env["VAR_NAME"] or process.env['VAR_NAME']
    if node.kind() == "subscript_expression" {
        if let Some(index) = node.child_by_field_name("index") {
            let idx_text = node_text(index, source);
            let trimmed = idx_text.trim_matches('"').trim_matches('\'').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

/// Get the text of a tree-sitter node.
#[cfg(feature = "typescript")]
pub(super) fn node_text<'a>(node: tree_sitter::Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

/// Build a SourceLocation from a tree-sitter node (1-indexed lines).
#[cfg(feature = "typescript")]
pub(super) fn loc(file: &Path, node: tree_sitter::Node) -> SourceLocation {
    let start = node.start_position();
    let end = node.end_position();
    SourceLocation {
        file: file.to_path_buf(),
        line: start.row + 1,
        column: start.column,
        end_line: Some(end.row + 1),
        end_column: Some(end.column),
    }
}
