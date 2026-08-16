use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tree_sitter::Node;

use crate::ir::SourceLocation;
use super::types::ByteSpan;

pub(crate) fn normalized_subtree_hash(node: Node<'_>, source: &str) -> String {
    fn append(node: Node<'_>, source: &str, output: &mut String) {
        output.push_str(node.kind());
        output.push('(');
        let children = named_children(node);
        if children.is_empty() {
            if node.kind() == "identifier" {
                output.push_str("<identifier>");
            } else {
                output.push_str(text(node, source).trim());
            }
        } else {
            for child in children {
                append(child, source, output);
            }
        }
        output.push(')');
    }
    let mut normalized = String::new();
    append(node, source, &mut normalized);
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub(crate) fn walk<'tree>(node: Node<'tree>, callback: &mut impl FnMut(Node<'tree>)) {
    callback(node);
    for child in named_children(node) {
        walk(child, callback);
    }
}

pub(crate) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

pub(crate) fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

pub(crate) fn span(node: Node<'_>) -> ByteSpan {
    ByteSpan {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}

pub(crate) fn location(path: &Path, node: Node<'_>) -> SourceLocation {
    let start = node.start_position();
    let end = node.end_position();
    SourceLocation {
        file: path.to_path_buf(),
        line: start.row + 1,
        column: start.column,
        end_line: Some(end.row + 1),
        end_column: Some(end.column),
    }
}

pub(crate) fn location_for_node(node: Node<'_>) -> (usize, usize) {
    let start = node.start_position();
    (start.row + 1, start.column)
}

pub(crate) fn unwrap_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        if matches!(node.kind(), "await_expression" | "parenthesized_expression") {
            if let Some(child) = named_children(node).into_iter().next() {
                node = child;
                continue;
            }
        }
        return node;
    }
}

pub(crate) fn call_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "call_expression")
        .then(|| node.child_by_field_name("function"))
        .flatten()
        .map(|function| text(function, source).replace([' ', '\n'], ""))
}

pub(crate) fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
}

pub(crate) fn is_function(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
    )
}

pub(crate) fn function_is_top_level(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if is_function(parent) {
            return false;
        }
        current = parent.parent();
    }
    true
}

pub(crate) fn is_exported_function(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "export_statement" {
            return true;
        }
        if is_function(parent) || parent.kind() == "program" {
            return false;
        }
        current = parent.parent();
    }
    false
}

pub(crate) fn function_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(text(name, source).to_string());
    }
    let parent = node.parent()?;
    if parent.kind() == "variable_declarator" {
        return parent
            .child_by_field_name("name")
            .map(|name| text(name, source).to_string());
    }
    None
}

pub(crate) fn function_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
}

pub(crate) fn binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            vec![text(node, source).to_string()]
        }
        "required_parameter" | "optional_parameter" => node
            .child_by_field_name("pattern")
            .map(|pattern| binding_names(pattern, source))
            .unwrap_or_default(),
        "object_pattern" => named_children(node)
            .into_iter()
            .flat_map(|child| binding_names(child, source))
            .collect(),
        "pair_pattern" => node
            .child_by_field_name("value")
            .map(|value| binding_names(value, source))
            .unwrap_or_default(),
        "formal_parameters" => named_children(node)
            .into_iter()
            .flat_map(|parameter| binding_names(parameter, source))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn simple_binding_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier").then(|| text(node, source).to_string())
}

pub(crate) fn collect_bindings(node: Node<'_>, root: Node<'_>, source: &str, output: &mut Vec<String>) {
    if node != root && is_function(node) {
        return;
    }
    if node.kind() == "variable_declarator" {
        if let Some(name) = node.child_by_field_name("name") {
            output.extend(binding_names(name, source));
        }
    }
    for child in named_children(node) {
        collect_bindings(child, root, source, output);
    }
}

pub(crate) fn collect_events<'tree>(node: Node<'tree>, root: Node<'tree>, output: &mut Vec<Node<'tree>>) {
    if node != root && is_function(node) {
        return;
    }
    if matches!(
        node.kind(),
        "variable_declarator"
            | "assignment_expression"
            | "augmented_assignment_expression"
            | "call_expression"
            | "return_statement"
    ) {
        output.push(node);
    }
    for child in named_children(node) {
        collect_events(child, root, output);
    }
}

pub(crate) fn object_property<'tree>(
    object: Node<'tree>,
    source: &str,
    property: &str,
) -> Option<Node<'tree>> {
    let object = unwrap_expression(object);
    if object.kind() != "object" {
        return None;
    }
    named_children(object).into_iter().find_map(|pair| {
        if pair.kind() != "pair" {
            return None;
        }
        let key = pair.child_by_field_name("key")?;
        (text(key, source).trim_matches(['\'', '"']) == property)
            .then(|| pair.child_by_field_name("value"))
            .flatten()
    })
}

pub(crate) fn relative_import_targets(caller: &Path, module: &str, target: &Path) -> bool {
    let Some(parent) = caller.parent() else {
        return false;
    };
    let base = normalize_path(&parent.join(module));
    let target = normalize_path(target);
    if base.extension().is_some() {
        return base == target;
    }
    ["ts", "tsx", "js", "jsx", "mjs", "cjs"]
        .iter()
        .any(|extension| base.with_extension(extension) == target)
        || ["ts", "tsx", "js", "jsx"]
            .iter()
            .any(|extension| base.join("index").with_extension(extension) == target)
}

pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
