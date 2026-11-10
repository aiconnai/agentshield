//! Function-scoped sanitizer tracking for the tree-sitter TypeScript parser.

use tree_sitter::Node;

use crate::analysis::cross_file::assignment_sanitizer_label;
use crate::parser::common::ScopedSanitizers;

use super::ast::node_text;

const FUNCTION_KINDS: &[&str] = &[
    "function_declaration",
    "function",
    "arrow_function",
    "method_definition",
    "function_expression",
    "generator_function_declaration",
    "generator_function",
];

/// `/`-joined start offsets of the functions enclosing `node`, outermost
/// first; empty at module level.
pub(super) fn scope_path(node: Node) -> String {
    let mut starts = Vec::new();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if FUNCTION_KINDS.contains(&parent.kind()) {
            starts.push(parent.start_byte().to_string());
        }
        current = parent;
    }
    starts.reverse();
    starts.join("/")
}

/// Record every `const x = sanitizer(...)` under the function that contains it.
pub(super) fn collect_scoped_sanitizers(root: Node, source: &[u8]) -> ScopedSanitizers {
    let mut scoped = ScopedSanitizers::default();
    collect(root, source, root, &mut scoped);
    scoped
}

fn collect(node: Node, source: &[u8], enclosing: Node, scoped: &mut ScopedSanitizers) {
    if node.kind() == "variable_declarator" {
        record_declarator(node, source, enclosing, scoped);
    }
    let enclosing = if FUNCTION_KINDS.contains(&node.kind()) {
        node
    } else {
        enclosing
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect(child, source, enclosing, scoped);
    }
}

fn record_declarator(node: Node, source: &[u8], enclosing: Node, scoped: &mut ScopedSanitizers) {
    let (Some(name), Some(value)) = (
        node.child_by_field_name("name"),
        node.child_by_field_name("value"),
    ) else {
        return;
    };
    if name.kind() != "identifier" {
        return;
    }
    let Some(call) = called_expression(value) else {
        return;
    };
    let Some(callee) = call.child_by_field_name("function") else {
        return;
    };
    let callee: String = node_text(callee, source)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    let var = node_text(name, source);
    let scope_text = node_text(enclosing, source);
    if let Some(label) = assignment_sanitizer_label(&callee, var, scope_text) {
        scoped.insert(&scope_path(node), var, &label);
    }
}

/// The call expression a declarator is initialized with, looking through
/// `await`.
fn called_expression(value: Node) -> Option<Node> {
    match value.kind() {
        "call_expression" => Some(value),
        "await_expression" => {
            let mut cursor = value.walk();
            value
                .named_children(&mut cursor)
                .find(|child| child.kind() == "call_expression")
        }
        _ => None,
    }
}
