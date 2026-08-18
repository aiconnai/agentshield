use std::collections::BTreeSet;

use tree_sitter::Node;

use super::ast::{
    binding_names, collect_bindings, function_body, function_name, is_function, named_children,
    walk,
};
use super::builder::ParsedUnit;

pub(crate) fn has_containment_guard(source: &str, before: usize, path_expression: &str) -> bool {
    let prefix = &source[..before.min(source.len())];
    let guard = format!("!{}.startsWith(", path_expression.trim());
    let Some(guard_start) = prefix.rfind(&guard) else {
        return false;
    };
    let guard_tail = &prefix[guard_start + guard.len()..];
    let literal_root = guard_tail.trim_start().starts_with(['\'', '"']);
    let guard_body = &prefix[guard_start..];
    literal_root && (guard_body.contains("throw ") || guard_body.contains("return "))
}

pub(crate) fn contains_opaque_control_flow(node: Node<'_>, reject_return: bool) -> bool {
    if matches!(
        node.kind(),
        "if_statement"
            | "switch_statement"
            | "for_statement"
            | "for_in_statement"
            | "for_of_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "with_statement"
            | "labeled_statement"
            | "ternary_expression"
            | "binary_expression"
    ) || (reject_return && node.kind() == "return_statement")
    {
        return true;
    }
    named_children(node)
        .into_iter()
        .filter(|child| !is_function(*child))
        .any(|child| contains_opaque_control_flow(child, reject_return))
}

pub(crate) fn top_level_return_count(body: Node<'_>) -> usize {
    named_children(body)
        .into_iter()
        .filter(|child| child.kind() == "return_statement")
        .count()
}

pub(crate) fn has_ambiguous_shadowing(function: Node<'_>, source: &str) -> bool {
    let mut names = BTreeSet::new();
    if let Some(parameters) = function.child_by_field_name("parameters") {
        for name in binding_names(parameters, source) {
            if !names.insert(name) {
                return true;
            }
        }
    }
    let Some(body) = function_body(function) else {
        return false;
    };
    let mut declarations = Vec::new();
    collect_bindings(body, body, source, &mut declarations);
    declarations.into_iter().any(|name| !names.insert(name))
}

pub(crate) fn global_name_shadowed(unit: &ParsedUnit<'_>, name: &str) -> bool {
    let mut shadowed = false;
    walk(unit.tree.root_node(), &mut |node| {
        if shadowed {
            return;
        }
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|candidate| {
                    binding_names(candidate, unit.content)
                        .iter()
                        .any(|b| b == name)
                })
        {
            shadowed = true;
        }
        if is_function(node) && function_name(node, unit.content).as_deref() == Some(name) {
            shadowed = true;
        }
        if node.kind() == "formal_parameters"
            && binding_names(node, unit.content)
                .iter()
                .any(|parameter| parameter == name)
        {
            shadowed = true;
        }
    });
    shadowed
}
