use std::collections::BTreeMap;
use std::path::Path;
use tree_sitter::Node;

use super::super::ast::{
    binding_names, call_arguments, collect_events, function_body, function_name, location,
    named_children, normalized_subtree_hash, simple_binding_name, span, text, unwrap_expression,
};
use super::super::guard::{
    contains_opaque_control_flow, has_ambiguous_shadowing, top_level_return_count,
};
use super::super::types::{
    DefinitionId, FlowEdge, FlowEdgeKind, ScopeId, ValueId,
};
use super::resolve::{assign, resolve_lineage, resolved_file_read_api};
use super::types::{AnchorKey, AnchorSeed, Lineage, ParsedUnit};

pub(crate) fn analyze_helper_return(
    unit: &ParsedUnit<'_>,
    function: Node<'_>,
    seed: BTreeMap<String, Lineage>,
    caller_scope: &ScopeId,
) -> Option<Lineage> {
    let body = function_body(function)?;
    if contains_opaque_control_flow(body, false)
        || has_ambiguous_shadowing(function, unit.content)
        || top_level_return_count(body) != 1
    {
        return None;
    }
    let mut variables = seed;
    let mut events = Vec::new();
    collect_events(body, body, &mut events);
    events.sort_by_key(Node::start_byte);
    let helper_scope = ScopeId {
        relative_file: unit.path.to_path_buf(),
        lexical_owner: function_name(function, unit.content)?,
    };
    let mut versions = BTreeMap::new();
    for event in events {
        match event.kind() {
            "variable_declarator" => {
                let name = event
                    .child_by_field_name("name")
                    .and_then(|node| simple_binding_name(node, unit.content));
                let value = event.child_by_field_name("value");
                if let (Some(name), Some(value)) = (name, value) {
                    let next = evaluate_helper_expression(unit, value, &variables, &helper_scope);
                    assign(
                        &mut variables,
                        &mut versions,
                        name,
                        next,
                        event,
                        &helper_scope,
                        unit.path,
                    );
                }
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                let left = event.child_by_field_name("left");
                let right = event.child_by_field_name("right");
                let name = left.and_then(|node| simple_binding_name(node, unit.content));
                if let (Some(name), Some(value)) = (name, right) {
                    let next = evaluate_helper_expression(unit, value, &variables, &helper_scope);
                    assign(
                        &mut variables,
                        &mut versions,
                        name,
                        next,
                        event,
                        &helper_scope,
                        unit.path,
                    );
                }
            }
            "return_statement" => {
                let returned = named_children(event).into_iter().next()?;
                let mut lineage = resolve_lineage(returned, unit.content, &variables)?;
                let returned_value = ValueId {
                    definition: DefinitionId {
                        scope: caller_scope.clone(),
                        definition_span: span(event),
                    },
                    version: 0,
                };
                lineage.edges.push(FlowEdge {
                    kind: FlowEdgeKind::Propagates,
                    input: lineage.value,
                    output: returned_value.clone(),
                    location: location(unit.path, event),
                });
                lineage.value = returned_value;
                return Some(lineage);
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn evaluate_helper_expression(
    unit: &ParsedUnit<'_>,
    value: Node<'_>,
    variables: &BTreeMap<String, Lineage>,
    helper_scope: &ScopeId,
) -> Option<Lineage> {
    let unwrapped = unwrap_expression(value);
    if unwrapped.kind() == "identifier" {
        variables.get(text(unwrapped, unit.content)).cloned()
    } else if resolved_file_read_api(unit, unwrapped).is_some() {
        let path = call_arguments(unwrapped)
            .into_iter()
            .next()
            .and_then(|node| resolve_lineage(node, unit.content, variables));
        path.map(|path| {
            let output = ValueId {
                definition: DefinitionId {
                    scope: helper_scope.clone(),
                    definition_span: span(value),
                },
                version: 0,
            };
            let loc = location(unit.path, value);
            let mut edges = path.edges;
            edges.push(FlowEdge {
                kind: FlowEdgeKind::ControlsFilePath,
                input: path.tool_argument.clone(),
                output: path.value.clone(),
                location: loc.clone(),
            });
            edges.push(FlowEdge {
                kind: FlowEdgeKind::ProducesFileContent,
                input: path.value,
                output: output.clone(),
                location: loc,
            });
            Lineage {
                value: output,
                tool_argument: path.tool_argument,
                source_location: path.source_location,
                edges,
                is_file_content: true,
                source_anchor: Some(AnchorSeed {
                    key: AnchorKey {
                        file: unit.path.to_path_buf(),
                        owner: helper_scope.lexical_owner.clone(),
                        operation: "file_read",
                        api: "fs.read",
                        hash: normalized_subtree_hash(value, unit.content),
                    },
                    occurrence: span(value),
                }),
            }
        })
    } else {
        None
    }
}

pub(crate) fn helper_seeds(
    function: Node<'_>,
    function_path: &Path,
    function_source: &str,
    actuals: &[Node<'_>],
    caller_source: &str,
    caller_variables: &BTreeMap<String, Lineage>,
) -> BTreeMap<String, Lineage> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return BTreeMap::new();
    };
    named_children(parameters)
        .into_iter()
        .zip(actuals.iter().copied())
        .filter_map(|(formal, actual)| {
            let mut lineage = resolve_lineage(actual, caller_source, caller_variables)?;
            let formal_value = ValueId {
                definition: DefinitionId {
                    scope: ScopeId {
                        relative_file: function_path.to_path_buf(),
                        lexical_owner: function_name(function, function_source)
                            .unwrap_or_else(|| "<anonymous-helper>".into()),
                    },
                    definition_span: span(formal),
                },
                version: 0,
            };
            lineage.edges.push(FlowEdge {
                kind: FlowEdgeKind::Propagates,
                input: lineage.value,
                output: formal_value.clone(),
                location: location(function_path, formal),
            });
            lineage.value = formal_value;
            Some(
                binding_names(formal, function_source)
                    .into_iter()
                    .map(move |name| (name, lineage.clone())),
            )
        })
        .flatten()
        .collect()
}
