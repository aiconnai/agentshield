use std::collections::BTreeMap;
use std::path::Path;
use tree_sitter::Node;

use super::super::ast::{
    binding_names, call_arguments, call_name, location, named_children, object_property, span,
    text, unwrap_expression,
};
use super::super::guard::global_name_shadowed;
use super::super::types::{DefinitionId, FlowEdge, FlowEdgeKind, ScopeId, ValueId};
use super::types::{Lineage, ParsedUnit};

pub(crate) fn assign(
    variables: &mut BTreeMap<String, Lineage>,
    versions: &mut BTreeMap<String, u32>,
    name: String,
    next: Option<Lineage>,
    definition: Node<'_>,
    scope: &ScopeId,
    path: &Path,
) {
    let version = versions.entry(name.clone()).or_default();
    let Some(mut lineage) = next else {
        *version += 1;
        variables.remove(&name);
        return;
    };
    let new_value = ValueId {
        definition: DefinitionId {
            scope: scope.clone(),
            definition_span: span(definition),
        },
        version: *version,
    };
    let produced_directly_into_binding = lineage.is_file_content
        && lineage
            .edges
            .last()
            .is_some_and(|edge| edge.kind == FlowEdgeKind::ProducesFileContent)
        && lineage.value.definition.definition_span.start >= definition.start_byte()
        && lineage.value.definition.definition_span.end <= definition.end_byte();
    if produced_directly_into_binding {
        if let Some(edge) = lineage.edges.last_mut() {
            edge.output = new_value.clone();
        }
        lineage.value = new_value;
    } else if lineage.value != new_value {
        lineage.edges.push(FlowEdge {
            kind: FlowEdgeKind::Propagates,
            input: lineage.value,
            output: new_value.clone(),
            location: location(path, definition),
        });
        lineage.value = new_value;
    }
    variables.insert(name, lineage);
    *version += 1;
}

pub(crate) fn resolved_file_read_api(
    unit: &ParsedUnit<'_>,
    expression: Node<'_>,
) -> Option<&'static str> {
    let expression = unwrap_expression(expression);
    if expression.kind() != "call_expression" {
        return None;
    }
    let function = expression.child_by_field_name("function")?;
    let name = text(function, unit.content).replace([' ', '\n'], "");
    if unit.imports.fs_read_functions.contains(&name) {
        return (!global_name_shadowed(unit, &name)).then_some("fs.read");
    }
    let (namespace, method) = name.split_once('.')?;
    (unit.imports.fs_namespaces.contains(namespace)
        && !global_name_shadowed(unit, namespace)
        && matches!(method, "readFile" | "readFileSync"))
    .then_some("fs.read")
}

pub(crate) fn resolved_network_payload<'tree>(
    unit: &ParsedUnit<'_>,
    call: Node<'tree>,
) -> Option<(&'static str, Node<'tree>)> {
    let name = call_name(call, unit.content)?;
    let arguments = call_arguments(call);
    if name == "fetch" && !global_name_shadowed(unit, "fetch") {
        let options = *arguments.get(1)?;
        return object_property(options, unit.content, "body").map(|body| ("global.fetch", body));
    }
    let (receiver, method) = name.split_once('.')?;
    if unit.imports.axios_names.contains(receiver)
        && !global_name_shadowed(unit, receiver)
        && method == "post"
    {
        return arguments.get(1).copied().map(|body| ("axios.post", body));
    }
    None
}

pub(crate) fn resolve_lineage(
    expression: Node<'_>,
    source: &str,
    variables: &BTreeMap<String, Lineage>,
) -> Option<Lineage> {
    let expression = unwrap_expression(expression);
    match expression.kind() {
        "identifier" | "shorthand_property_identifier" => {
            variables.get(text(expression, source)).cloned()
        }
        "member_expression" => {
            let object = expression.child_by_field_name("object")?;
            variables.get(text(object, source)).cloned()
        }
        _ => None,
    }
}

pub(crate) fn first_parameter_names(function: Node<'_>, source: &str) -> Vec<String> {
    let parameters = function.child_by_field_name("parameters");
    let Some(parameters) = parameters else {
        return Vec::new();
    };
    let Some(first) = named_children(parameters).into_iter().next() else {
        return Vec::new();
    };
    binding_names(first, source)
}
