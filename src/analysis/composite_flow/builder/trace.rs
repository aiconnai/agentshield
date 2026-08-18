use std::collections::BTreeMap;
use tree_sitter::Node;

use super::super::ast::{
    call_arguments, call_name, collect_events, function_body, location, named_children,
    normalized_subtree_hash, simple_binding_name, span, text, unwrap_expression,
};
use super::super::guard::{
    contains_opaque_control_flow, has_ambiguous_shadowing, has_containment_guard,
};
use super::super::types::{
    CompositeFlowCandidate, DefinitionId, FlowEdge, FlowEdgeKind, ScopeId, ValueId,
};
use super::helper::{analyze_helper_return, helper_seeds};
use super::parse::unique_function;
use super::resolve::{
    assign, first_parameter_names, resolve_lineage, resolved_file_read_api,
    resolved_network_payload,
};
use super::types::{AnchorKey, AnchorSeed, Analyzer, Lineage};

impl Analyzer<'_> {
    pub(crate) fn analyze_function(
        &mut self,
        unit_index: usize,
        function: Node<'_>,
        owner: String,
        seed: Option<BTreeMap<String, Lineage>>,
        depth: usize,
    ) -> Vec<CompositeFlowCandidate> {
        let unit = &self.units[unit_index];
        let scope = ScopeId {
            relative_file: unit.path.to_path_buf(),
            lexical_owner: owner.clone(),
        };
        let parameter_names = first_parameter_names(function, unit.content);
        if parameter_names.is_empty() && seed.is_none() {
            return Vec::new();
        }

        let mut variables = BTreeMap::<String, Lineage>::new();
        if let Some(seed) = seed {
            variables.extend(seed);
        } else {
            let parameter_node = function
                .child_by_field_name("parameters")
                .and_then(|parameters| named_children(parameters).into_iter().next());
            let span_val = function
                .child_by_field_name("parameters")
                .map(span)
                .unwrap_or_else(|| span(function));
            let value = ValueId {
                definition: DefinitionId {
                    scope: scope.clone(),
                    definition_span: span_val,
                },
                version: 0,
            };
            let tool_argument = Lineage {
                value: value.clone(),
                tool_argument: value,
                source_location: location(unit.path, parameter_node.unwrap_or(function)),
                edges: Vec::new(),
                is_file_content: false,
                source_anchor: None,
            };
            for parameter in parameter_names {
                variables.insert(parameter, tool_argument.clone());
            }
        }

        let Some(body) = function_body(function) else {
            return Vec::new();
        };
        if contains_opaque_control_flow(body, true)
            || has_ambiguous_shadowing(function, unit.content)
        {
            return Vec::new();
        }
        let mut events = Vec::new();
        collect_events(body, body, &mut events);
        events.sort_by_key(Node::start_byte);

        let mut candidates = Vec::new();
        let mut versions = BTreeMap::<String, u32>::new();
        for event in events {
            match event.kind() {
                "variable_declarator" => {
                    let Some(name_node) = event.child_by_field_name("name") else {
                        continue;
                    };
                    let Some(name) = simple_binding_name(name_node, unit.content) else {
                        continue;
                    };
                    let Some(value_node) = event.child_by_field_name("value") else {
                        variables.remove(&name);
                        continue;
                    };
                    let next = self.evaluate_expression(
                        unit_index,
                        value_node,
                        &scope,
                        &owner,
                        &variables,
                        &mut candidates,
                        depth,
                    );
                    assign(
                        &mut variables,
                        &mut versions,
                        name,
                        next,
                        event,
                        &scope,
                        unit.path,
                    );
                }
                "assignment_expression" | "augmented_assignment_expression" => {
                    let Some(left) = event.child_by_field_name("left") else {
                        continue;
                    };
                    let Some(name) = simple_binding_name(left, unit.content) else {
                        continue;
                    };
                    let next = event.child_by_field_name("right").and_then(|right| {
                        self.evaluate_expression(
                            unit_index,
                            right,
                            &scope,
                            &owner,
                            &variables,
                            &mut candidates,
                            depth,
                        )
                    });
                    assign(
                        &mut variables,
                        &mut versions,
                        name,
                        next,
                        event,
                        &scope,
                        unit.path,
                    );
                }
                "call_expression" => {
                    self.handle_network_or_helper(
                        unit_index,
                        event,
                        &owner,
                        &variables,
                        &mut candidates,
                        depth,
                    );
                }
                _ => {}
            }
        }
        candidates
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Refactoring this method would trade readability for signature complexity in this IR walk."
    )]
    pub(crate) fn evaluate_expression(
        &mut self,
        unit_index: usize,
        expression: Node<'_>,
        scope: &ScopeId,
        owner: &str,
        variables: &BTreeMap<String, Lineage>,
        candidates: &mut Vec<CompositeFlowCandidate>,
        depth: usize,
    ) -> Option<Lineage> {
        let unit = &self.units[unit_index];
        let expression = unwrap_expression(expression);
        if expression.kind() == "identifier" {
            return variables.get(text(expression, unit.content)).cloned();
        }
        if expression.kind() == "member_expression" {
            let object = expression.child_by_field_name("object")?;
            if object.kind() == "identifier" {
                return variables.get(text(object, unit.content)).cloned();
            }
        }
        if expression.kind() != "call_expression" {
            return None;
        }

        if let Some(api) = resolved_file_read_api(unit, expression) {
            let path_expression = call_arguments(expression).into_iter().next()?;
            let path_lineage = resolve_lineage(path_expression, unit.content, variables)?;
            if has_containment_guard(
                unit.content,
                path_expression.start_byte(),
                text(path_expression, unit.content),
            ) {
                return None;
            }
            let output = ValueId {
                definition: DefinitionId {
                    scope: scope.clone(),
                    definition_span: span(expression),
                },
                version: 0,
            };
            let read_location = location(unit.path, expression);
            let mut edges = path_lineage.edges.clone();
            edges.push(FlowEdge {
                kind: FlowEdgeKind::ControlsFilePath,
                input: path_lineage.tool_argument.clone(),
                output: path_lineage.value.clone(),
                location: read_location.clone(),
            });
            edges.push(FlowEdge {
                kind: FlowEdgeKind::ProducesFileContent,
                input: path_lineage.value,
                output: output.clone(),
                location: read_location,
            });
            return Some(Lineage {
                value: output,
                tool_argument: path_lineage.tool_argument,
                source_location: path_lineage.source_location,
                edges,
                is_file_content: true,
                source_anchor: Some(AnchorSeed {
                    key: AnchorKey {
                        file: unit.path.to_path_buf(),
                        owner: owner.to_string(),
                        operation: "file_read",
                        api,
                        hash: normalized_subtree_hash(expression, unit.content),
                    },
                    occurrence: span(expression),
                }),
            });
        }

        if depth == 0 {
            let callee = call_name(expression, unit.content)?;
            let matches = unique_function(&callee, self.units, unit_index)?;
            let seeds = helper_seeds(
                matches.node,
                self.units[matches.unit_index].path,
                self.units[matches.unit_index].content,
                &call_arguments(expression),
                unit.content,
                variables,
            );
            if seeds.is_empty() {
                return None;
            }
            let returned =
                analyze_helper_return(&self.units[matches.unit_index], matches.node, seeds, scope)?;
            return Some(returned);
        }

        let _ = (owner, candidates);
        None
    }

    pub(crate) fn handle_network_or_helper(
        &mut self,
        unit_index: usize,
        call: Node<'_>,
        owner: &str,
        variables: &BTreeMap<String, Lineage>,
        candidates: &mut Vec<CompositeFlowCandidate>,
        depth: usize,
    ) {
        let unit = &self.units[unit_index];
        if let Some((api, payload)) = resolved_network_payload(unit, call) {
            let Some(lineage) = resolve_lineage(payload, unit.content, variables) else {
                return;
            };
            if !lineage.is_file_content {
                return;
            }
            let sink_value = ValueId {
                definition: DefinitionId {
                    scope: ScopeId {
                        relative_file: unit.path.to_path_buf(),
                        lexical_owner: owner.to_string(),
                    },
                    definition_span: span(payload),
                },
                version: 0,
            };
            let sink_location = location(unit.path, call);
            let mut edges = lineage.edges.clone();
            edges.push(FlowEdge {
                kind: FlowEdgeKind::EntersNetworkPayload,
                input: lineage.value,
                output: sink_value,
                location: sink_location.clone(),
            });
            let Some(source_key) = lineage.source_anchor else {
                return;
            };
            let source_anchor = self.anchor_from_key(source_key);
            let sink_anchor = self.anchor(unit_index, owner, "network_payload", api, call);
            candidates.push(CompositeFlowCandidate {
                tool_name: self.tool_name.to_string(),
                source_location: lineage.source_location,
                sink_location,
                source_anchor,
                sink_anchor,
                edges,
                observation_complete: true,
            });
            return;
        }

        if depth != 0 {
            return;
        }
        let Some(callee) = call_name(call, unit.content) else {
            return;
        };
        let Some(function) = unique_function(&callee, self.units, unit_index) else {
            return;
        };
        let seeds = helper_seeds(
            function.node,
            self.units[function.unit_index].path,
            self.units[function.unit_index].content,
            &call_arguments(call),
            unit.content,
            variables,
        );
        if seeds.is_empty() {
            return;
        }
        candidates.extend(self.analyze_function(
            function.unit_index,
            function.node,
            function.owner,
            Some(seeds),
            depth + 1,
        ));
    }
}
