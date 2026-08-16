use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[cfg(feature = "typescript")]
use tree_sitter::Parser;
use tree_sitter::{Node, Tree};

use crate::ir::SourceLocation;

use super::ast::{
    binding_names, call_arguments, call_name, collect_events, function_body, function_is_top_level,
    function_name, is_exported_function, is_function, location, location_for_node, named_children,
    normalized_subtree_hash, object_property, relative_import_targets, simple_binding_name, span,
    text, unwrap_expression, walk,
};
use super::guard::{
    contains_opaque_control_flow, global_name_shadowed, has_ambiguous_shadowing,
    has_containment_guard, top_level_return_count,
};
use super::types::{
    ByteSpan, CompositeFlowCandidate, DefinitionId, FlowEdge, FlowEdgeKind, ScopeId,
    SemanticAnchor, SourceUnit, ToolFlowInput, ValueId,
};

pub(crate) struct ParsedUnit<'a> {
    pub(crate) path: &'a Path,
    pub(crate) content: &'a str,
    pub(crate) tree: Tree,
    pub(crate) imports: Imports,
}

#[derive(Default)]
pub(crate) struct Imports {
    pub(crate) fs_read_functions: BTreeSet<String>,
    pub(crate) fs_namespaces: BTreeSet<String>,
    pub(crate) axios_names: BTreeSet<String>,
    pub(crate) local_functions: BTreeMap<String, RelativeImport>,
}

#[derive(Clone)]
pub(crate) struct RelativeImport {
    pub(crate) module: String,
    pub(crate) exported: String,
}

#[derive(Clone)]
pub(crate) struct Lineage {
    pub(crate) value: ValueId,
    pub(crate) tool_argument: ValueId,
    pub(crate) source_location: SourceLocation,
    pub(crate) edges: Vec<FlowEdge>,
    pub(crate) is_file_content: bool,
    pub(crate) source_anchor: Option<AnchorSeed>,
}

pub(crate) struct Analyzer<'a> {
    pub(crate) units: &'a [ParsedUnit<'a>],
    pub(crate) tool_name: &'a str,
    pub(crate) anchor_ordinals: BTreeMap<AnchorKey, usize>,
    pub(crate) anchor_instances: BTreeMap<AnchorSeed, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AnchorKey {
    pub(crate) file: PathBuf,
    pub(crate) owner: String,
    pub(crate) operation: &'static str,
    pub(crate) api: &'static str,
    pub(crate) hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AnchorSeed {
    pub(crate) key: AnchorKey,
    pub(crate) occurrence: ByteSpan,
}

pub(crate) struct FunctionMatch<'tree> {
    pub(crate) unit_index: usize,
    pub(crate) node: Node<'tree>,
    pub(crate) owner: String,
}

pub(crate) fn build(
    tools: &[ToolFlowInput],
    sources: &[SourceUnit<'_>],
) -> Vec<CompositeFlowCandidate> {
    let units = parse_units(sources);
    let mut candidates = Vec::new();

    for tool in tools {
        let Some((unit_index, handler)) = find_node_for_location(&units, &tool.handler) else {
            continue;
        };
        let owner = function_name(handler, units[unit_index].content)
            .unwrap_or_else(|| format!("<inline:{}>", handler.start_byte()));
        let mut analyzer = Analyzer {
            units: &units,
            tool_name: &tool.tool_name,
            anchor_ordinals: BTreeMap::new(),
            anchor_instances: BTreeMap::new(),
        };
        candidates.extend(analyzer.analyze_function(unit_index, handler, owner, None, 0));
    }

    candidates.sort_by(|left, right| {
        (
            &left.tool_name,
            &left.source_location.file,
            left.source_location.line,
            left.source_location.column,
            &left.sink_location.file,
            left.sink_location.line,
            left.sink_location.column,
        )
            .cmp(&(
                &right.tool_name,
                &right.source_location.file,
                right.source_location.line,
                right.source_location.column,
                &right.sink_location.file,
                right.sink_location.line,
                right.sink_location.column,
            ))
    });
    candidates
}

#[cfg(feature = "typescript")]
pub(crate) fn parse_units<'a>(sources: &[SourceUnit<'a>]) -> Vec<ParsedUnit<'a>> {
    sources
        .iter()
        .filter_map(|source| {
            let mut parser = Parser::new();
            let language = if source
                .path
                .extension()
                .is_some_and(|extension| extension == "tsx")
            {
                tree_sitter_typescript::LANGUAGE_TSX
            } else {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT
            };
            parser.set_language(&language.into()).ok()?;
            let tree = parser.parse(source.content, None)?;
            Some(ParsedUnit {
                path: source.path,
                content: source.content,
                imports: collect_imports(tree.root_node(), source.content),
                tree,
            })
        })
        .collect()
}

#[cfg(not(feature = "typescript"))]
pub(crate) fn parse_units<'a>(_sources: &[SourceUnit<'a>]) -> Vec<ParsedUnit<'a>> {
    Vec::new()
}

pub(crate) fn collect_imports(root: Node<'_>, source: &str) -> Imports {
    let mut imports = Imports::default();
    walk(root, &mut |node| {
        if node.kind() != "import_statement" {
            return;
        }
        let import_text = text(node, source);
        let Some(module) = import_module(node, source) else {
            return;
        };
        let is_fs = matches!(
            module.as_str(),
            "fs" | "fs/promises" | "node:fs" | "node:fs/promises"
        );
        if is_fs {
            if let Some((clause, _)) = import_text.split_once(" from ") {
                let clause = clause.trim_start_matches("import").trim();
                if let Some(namespace) = clause.strip_prefix("* as ") {
                    imports.fs_namespaces.insert(namespace.trim().to_string());
                }
                if let Some(named) = clause
                    .strip_prefix('{')
                    .and_then(|value| value.strip_suffix('}'))
                {
                    for import in named.split(',').map(str::trim) {
                        let mut parts = import.split_whitespace();
                        let Some(imported) = parts.next() else {
                            continue;
                        };
                        if matches!(imported, "readFile" | "readFileSync") {
                            let local = match (parts.next(), parts.next()) {
                                (Some("as"), Some(alias)) => alias,
                                _ => imported,
                            };
                            imports.fs_read_functions.insert(local.to_string());
                        }
                    }
                }
            }
        }
        if module == "axios" {
            if let Some((clause, _)) = import_text.split_once(" from ") {
                let local = clause.trim_start_matches("import").trim();
                if !local.is_empty() && !local.starts_with(['{', '*']) {
                    imports.axios_names.insert(local.to_string());
                }
            }
        }
        if module.starts_with('.') {
            for (exported, local) in named_imports(import_text) {
                imports.local_functions.insert(
                    local,
                    RelativeImport {
                        module: module.clone(),
                        exported,
                    },
                );
            }
        }
    });
    imports
}

pub(crate) fn import_module(node: Node<'_>, source: &str) -> Option<String> {
    let module = node.child_by_field_name("source")?;
    Some(text(module, source).trim_matches(['\'', '"']).to_string())
}

pub(crate) fn named_imports(import_text: &str) -> Vec<(String, String)> {
    let Some(start) = import_text.find('{') else {
        return Vec::new();
    };
    let Some(end) = import_text[start + 1..]
        .find('}')
        .map(|offset| start + 1 + offset)
    else {
        return Vec::new();
    };
    import_text[start + 1..end]
        .split(',')
        .filter_map(|item| {
            let mut parts = item.split_whitespace();
            let exported = parts.next()?.to_string();
            let local = match (parts.next(), parts.next()) {
                (Some("as"), Some(alias)) => alias.to_string(),
                _ => exported.clone(),
            };
            Some((exported, local))
        })
        .collect()
}

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

    pub(crate) fn anchor(
        &mut self,
        unit_index: usize,
        owner: &str,
        operation: &'static str,
        api: &'static str,
        node: Node<'_>,
    ) -> SemanticAnchor {
        let unit = &self.units[unit_index];
        let hash = normalized_subtree_hash(node, unit.content);
        let key = AnchorKey {
            file: unit.path.to_path_buf(),
            owner: owner.to_string(),
            operation,
            api,
            hash: hash.clone(),
        };
        let ordinal = self.anchor_ordinals.entry(key).or_default();
        let current = *ordinal;
        *ordinal += 1;
        SemanticAnchor {
            relative_file: unit.path.to_path_buf(),
            lexical_owner: owner.to_string(),
            operation_kind: operation,
            resolved_api: api,
            normalized_subtree_hash: hash,
            identical_ordinal: current,
        }
    }

    pub(crate) fn anchor_from_key(&mut self, seed: AnchorSeed) -> SemanticAnchor {
        let current = if let Some(ordinal) = self.anchor_instances.get(&seed) {
            *ordinal
        } else {
            let ordinal = self.anchor_ordinals.entry(seed.key.clone()).or_default();
            let current = *ordinal;
            *ordinal += 1;
            self.anchor_instances.insert(seed.clone(), current);
            current
        };
        let key = seed.key;
        SemanticAnchor {
            relative_file: key.file,
            lexical_owner: key.owner,
            operation_kind: key.operation,
            resolved_api: key.api,
            normalized_subtree_hash: key.hash,
            identical_ordinal: current,
        }
    }
}

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

fn evaluate_helper_expression(
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

pub(crate) fn find_node_for_location<'tree>(
    units: &'tree [ParsedUnit<'_>],
    location: &SourceLocation,
) -> Option<(usize, Node<'tree>)> {
    let (index, unit) = units
        .iter()
        .enumerate()
        .find(|(_, unit)| unit.path == location.file)?;
    let mut best = None;
    walk(unit.tree.root_node(), &mut |node| {
        if !is_function(node) {
            return;
        }
        let node_location = location_for_node(node);
        if node_location.0 == location.line && node_location.1 == location.column && best.is_none()
        {
            best = Some(node);
        }
    });
    best.map(|node| (index, node))
}

pub(crate) fn unique_function<'tree>(
    name: &str,
    units: &'tree [ParsedUnit<'_>],
    caller_unit_index: usize,
) -> Option<FunctionMatch<'tree>> {
    if name.contains('.') {
        return None;
    }
    let caller = &units[caller_unit_index];
    let same_file = functions_named(name, caller_unit_index, caller);
    if same_file.len() == 1 {
        return same_file.into_iter().next();
    }
    if !same_file.is_empty() {
        return None;
    }

    let import = caller.imports.local_functions.get(name)?;
    let mut matches = Vec::new();
    for (unit_index, unit) in units.iter().enumerate() {
        if unit_index == caller_unit_index
            || !relative_import_targets(caller.path, &import.module, unit.path)
        {
            continue;
        }
        walk(unit.tree.root_node(), &mut |node| {
            if is_function(node)
                && function_is_top_level(node)
                && is_exported_function(node)
                && function_name(node, unit.content).as_deref() == Some(&import.exported)
            {
                matches.push(FunctionMatch {
                    unit_index,
                    node,
                    owner: import.exported.clone(),
                });
            }
        });
    }
    (matches.len() == 1).then(|| matches.remove(0))
}

pub(crate) fn functions_named<'tree>(
    name: &str,
    unit_index: usize,
    unit: &'tree ParsedUnit<'_>,
) -> Vec<FunctionMatch<'tree>> {
    let mut matches = Vec::new();
    walk(unit.tree.root_node(), &mut |node| {
        if is_function(node)
            && function_is_top_level(node)
            && function_name(node, unit.content).as_deref() == Some(name)
        {
            matches.push(FunctionMatch {
                unit_index,
                node,
                owner: name.to_string(),
            });
        }
    });
    matches
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
