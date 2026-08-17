use tree_sitter::Node;

#[cfg(feature = "typescript")]
use tree_sitter::Parser;

use crate::ir::SourceLocation;

use super::super::ast::{
    function_is_top_level, function_name, is_exported_function, is_function, location_for_node,
    relative_import_targets, text, walk,
};
use super::super::types::SourceUnit;
use super::types::{FunctionMatch, Imports, ParsedUnit, RelativeImport};

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
