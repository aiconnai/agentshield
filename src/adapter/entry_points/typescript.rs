//! Vercel AI SDK `tool({ execute })` handler references.
//!
//! A named `execute` function is invoked by the model, so internal call sites
//! must not clear it. Inline `execute` functions are analysed in place and
//! are skipped: forwarding calls such as `(args) => run(args.cmd)` already
//! carry an agent-controlled argument.

use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use super::{References, follow_assignments};
use crate::adapter::mcp::tools::handlers::{import_aliases, js_identifiers};
use crate::adapter::mcp::tools::scan::{
    find_matching_delimiter, is_inline_handler, top_level_segments,
};

/// `ai` exports that wrap an `execute` handler.
const TOOL_FACTORIES: &[&str] = &["tool", "dynamicTool"];

/// Upper bound on tool calls scanned per file; each scan is linear in the
/// call's size, so nesting could otherwise be made quadratic. Exceeding it
/// makes the caller treat every function in the file as an entry point.
const MAX_TOOL_CALLS: usize = 256;

static TOOL_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*(?:<[^(){};]*>)?\s*\(")
        .expect("tool call regex is valid")
});

static NAMESPACE_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*["']ai["']"#)
        .expect("namespace import regex is valid")
});

static ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*([^;\n]+)")
        .expect("assignment regex is valid")
});

/// Names that may identify the `execute` handler of each `tool({...})` call.
pub(crate) fn vercel_execute_references(content: &str) -> References {
    let aliases = import_aliases(content);
    let factories = factory_names(&aliases);
    let namespaces: HashSet<&str> = NAMESPACE_IMPORT_RE
        .captures_iter(content)
        .filter_map(|captures| captures.get(1).map(|m| m.as_str()))
        .collect();

    let mut references = References::default();
    let mut calls = 0;
    for captures in TOOL_CALL_RE.captures_iter(content) {
        let whole = captures.get(0).expect("whole match");
        if !is_factory_call(content, &captures, &factories, &namespaces) {
            continue;
        }
        calls += 1;
        if calls > MAX_TOOL_CALLS {
            references.exhausted = true;
            break;
        }
        let open = whole.end() - 1;
        let Some(close) = find_matching_delimiter(content, open, b'(', b')') else {
            continue;
        };
        for (start, end) in top_level_segments(content, open + 1, close) {
            if content[start..end].starts_with('{') {
                collect_execute(content, start, &mut references);
            }
        }
    }

    for name in references.names.clone() {
        if let Some(original) = aliases.get(&name) {
            references.names.insert(original.clone());
        }
    }
    follow_assignments(&mut references.names, &assignments(content));
    references
}

/// Local names bound to an `ai` tool factory, including `import { tool as t }`.
fn factory_names(aliases: &HashMap<String, String>) -> HashSet<String> {
    let mut names: HashSet<String> = TOOL_FACTORIES.iter().map(|n| n.to_string()).collect();
    names.extend(
        aliases
            .iter()
            .filter(|(_, imported)| TOOL_FACTORIES.contains(&imported.as_str()))
            .map(|(local, _)| local.clone()),
    );
    names
}

fn is_factory_call(
    content: &str,
    captures: &regex::Captures<'_>,
    factories: &HashSet<String>,
    namespaces: &HashSet<&str>,
) -> bool {
    let name = &captures[2];
    match captures.get(1) {
        Some(namespace) => {
            namespaces.contains(namespace.as_str()) && TOOL_FACTORIES.contains(&name)
        }
        None => {
            let start = captures.get(0).map_or(0, |m| m.start());
            factories.contains(name) && !content[..start].trim_end().ends_with('.')
        }
    }
}

/// Record the `execute` property of the object literal starting at `start`.
fn collect_execute(content: &str, start: usize, references: &mut References) {
    let Some(end) = find_matching_delimiter(content, start, b'{', b'}') else {
        return;
    };
    for (prop_start, prop_end) in top_level_segments(content, start + 1, end) {
        let property = &content[prop_start..prop_end];
        let Some(rest) = property.strip_prefix("execute") else {
            continue;
        };
        if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
            continue;
        }
        let rest = rest.trim_start();
        if rest.is_empty() {
            // `{ execute }` shorthand: resolved through its declaration.
            references.names.insert("execute".to_string());
        } else if let Some(value) = rest.strip_prefix(':') {
            collect_named_handler(value.trim(), references);
        }
        // `execute(args) { ... }` is an inline method and needs no marking.
    }
}

fn collect_named_handler(value: &str, references: &mut References) {
    if !is_inline_handler(value) {
        references
            .names
            .extend(js_identifiers(value).map(str::to_string));
    }
}

/// `const name = expression` declarations, as the identifiers each expression
/// references (inline functions excluded).
fn assignments(content: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for captures in ASSIGNMENT_RE.captures_iter(content) {
        let value = captures[2].trim();
        if is_inline_handler(value) {
            continue;
        }
        map.entry(captures[1].to_string())
            .or_default()
            .extend(js_identifiers(value).map(str::to_string));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(content: &str) -> Vec<String> {
        let mut names: Vec<_> = vercel_execute_references(content)
            .names
            .into_iter()
            .collect();
        names.sort();
        names
    }

    #[test]
    fn named_bound_and_wrapped_execute_references() {
        assert_eq!(names("tool({ description: \"d\", execute: run })"), ["run"]);
        assert!(names("tool({ execute: run.bind(null) })").contains(&"run".to_string()));
        assert!(names("tool({ execute: withLog(run) })").contains(&"run".to_string()));
        assert_eq!(names("tool({ execute: ns.run })"), ["ns", "run"]);
    }

    #[test]
    fn inline_execute_references_nothing() {
        assert!(names("tool({ execute: async (args) => run(args.cmd) })").is_empty());
        assert!(names("tool({ execute: async function (a) { return run(a); } })").is_empty());
        assert!(names("tool({ async execute(a) { return run(a); } })").is_empty());
        assert!(names("tool({ execute(a) { return run(a); } })").is_empty());
    }

    #[test]
    fn shorthand_follows_its_declaration() {
        let found = names("const execute = run;\ntool({ description: \"d\", execute });");
        assert!(found.contains(&"run".to_string()));
        assert!(found.contains(&"execute".to_string()));
    }

    #[test]
    fn variable_aliases_are_followed() {
        let found = names("const handler = run;\ntool({ execute: handler });");
        assert!(found.contains(&"run".to_string()));
    }

    #[test]
    fn aliased_and_namespaced_factories() {
        assert_eq!(
            names("import { tool as define } from \"ai\";\ndefine({ execute: a });"),
            ["a"]
        );
        assert_eq!(
            names("import * as ai from \"ai\";\nai.tool({ execute: b });"),
            ["b"]
        );
        assert_eq!(names("dynamicTool({ execute: c });"), ["c"]);
        assert_eq!(names("tool<Args, Out>({ execute: d });"), ["d"]);
    }

    #[test]
    fn other_calls_reference_nothing() {
        assert!(names("server.tool(\"a\", { execute: run });").is_empty());
        assert!(names("other({ execute: run });\nx.tool({ execute: run });").is_empty());
        assert!(names("tool({ description: \"executed\", parameters: p });").is_empty());
    }

    #[test]
    fn nested_tool_calls_do_not_stall() {
        let content = format!("{}x{}", "tool(".repeat(20_000), ")".repeat(20_000));
        let started = std::time::Instant::now();
        let references = vercel_execute_references(&content);
        assert!(references.exhausted);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
