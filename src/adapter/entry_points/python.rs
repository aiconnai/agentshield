//! Python agent entry points declared through framework API calls and
//! tool base classes (the decorator form lives in the Python parser).
//!
//! Everything here works on source text with strings and comments masked, so
//! registration-looking text in a docstring or comment marks nothing. The
//! extraction is deliberately over-inclusive: every identifier in a function
//! argument counts as a reference, because marking an extra function only
//! weakens a downgrade and never hides a finding.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

use super::{References, follow_assignments};
use crate::parser::python::defs::{TOOL_DECORATORS, mask_strings_and_comments};

/// Upper bound on argument text scanned per file. Exceeding it (only
/// reachable with adversarial nesting) makes the caller treat every function
/// in the file as an entry point instead of silently skipping registrations.
const MAX_SCANNED_BYTES: usize = 16 * 1024 * 1024;

/// How a registering call references the agent-facing function.
struct Registration {
    /// Dotted callee suffix, matched on segment boundaries.
    callee: &'static str,
    /// Positional argument indexes that hold a function.
    positional: &'static [usize],
    /// Keyword arguments that hold a function.
    keywords: &'static [&'static str],
}

const REGISTRATIONS: &[Registration] = &[
    // LlamaIndex
    Registration {
        callee: "FunctionTool.from_defaults",
        positional: &[0],
        keywords: &["fn", "async_fn"],
    },
    Registration {
        callee: "FunctionTool",
        positional: &[0],
        keywords: &["fn", "func", "async_fn"],
    },
    // LangChain
    Registration {
        callee: "StructuredTool.from_function",
        positional: &[0],
        keywords: &["func", "coroutine"],
    },
    Registration {
        callee: "StructuredTool",
        positional: &[],
        keywords: &["func", "coroutine"],
    },
    Registration {
        callee: "Tool.from_function",
        positional: &[0],
        keywords: &["func", "coroutine"],
    },
    Registration {
        callee: "Tool",
        positional: &[1],
        keywords: &["func", "coroutine"],
    },
    // AutoGen
    Registration {
        callee: "register_function",
        positional: &[0],
        keywords: &["f"],
    },
    // FastMCP and similar `add_tool(fn)` registries
    Registration {
        callee: "add_tool",
        positional: &[0],
        keywords: &["fn"],
    },
];

/// Base classes whose subclasses are agent tools (LangChain, CrewAI,
/// LlamaIndex, AutoGen).
const TOOL_BASES: &[&str] = &[
    "BaseTool",
    "AsyncBaseTool",
    "StructuredTool",
    "Tool",
    "FunctionTool",
    "QueryEngineTool",
    "BaseStreamTool",
];

/// Methods through which the agent invokes a tool class.
const TOOL_ENTRY_METHODS: &[&str] = &[
    "_run", "_arun", "run", "arun", "call", "acall", "invoke", "ainvoke", "_call", "_acall",
    "__call__",
];

const NOT_A_FUNCTION: &[&str] = &[
    "None", "True", "False", "self", "cls", "lambda", "await", "async", "not", "and", "or", "if",
    "else", "for", "in", "is", "yield",
];

static CALL_HEAD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\(").expect("call head regex is valid")
});

static IDENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z_]\w*").expect("identifier regex is valid"));

static FROM_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bfrom\s+[\w.]+\s+import\s+(\([^)]*\)|[^\n]*)").expect("import regex is valid")
});

static ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*(?::[^=\n]+)?=[ \t]*([^\n=][^\n]*)$")
        .expect("assignment regex is valid")
});

static CLASS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^([ \t]*)class\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?\s*:")
        .expect("class regex is valid")
});

static DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)").expect("def regex is valid"));

/// A class definition: its name, base class names, and defined method names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassInfo {
    pub(crate) name: String,
    pub(crate) bases: Vec<String>,
    pub(crate) methods: Vec<String>,
}

/// Names of functions passed to framework registration calls in `content`,
/// with `from x import a as b` aliases resolved to the original name.
pub(crate) fn function_references(content: &str) -> References {
    let masked = mask_strings_and_comments(content);
    let pairs = paren_pairs(&masked);
    let mut references = References::default();
    let mut budget = MAX_SCANNED_BYTES;

    for head in CALL_HEAD_RE.find_iter(&masked) {
        let open = head.end() - 1;
        let Some(&close) = pairs.get(&open) else {
            continue;
        };
        if is_definition_name(&masked[..head.start()]) {
            continue;
        }
        let chain: String = head
            .as_str()
            .trim_end_matches('(')
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let registration = REGISTRATIONS
            .iter()
            .find(|registration| callee_matches(&chain, registration.callee));
        let last = chain.rsplit('.').next().unwrap_or(&chain);
        let is_decorator = TOOL_DECORATORS.contains(&last);
        if registration.is_none() && !is_decorator {
            continue;
        }

        budget = budget.saturating_sub(close - open);
        if budget == 0 {
            references.exhausted = true;
            break;
        }
        let args = split_arguments(&masked[open + 1..close]);

        if let Some(registration) = registration {
            collect_registration(registration, &args, &mut references);
        }
        if is_decorator {
            // `mcp.tool()(fn)` applies the decorator to `fn`; `tool(fn)` too.
            let applied = chained_call_arguments(&masked, close, &pairs).unwrap_or(args);
            for arg in &applied {
                if keyword_name(arg).is_none() {
                    references.names.extend(function_names(arg));
                }
            }
        }
    }

    resolve_aliases(&masked, &mut references);
    follow_assignments(&mut references.names, &assignments(&masked));
    references
}

/// Classes defined in `content` with their bases and methods.
pub(crate) fn class_infos(content: &str) -> Vec<ClassInfo> {
    let masked = mask_strings_and_comments(content);
    let lines: Vec<&str> = masked.lines().collect();
    let mut infos = Vec::new();

    for captures in CLASS_RE.captures_iter(&masked) {
        let whole = captures.get(0).expect("whole match");
        let indent = captures[1].chars().count();
        let header_end_line = masked[..whole.end()].matches('\n').count();
        let bases = captures
            .get(3)
            .map(|m| base_names(m.as_str()))
            .unwrap_or_default();

        let mut methods = Vec::new();
        for line in lines.iter().skip(header_end_line + 1) {
            if line.trim().is_empty() {
                continue;
            }
            if line.chars().take_while(|c| c.is_whitespace()).count() <= indent {
                break;
            }
            if let Some(def) = DEF_RE.captures(line) {
                methods.push(def[1].to_string());
            }
        }
        infos.push(ClassInfo {
            name: captures[2].to_string(),
            bases,
            methods,
        });
    }
    infos
}

/// Entry methods of every class that (transitively, across `classes`)
/// inherits from a known tool base. Returned per input group, in order.
///
/// Inheritance is resolved by class name across all groups, so a tool base
/// declared in another file is followed. Name collisions only make more
/// classes count as tools, which is the conservative direction.
pub(crate) fn tool_class_entry_methods(groups: &[Vec<ClassInfo>]) -> Vec<Vec<String>> {
    let mut tool_classes: HashMap<&str, ()> = HashMap::new();
    loop {
        let before = tool_classes.len();
        for class in groups.iter().flatten() {
            if class.bases.iter().any(|base| {
                TOOL_BASES.contains(&base.as_str()) || tool_classes.contains_key(base.as_str())
            }) {
                tool_classes.insert(class.name.as_str(), ());
            }
        }
        if tool_classes.len() == before {
            break;
        }
    }

    groups
        .iter()
        .map(|classes| {
            classes
                .iter()
                .filter(|class| tool_classes.contains_key(class.name.as_str()))
                .flat_map(|class| class.methods.iter())
                .filter(|method| TOOL_ENTRY_METHODS.contains(&method.as_str()))
                .cloned()
                .collect()
        })
        .collect()
}

fn collect_registration(registration: &Registration, args: &[String], out: &mut References) {
    let mut position = 0;
    for arg in args {
        match keyword_name(arg) {
            Some((name, value)) => {
                if registration.keywords.contains(&name) {
                    out.names.extend(function_names(value));
                }
            }
            None => {
                if registration.positional.contains(&position) {
                    out.names.extend(function_names(arg));
                }
                position += 1;
            }
        }
    }
}

/// True when the name that follows `before` is being defined (`def f(`,
/// `class Tool(`), not called.
fn is_definition_name(before: &str) -> bool {
    let before = before.trim_end();
    ["def", "class"].iter().any(|keyword| {
        before.strip_suffix(keyword).is_some_and(|rest| {
            !rest.ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == '.')
        })
    })
}

fn callee_matches(chain: &str, suffix: &str) -> bool {
    chain == suffix
        || chain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Split `name=value` into its parts; `==` and non-identifier lefts are not
/// keyword arguments.
fn keyword_name(arg: &str) -> Option<(&str, &str)> {
    let end = arg.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    if end == 0 {
        return None;
    }
    let rest = arg[end..].trim_start();
    let value = rest.strip_prefix('=')?;
    (!value.starts_with('=')).then(|| (&arg[..end], value.trim()))
}

/// Identifiers in `expression` that may name a function. Lambdas are inline
/// handlers: their bodies are analysed in place, so they reference nothing.
fn function_names(expression: &str) -> Vec<String> {
    let trimmed = expression.trim_start();
    let is_lambda = trimmed
        .strip_prefix("lambda")
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'));
    if is_lambda || trimmed.starts_with('*') {
        return Vec::new();
    }
    IDENT_RE
        .find_iter(trimmed)
        .map(|m| m.as_str())
        .filter(|name| !NOT_A_FUNCTION.contains(name))
        .map(str::to_string)
        .collect()
}

/// Top-level comma-separated arguments of a call's argument text. Commas in a
/// lambda's parameter list do not split.
fn split_arguments(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut in_lambda_params = false;
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b':' if depth == 0 => in_lambda_params = false,
            b',' if depth == 0 && !in_lambda_params => {
                parts.push(text[start..i].trim().to_string());
                start = i + 1;
            }
            b'l' if depth == 0 && is_lambda_keyword(bytes, i) => in_lambda_params = true,
            _ => {}
        }
        i += 1;
    }
    parts.push(text[start..].trim().to_string());
    parts.retain(|part| !part.is_empty());
    parts
}

fn is_lambda_keyword(bytes: &[u8], at: usize) -> bool {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    bytes[at..].starts_with(b"lambda")
        && (at == 0 || !is_word(bytes[at - 1]))
        && bytes.get(at + 6).is_none_or(|b| !is_word(*b))
}

/// Arguments of a call immediately following the call that closes at `close`,
/// as in `mcp.tool()(fn)`.
fn chained_call_arguments(
    masked: &str,
    close: usize,
    pairs: &HashMap<usize, usize>,
) -> Option<Vec<String>> {
    let after = &masked[close + 1..];
    let skipped = after.len() - after.trim_start_matches([' ', '\t']).len();
    let open = close + 1 + skipped;
    if !masked[open..].starts_with('(') {
        return None;
    }
    let end = *pairs.get(&open)?;
    Some(split_arguments(&masked[open + 1..end]))
}

/// Map each `(` to its matching `)` in one pass, so nested registrations cost
/// linear rather than quadratic time.
fn paren_pairs(masked: &str) -> HashMap<usize, usize> {
    let mut stack = Vec::new();
    let mut pairs = HashMap::new();
    for (index, byte) in masked.bytes().enumerate() {
        match byte {
            b'(' => stack.push(index),
            b')' => {
                if let Some(open) = stack.pop() {
                    pairs.insert(open, index);
                }
            }
            _ => {}
        }
    }
    pairs
}

fn base_names(bases: &str) -> Vec<String> {
    split_arguments(bases)
        .iter()
        .filter(|base| keyword_name(base).is_none())
        .filter_map(|base| {
            let without_subscript = base.split('[').next().unwrap_or(base).trim();
            let last = without_subscript.rsplit('.').next()?.trim();
            (!last.is_empty()).then(|| last.to_string())
        })
        .collect()
}

/// `name = expression` statements, as the identifiers each expression
/// references.
fn assignments(masked: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for captures in ASSIGNMENT_RE.captures_iter(masked) {
        map.entry(captures[1].to_string())
            .or_default()
            .extend(function_names(&captures[2]));
    }
    map
}

/// Add the original name of every aliased reference (`import a as b`).
fn resolve_aliases(masked: &str, references: &mut References) {
    let mut aliases: HashMap<String, String> = HashMap::new();
    for captures in FROM_IMPORT_RE.captures_iter(masked) {
        let names = captures[1].trim_matches(|c| c == '(' || c == ')');
        for spec in names.split(',') {
            let mut words = spec.split_whitespace();
            if let (Some(original), Some("as"), Some(local)) =
                (words.next(), words.next(), words.next())
            {
                aliases.insert(local.to_string(), original.to_string());
            }
        }
    }
    let originals: Vec<String> = references
        .names
        .iter()
        .filter_map(|name| aliases.get(name).cloned())
        .collect();
    references.names.extend(originals);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(content: &str) -> Vec<String> {
        let mut names: Vec<_> = function_references(content).names.into_iter().collect();
        names.sort();
        names
    }

    #[test]
    fn llama_index_function_tool_forms() {
        assert_eq!(names("FunctionTool.from_defaults(fn=a)"), ["a"]);
        assert_eq!(names("FunctionTool.from_defaults(b, name=\"x\")"), ["b"]);
        assert_eq!(names("llama.FunctionTool.from_defaults(async_fn=c)"), ["c"]);
        assert_eq!(names("FunctionTool(d)"), ["d"]);
    }

    #[test]
    fn langchain_forms() {
        assert_eq!(names("StructuredTool.from_function(func=a)"), ["a"]);
        assert_eq!(
            names("StructuredTool.from_function(b, coroutine=c)"),
            ["b", "c"]
        );
        assert_eq!(names("Tool(name=\"x\", func=d, description=\"y\")"), ["d"]);
        assert_eq!(names("Tool(\"x\", e, \"y\")"), ["e"]);
    }

    #[test]
    fn autogen_and_fastmcp_forms() {
        assert_eq!(names("register_function(a, caller=b, executor=c)"), ["a"]);
        assert_eq!(names("autogen.register_function(f=d, caller=b)"), ["d"]);
        assert_eq!(names("mcp.add_tool(e)"), ["e"]);
        assert_eq!(names("mcp.add_tool(fn=f)"), ["f"]);
    }

    #[test]
    fn decorator_applied_as_a_call() {
        assert_eq!(names("mcp.tool()(a)"), ["a"]);
        assert_eq!(names("mcp.tool(name=\"x\")  (b)"), ["b"]);
        assert_eq!(names("agent.register_for_llm(description=\"d\")(c)"), ["c"]);
        assert_eq!(names("wrapped = tool(d)"), ["d"]);
    }

    #[test]
    fn multiline_and_wrapped_references() {
        let content = "register_function(\n    functools.partial(a, 1),\n    caller=b,\n)\n";
        let found = names(content);
        assert!(found.contains(&"a".to_string()));
    }

    #[test]
    fn lambdas_strings_and_comments_reference_nothing() {
        assert!(names("FunctionTool.from_defaults(fn=lambda x: helper(x))").is_empty());
        assert!(names("Tool(\"x\", lambda a, b: helper(a), \"d\")").is_empty());
        assert!(names("# register_function(a)\nx = \"mcp.add_tool(b)\"").is_empty());
        assert!(names("register_function(\"a\", caller=b)").is_empty());
    }

    #[test]
    fn unrelated_calls_and_definitions_reference_nothing() {
        assert!(names("def add_tool(fn): ...\nprint(fn)\nother.add(fn)").is_empty());
        assert!(names("Tooling(a)\nMyTool(b)\nNotTool.from_function(c)").is_empty());
    }

    #[test]
    fn aliased_imports_resolve_to_the_original_name() {
        let content = "from handlers import (run_cmd as shell, other)\nregister_function(shell)\n";
        assert_eq!(names(content), ["run_cmd", "shell"]);
    }

    #[test]
    fn variable_aliases_are_followed() {
        let content = "handler = run_cmd\nmcp.add_tool(handler)\n";
        assert!(names(content).contains(&"run_cmd".to_string()));
    }

    #[test]
    fn deeply_nested_registrations_do_not_stall() {
        let content = format!("{}x{}", "add_tool(".repeat(50_000), ")".repeat(50_000));
        let started = std::time::Instant::now();
        let _ = function_references(&content);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    fn infos(content: &str) -> Vec<ClassInfo> {
        class_infos(content)
    }

    #[test]
    fn extracts_classes_bases_and_methods() {
        let content = "class A(langchain.tools.BaseTool, Generic[T], metaclass=Meta):\n    x = 1\n\n    def _run(self): ...\n\n    async def _arun(self): ...\n\nclass B:\n    def run(self): ...\n";
        let found = infos(content);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "A");
        assert_eq!(found[0].bases, ["BaseTool", "Generic"]);
        assert_eq!(found[0].methods, ["_run", "_arun"]);
        assert!(found[1].bases.is_empty());
        assert_eq!(found[1].methods, ["run"]);
    }

    #[test]
    fn tool_entry_methods_follow_inheritance_across_groups() {
        let base = infos("class Base(BaseTool):\n    pass\n");
        let child = infos(
            "class Child(Base):\n    def _run(self): ...\n    def helper(self): ...\n\nclass Plain:\n    def _run(self): ...\n",
        );
        let methods = tool_class_entry_methods(&[child, base]);
        assert_eq!(methods[0], ["_run"]);
        assert!(methods[1].is_empty());
    }
}
