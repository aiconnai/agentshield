//! Handler references passed to MCP `server.tool(...)` registrations.
//!
//! These names mark agent entry points for cross-file analysis. The scan works
//! on raw registrations, before tool declarations are deduplicated by name, so
//! a decoy registration cannot displace the real handler. It is deliberately
//! over-inclusive: every identifier in a non-inline handler argument counts.

use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use super::scan::{
    find_matching_delimiter, find_next_mcp_tool_call, is_inline_handler, is_js_identifier,
    is_js_reserved_word, top_level_segments, trim_range,
};

/// `import { a as b, c } from "..."` (also `import type` and `import x, {...}`).
static NAMED_IMPORT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bimport\b[^;{]*\{([^}]*)\}").expect("named import regex is valid"));

/// Identifiers that may name a handler function in `content`, with import
/// aliases resolved to the imported name.
pub(crate) fn extract_mcp_handler_references(content: &str) -> HashSet<String> {
    let aliases = import_aliases(content);
    let mut references = HashSet::new();
    let mut offset = 0;

    while let Some(relative_start) = find_next_mcp_tool_call(&content[offset..]) {
        let call_start = offset + relative_start;
        let Some(open_paren) = content[call_start..].find('(').map(|pos| call_start + pos) else {
            break;
        };
        let Some(close_paren) = find_matching_delimiter(content, open_paren, b'(', b')') else {
            break;
        };
        let arguments = top_level_segments(content, open_paren + 1, close_paren);
        if let Some(&(start, end)) = arguments.last() {
            let (start, end) = trim_range(content, start, end);
            let candidate = &content[start..end];
            if !is_inline_handler(candidate) {
                for identifier in js_identifiers(candidate) {
                    if let Some(original) = aliases.get(identifier) {
                        references.insert(original.clone());
                    }
                    references.insert(identifier.to_string());
                }
            }
        }
        offset = close_paren + 1;
    }

    references
}

pub(crate) fn js_identifiers(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .filter(|token| is_js_identifier(token) && !is_js_reserved_word(token))
}

/// Map each local alias to the name it imports (`import { a as b }` → b → a).
pub(crate) fn import_aliases(content: &str) -> HashMap<String, String> {
    NAMED_IMPORT_RE
        .captures_iter(content)
        .flat_map(|captures| {
            captures[1]
                .split(',')
                .filter_map(|spec| {
                    let spec = spec.trim().trim_start_matches("type ").trim();
                    let (imported, local) = spec.split_once(" as ")?;
                    Some((local.trim().to_string(), imported.trim().to_string()))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(content: &str) -> Vec<String> {
        let mut names: Vec<_> = extract_mcp_handler_references(content)
            .into_iter()
            .collect();
        names.sort();
        names
    }

    #[test]
    fn collects_every_registration_before_dedupe() {
        let content = "server.tool(\"a\", {}, decoy);\nserver.tool(\"a\", {}, real);\n";
        let names = refs(content);
        assert!(names.contains(&"decoy".to_string()));
        assert!(names.contains(&"real".to_string()));
    }

    #[test]
    fn resolves_dotted_wrapped_and_aliased_references() {
        let content = "import { runCmd as rc, other } from \"./h\";\nserver.tool(\"a\", {}, ns.first);\nserver.tool(\"b\", {}, withLog(second));\nserver.tool(\"c\", {}, third.bind(null));\nserver.registerTool(\"d\", {}, rc);\n";
        let names = refs(content);
        for expected in ["first", "second", "third", "rc", "runCmd"] {
            assert!(
                names.contains(&expected.to_string()),
                "{expected} in {names:?}"
            );
        }
        assert!(!names.contains(&"null".to_string()));
    }

    #[test]
    fn skips_inline_handlers() {
        let content = "server.tool(\"a\", {}, async (args) => helper(args.cmd));\n";
        assert!(refs(content).is_empty());
    }
}
