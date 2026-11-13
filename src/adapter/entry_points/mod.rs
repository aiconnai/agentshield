//! Agent entry points declared through framework APIs.
//!
//! Cross-file analysis downgrades a function's tainted parameter when every
//! internal call site passes a literal. That is wrong for a function the
//! agent invokes directly: the agent supplies the arguments, whatever the
//! scanned code happens to call it with. The Python parser marks decorated
//! tools; this module marks the rest:
//!
//! - class-based tools (`_run`, `call`, ... on `BaseTool` subclasses);
//! - function references passed to registration calls
//!   (`FunctionTool.from_defaults(fn=f)`, `register_function(f, ...)`,
//!   `mcp.add_tool(f)`, `mcp.tool()(f)`, `StructuredTool.from_function`, ...);
//! - Vercel AI SDK `tool({ execute: f })` references.
//!
//! Marking is by name, and deliberately over-inclusive. A name referenced in
//! one file marks every same-named definition in all scanned files, which can
//! only keep a finding alive that a downgrade would have removed.

mod python;
mod typescript;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ir::{Language, SourceFile};
use crate::parser::ParsedFile;

/// Function names found in registrations. `exhausted` is set when scanning
/// gave up on a pathological file; the caller then treats every function in
/// that file as an entry point rather than silently dropping registrations.
#[derive(Debug, Default)]
pub(crate) struct References {
    pub(crate) names: HashSet<String>,
    pub(crate) exhausted: bool,
}

/// Maximum hops through `alias = original` assignments.
const ASSIGNMENT_HOPS: usize = 3;

/// Mark framework-declared entry points in `parsed_files`.
///
/// `source_files` supplies the text the registrations are read from; files in
/// `parsed_files` are matched to it by path.
pub(crate) fn mark_framework_entry_points(
    source_files: &[SourceFile],
    parsed_files: &mut [(PathBuf, ParsedFile)],
) {
    let mut names = HashSet::new();
    let mut exhausted_files = HashSet::new();
    let mut class_groups = Vec::new();
    let mut class_files = Vec::new();

    for source in source_files {
        let references = match source.language {
            Language::Python => {
                class_groups.push(python::class_infos(&source.content));
                class_files.push(&source.path);
                python::function_references(&source.content)
            }
            Language::TypeScript | Language::JavaScript => {
                typescript::vercel_execute_references(&source.content)
            }
            _ => continue,
        };
        if references.exhausted {
            exhausted_files.insert(&source.path);
        }
        names.extend(references.names);
    }

    mark_referenced_functions(&names, parsed_files);

    let methods = python::tool_class_entry_methods(&class_groups);
    let mut parsed_by_path: HashMap<&Path, &mut ParsedFile> = parsed_files
        .iter_mut()
        .map(|(p, parsed)| (p.as_path(), parsed))
        .collect();
    for (path, methods) in class_files.into_iter().zip(methods) {
        if let Some(parsed) = parsed_by_path.get_mut(path.as_path()) {
            parsed.entry_points.extend(methods);
        }
    }

    for (path, parsed) in parsed_files.iter_mut() {
        if exhausted_files.contains(path) {
            let all: Vec<String> = parsed
                .function_defs
                .iter()
                .map(|d| d.name.clone())
                .collect();
            parsed.entry_points.extend(all);
        }
    }
}

/// Mark every definition named in `references` as an entry point, in any file.
pub(crate) fn mark_referenced_functions(
    references: &HashSet<String>,
    parsed_files: &mut [(PathBuf, ParsedFile)],
) {
    if references.is_empty() {
        return;
    }
    for (_, parsed) in parsed_files.iter_mut() {
        let handlers: Vec<String> = parsed
            .function_defs
            .iter()
            .filter(|def| references.contains(&def.name))
            .map(|def| def.name.clone())
            .collect();
        parsed.entry_points.extend(handlers);
    }
}

/// Extend `names` with what each `alias = original` assignment references,
/// so `handler = run_cmd; register(handler)` still marks `run_cmd`.
fn follow_assignments(names: &mut HashSet<String>, assignments: &HashMap<String, Vec<String>>) {
    for _ in 0..ASSIGNMENT_HOPS {
        let added: Vec<String> = names
            .iter()
            .filter_map(|name| assignments.get(name))
            .flatten()
            .filter(|referenced| !names.contains(*referenced))
            .cloned()
            .collect();
        if added.is_empty() {
            return;
        }
        names.extend(added);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parser_for_language;

    fn source(path: &str, language: Language, content: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from(path),
            language,
            content: content.to_string(),
            size_bytes: content.len() as u64,
            content_hash: String::new(),
        }
    }

    fn marked(sources: &[SourceFile]) -> Vec<Vec<String>> {
        let mut parsed: Vec<_> = sources
            .iter()
            .map(|s| {
                let file = parser_for_language(s.language)
                    .expect("parser")
                    .parse_file(&s.path, &s.content)
                    .expect("parse");
                (s.path.clone(), file)
            })
            .collect();
        mark_framework_entry_points(sources, &mut parsed);
        parsed
            .into_iter()
            .map(|(_, file)| {
                let mut names: Vec<_> = file.entry_points.into_iter().collect();
                names.sort();
                names
            })
            .collect()
    }

    #[test]
    fn registration_marks_definitions_in_other_files_by_name() {
        let sources = [
            source(
                "a.py",
                Language::Python,
                "def run_cmd(c): ...\ndef other(c): ...\n",
            ),
            source(
                "b.py",
                Language::Python,
                "from a import run_cmd\nregister_function(run_cmd)\n",
            ),
        ];
        let result = marked(&sources);
        assert_eq!(result[0], ["run_cmd"]);
        assert!(result[1].is_empty());
    }

    #[test]
    fn tool_class_methods_are_marked_only_in_the_declaring_file() {
        let sources = [
            source(
                "tool.py",
                Language::Python,
                "class T(BaseTool):\n    def _run(self, c): ...\n    def helper(self, c): ...\n",
            ),
            source("other.py", Language::Python, "def _run(c): ...\n"),
        ];
        let result = marked(&sources);
        assert_eq!(result[0], ["_run"]);
        assert!(result[1].is_empty());
    }

    #[test]
    fn exhausted_files_mark_every_function() {
        let nested = format!("{}x{}", "add_tool(".repeat(50_000), ")".repeat(50_000));
        let sources = [source(
            "big.py",
            Language::Python,
            &format!("def a(x): ...\ndef b(x): ...\nz = {nested}\n"),
        )];
        assert_eq!(marked(&sources)[0], ["a", "b"]);
    }
}
