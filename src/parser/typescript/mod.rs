pub(crate) mod ast;
pub(crate) mod child_process;
pub(crate) mod classify;
pub(crate) mod fallback;
pub(crate) mod patterns;
#[cfg(feature = "typescript")]
pub(crate) mod scoped;

#[cfg(test)]
mod tests;

#[cfg(feature = "typescript")]
use std::collections::HashSet;
use std::path::Path;
#[cfg(feature = "typescript")]
use std::path::PathBuf;

#[cfg(feature = "typescript")]
use ast::{collect_params, walk_node};
#[cfg(feature = "typescript")]
use child_process::ChildProcessBindings;
#[cfg(not(feature = "typescript"))]
use fallback::parse_file_fallback;
#[cfg(feature = "typescript")]
use scoped::collect_scoped_sanitizers;

use crate::error::Result;
use crate::ir::Language;
use crate::parser::LanguageParser;
use crate::parser::ParsedFile;

/// Parser for TypeScript and JavaScript source files (.ts, .tsx, .js, .jsx).
pub struct TypeScriptParser;

#[cfg(feature = "typescript")]
impl LanguageParser for TypeScriptParser {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parser = tree_sitter::Parser::new();
        let is_tsx = path
            .extension()
            .is_some_and(|ext| ext == "tsx" || ext == "jsx");

        let lang = if is_tsx {
            tree_sitter_typescript::LANGUAGE_TSX
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT
        };

        parser
            .set_language(&lang.into())
            .map_err(|e| crate::error::ShieldError::Parse {
                file: path.display().to_string(),
                message: format!("Failed to load TypeScript grammar: {e}"),
            })?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| crate::error::ShieldError::Parse {
                file: path.display().to_string(),
                message: "tree-sitter failed to parse TypeScript".into(),
            })?;

        let file_path = PathBuf::from(path);
        let source = content.as_bytes();
        let mut parsed = ParsedFile::default();
        let mut param_names = HashSet::new();

        // Phase 0: Detect sanitizer assignments, per enclosing function
        let scoped_sanitizers = collect_scoped_sanitizers(tree.root_node(), source);
        parsed.sanitized_vars.extend(scoped_sanitizers.all());

        // Phase 1: Collect function parameters + function defs
        collect_params(
            tree.root_node(),
            source,
            &file_path,
            &mut param_names,
            &mut parsed,
        );

        // Phase 2: Walk AST for call expressions, call sites, and env accesses
        let child_process = ChildProcessBindings::from_source(content);
        walk_node(
            tree.root_node(),
            source,
            &file_path,
            &param_names,
            &child_process,
            &scoped_sanitizers,
            &mut parsed,
        );

        Ok(parsed)
    }
}

#[cfg(not(feature = "typescript"))]
impl LanguageParser for TypeScriptParser {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        parse_file_fallback(path, content)
    }
}
