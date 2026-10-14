pub(crate) mod common;
pub mod json_schema;
pub mod python;
pub mod shell;
pub mod typescript;

use std::collections::HashSet;
use std::path::Path;

use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language, SourceLocation};

/// Result of parsing a single source file.
#[derive(Debug, Clone, Default)]
pub struct ParsedFile {
    pub commands: Vec<CommandInvocation>,
    pub file_operations: Vec<FileOperation>,
    pub network_operations: Vec<NetworkOperation>,
    pub env_accesses: Vec<EnvAccess>,
    pub dynamic_exec: Vec<DynamicExec>,
    /// Names of function parameters (for tool argument tracking).
    pub function_params: Vec<FunctionParam>,
    /// Function definitions discovered in source code.
    pub function_defs: Vec<FunctionDef>,
    /// Function call sites discovered in source code.
    pub call_sites: Vec<CallSite>,
    /// Variables holding sanitized values (e.g., `validPath = validatePath(x)`).
    pub sanitized_vars: HashSet<String>,
}

/// A function parameter discovered in source code.
#[derive(Debug, Clone)]
pub struct FunctionParam {
    pub function_name: String,
    pub param_name: String,
    pub location: SourceLocation,
}

/// A function definition discovered in source code.
#[derive(Debug, Clone)]
pub struct FunctionDef {
    pub name: String,
    pub params: Vec<String>,
    pub is_exported: bool,
    pub location: SourceLocation,
}

/// A function call site discovered in source code.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// The function being called.
    pub callee: String,
    /// Arguments passed, each classified.
    pub arguments: Vec<ArgumentSource>,
    /// The enclosing function name, if any.
    pub caller: Option<String>,
    pub location: SourceLocation,
}

/// Language parser trait. Each parser extracts security-relevant operations
/// from source files.
pub trait LanguageParser: Send + Sync {
    fn language(&self) -> Language;
    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile>;
}

/// Get the appropriate parser for a language.
pub fn parser_for_language(lang: Language) -> Option<Box<dyn LanguageParser>> {
    match lang {
        Language::Python => Some(Box::new(python::PythonParser)),
        Language::TypeScript | Language::JavaScript => Some(Box::new(typescript::TypeScriptParser)),
        Language::Shell => Some(Box::new(shell::ShellParser)),
        _ => None,
    }
}
