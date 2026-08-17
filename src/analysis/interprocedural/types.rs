use std::collections::HashMap;
use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::data_surface::TaintSink;
use crate::ir::{ScanTarget, SourceLocation};

pub(crate) static CALL_EXPR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b([A-Za-z0-9_]+)\s*\(([^)]*)\)"#).expect("valid regex"));

/// A representation of a function definition in the project.
#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub name: String,
    pub file_path: PathBuf,
    pub params: Vec<String>,
    pub start_line: usize,
    pub end_line: usize,
    pub location: SourceLocation,
    pub sinks: Vec<TaintSink>,
}

/// A call-site invoking a function.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub caller_name: String,
    pub callee_name: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub args: Vec<String>,
    pub location: SourceLocation,
}

/// Interprocedural Call Graph.
#[derive(Debug, Default)]
pub struct CallGraph {
    pub functions: HashMap<String, Vec<FunctionNode>>,
    pub call_sites: Vec<CallSite>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build call graph from all source files in a ScanTarget.
    pub fn build(target: &ScanTarget) -> Self {
        let mut graph = CallGraph::new();

        for sf in &target.source_files {
            let ext = sf.path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "py" {
                super::python::parse_python_file(&mut graph, &sf.path, &sf.content, target);
            } else if matches!(ext, "ts" | "js" | "tsx" | "jsx" | "mjs") {
                super::typescript::parse_typescript_file(&mut graph, &sf.path, &sf.content, target);
            }
        }

        graph
    }

    pub fn find_enclosing_function(&self, file_path: &Path, line: usize) -> String {
        let mut best_match: Option<(&FunctionNode, usize)> = None;
        for nodes in self.functions.values() {
            for node in nodes {
                let start = node.start_line.saturating_sub(1);
                if node.file_path == file_path && line >= start && line <= node.end_line {
                    let span = node.end_line - start;
                    if best_match.is_none_or(|(_, best_span)| span < best_span) {
                        best_match = Some((node, span));
                    }
                }
            }
        }
        best_match
            .map(|(n, _)| n.name.clone())
            .unwrap_or_else(|| "<global>".to_string())
    }
}
