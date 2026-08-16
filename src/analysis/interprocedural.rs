//! Interprocedural call-graph and cross-function taint propagation engine (milestone v1.0.0).
//!
//! Analyzes cross-function and cross-method control/data flow across Python and TypeScript
//! agent extensions. Connects tool input parameters that are passed through intermediate
//! helper functions, utility wrappers, and class methods to downstream execution sinks.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::analysis::AnalysisBundle;
use crate::ir::data_surface::{TaintPath, TaintSink, TaintSource};
use crate::ir::{ScanTarget, SourceLocation};

static PY_FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#).expect("valid regex")
});

static TS_FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"#)
        .expect("valid regex")
});

static CALL_EXPR_RE: Lazy<Regex> =
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
                graph.parse_python_file(&sf.path, &sf.content, target);
            } else if matches!(ext, "ts" | "js" | "tsx" | "jsx" | "mjs") {
                graph.parse_typescript_file(&sf.path, &sf.content, target);
            }
        }

        graph
    }

    fn parse_python_file(&mut self, file_path: &Path, content: &str, target: &ScanTarget) {
        let lines: Vec<&str> = content.lines().collect();

        // 1. Extract function definitions
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            if let Some(cap) = PY_FUNC_DEF_RE.captures(line) {
                let func_name = cap[1].to_string();
                let raw_params = &cap[2];

                let params: Vec<String> = raw_params
                    .split(',')
                    .map(|p| {
                        p.split(':')
                            .next()
                            .unwrap_or("")
                            .split('=')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    })
                    .filter(|p| !p.is_empty() && p != "self" && p != "cls")
                    .collect();

                let start_line = line_num;
                let func_indent = line.len() - line.trim_start().len();
                let mut end_line = start_line;

                for (sub_idx, next_line) in lines.iter().enumerate().skip(start_line) {
                    let next_trimmed = next_line.trim();
                    if next_trimmed.is_empty() || next_trimmed.starts_with('#') {
                        continue;
                    }
                    let next_indent = next_line.len() - next_line.trim_start().len();
                    if next_indent <= func_indent
                        || next_trimmed.starts_with('@')
                        || next_trimmed.starts_with("def ")
                        || next_trimmed.starts_with("async def ")
                        || next_trimmed.starts_with("class ")
                    {
                        break;
                    }
                    end_line = sub_idx + 1;
                }

                let func_sinks = target
                    .data
                    .sinks
                    .iter()
                    .filter(|s| {
                        s.location.file == file_path
                            && s.location.line >= start_line
                            && s.location.line <= end_line
                    })
                    .cloned()
                    .collect();

                let node = FunctionNode {
                    name: func_name.clone(),
                    file_path: file_path.to_path_buf(),
                    params,
                    start_line,
                    end_line,
                    location: SourceLocation {
                        file: file_path.to_path_buf(),
                        line: start_line,
                        column: func_indent,
                        end_line: Some(end_line),
                        end_column: None,
                    },
                    sinks: func_sinks,
                };

                self.functions.entry(func_name).or_default().push(node);
            }
        }

        // 2. Extract call sites
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.starts_with('#')
                || trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
            {
                continue;
            }

            for cap in CALL_EXPR_RE.captures_iter(line) {
                let callee_name = cap[1].to_string();
                let raw_args = &cap[2];

                // Determine caller function containing this line
                let caller_name = self.find_enclosing_function(file_path, line_num);

                let args: Vec<String> = raw_args
                    .split(',')
                    .map(|a| a.split('=').next().unwrap_or("").trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect();

                self.call_sites.push(CallSite {
                    caller_name,
                    callee_name,
                    file_path: file_path.to_path_buf(),
                    line_number: line_num,
                    args,
                    location: SourceLocation {
                        file: file_path.to_path_buf(),
                        line: line_num,
                        column: line.find(&cap[0]).unwrap_or(0),
                        end_line: None,
                        end_column: None,
                    },
                });
            }
        }
    }

    fn parse_typescript_file(&mut self, file_path: &Path, content: &str, target: &ScanTarget) {
        let lines: Vec<&str> = content.lines().collect();

        // 1. Extract function definitions
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            if let Some(cap) = TS_FUNC_DEF_RE.captures(line) {
                let func_name = cap
                    .get(1)
                    .or_else(|| cap.get(3))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                if func_name.is_empty() {
                    continue;
                }

                let raw_params = cap
                    .get(2)
                    .or_else(|| cap.get(4))
                    .map(|m| m.as_str())
                    .unwrap_or("");

                let params: Vec<String> = raw_params
                    .split(',')
                    .map(|p| {
                        p.split(':')
                            .next()
                            .unwrap_or("")
                            .split('=')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    })
                    .filter(|p| !p.is_empty())
                    .collect();

                let start_line = line_num;
                let mut end_line = start_line;
                let mut brace_count: i32 = 0;
                for (sub_idx, next_line) in
                    lines.iter().enumerate().skip(start_line.saturating_sub(1))
                {
                    let next_trimmed = next_line.trim();
                    if next_trimmed.is_empty() || next_trimmed.starts_with("//") {
                        continue;
                    }
                    brace_count += next_line.chars().filter(|&c| c == '{').count() as i32;
                    brace_count -= next_line.chars().filter(|&c| c == '}').count() as i32;
                    end_line = sub_idx + 1;
                    if brace_count <= 0 && sub_idx + 1 >= start_line {
                        break;
                    }
                }

                let func_sinks = target
                    .data
                    .sinks
                    .iter()
                    .filter(|s| {
                        s.location.file == file_path
                            && s.location.line >= start_line
                            && s.location.line <= end_line
                    })
                    .cloned()
                    .collect();

                let node = FunctionNode {
                    name: func_name.clone(),
                    file_path: file_path.to_path_buf(),
                    params,
                    start_line,
                    end_line,
                    location: SourceLocation {
                        file: file_path.to_path_buf(),
                        line: start_line,
                        column: 0,
                        end_line: Some(end_line),
                        end_column: None,
                    },
                    sinks: func_sinks,
                };

                self.functions.entry(func_name).or_default().push(node);
            }
        }

        // Call sites
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with("function ")
            {
                continue;
            }

            for cap in CALL_EXPR_RE.captures_iter(line) {
                let callee_name = cap[1].to_string();
                let raw_args = &cap[2];
                let caller_name = self.find_enclosing_function(file_path, line_num);

                let args: Vec<String> = raw_args
                    .split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect();

                self.call_sites.push(CallSite {
                    caller_name,
                    callee_name,
                    file_path: file_path.to_path_buf(),
                    line_number: line_num,
                    args,
                    location: SourceLocation {
                        file: file_path.to_path_buf(),
                        line: line_num,
                        column: line.find(&cap[0]).unwrap_or(0),
                        end_line: None,
                        end_column: None,
                    },
                });
            }
        }
    }

    fn find_enclosing_function(&self, file_path: &Path, line: usize) -> String {
        let mut best_match: Option<(&FunctionNode, usize)> = None;
        for nodes in self.functions.values() {
            for node in nodes {
                let start = node.start_line.saturating_sub(1);
                if node.file_path == file_path && line >= start && line <= node.end_line {
                    let span = node.end_line - start;
                    if best_match.is_none() || span < best_match.unwrap().1 {
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

/// Propagates taint across call-graph edges and constructs multi-hop `TaintPath` instances.
pub fn propagate_interprocedural_taint(target: &ScanTarget, graph: &CallGraph) -> Vec<TaintPath> {
    let mut new_paths = Vec::new();
    let mut visited_paths = HashSet::new();

    // Map each taint source to its enclosing function
    for source in &target.data.sources {
        let caller_name =
            graph.find_enclosing_function(&source.location.file, source.location.line);

        // Find calls originating from this function passing a tainted variable
        for call in &graph.call_sites {
            if call.file_path == source.location.file && call.caller_name == caller_name {
                let mut ctx = TraversalContext {
                    graph,
                    source,
                    trace: vec![call.location.clone()],
                    visited_functions: HashSet::from([caller_name.clone()]),
                    visited_paths: &mut visited_paths,
                    new_paths: &mut new_paths,
                    depth: 0,
                };
                ctx.trace_callee(&call.callee_name);
            }
        }
    }

    new_paths
}

const MAX_PROPAGATION_DEPTH: usize = 16;

struct TraversalContext<'a> {
    graph: &'a CallGraph,
    source: &'a TaintSource,
    trace: Vec<SourceLocation>,
    visited_functions: HashSet<String>,
    visited_paths: &'a mut HashSet<(String, usize, usize)>,
    new_paths: &'a mut Vec<TaintPath>,
    depth: usize,
}

impl<'a> TraversalContext<'a> {
    fn trace_callee(&mut self, callee_name: &str) {
        if self.depth > MAX_PROPAGATION_DEPTH || self.visited_functions.contains(callee_name) {
            return;
        }
        self.visited_functions.insert(callee_name.to_string());

        if let Some(nodes) = self.graph.functions.get(callee_name) {
            for node in nodes {
                self.trace.push(node.location.clone());

                // Check if this callee contains execution sinks
                for sink in &node.sinks {
                    let path_key = (
                        self.source.description.clone(),
                        self.source.location.line,
                        sink.location.line,
                    );
                    if !self.visited_paths.contains(&path_key) {
                        self.visited_paths.insert(path_key);
                        self.new_paths.push(TaintPath {
                            source: self.source.clone(),
                            sink: sink.clone(),
                            through: self.trace.clone(),
                            confidence: 0.9,
                        });
                    }
                }

                // Recurse into calls made by this callee
                for next_call in &self.graph.call_sites {
                    if next_call.file_path == node.file_path && next_call.caller_name == node.name {
                        self.trace.push(next_call.location.clone());
                        self.depth += 1;
                        self.trace_callee(&next_call.callee_name);
                        self.depth -= 1;
                        self.trace.pop();
                    }
                }

                self.trace.pop();
            }
        }

        self.visited_functions.remove(callee_name);
    }
}

/// Analyze analysis bundles and enrich target DataSurface with interprocedural taint paths.
pub(crate) fn analyze_and_enrich_targets(bundles: &mut [AnalysisBundle]) {
    for bundle in bundles {
        let call_graph = CallGraph::build(&bundle.target);
        let interprocedural_paths = propagate_interprocedural_taint(&bundle.target, &call_graph);

        for path in interprocedural_paths {
            if !bundle.target.data.taint_paths.iter().any(|p| {
                p.source.location.line == path.source.location.line
                    && p.sink.location.line == path.sink.location.line
            }) {
                bundle.target.data.taint_paths.push(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Language;
    use crate::ir::data_surface::{DataSurface, TaintSinkType, TaintSourceType};
    use crate::ir::dependency_surface::DependencySurface;
    use crate::ir::execution_surface::ExecutionSurface;
    use crate::ir::provenance_surface::ProvenanceSurface;
    use crate::ir::tool_surface::ToolSurface;

    #[test]
    fn test_cross_function_command_injection_propagation() {
        let py_code = r#"
def helper_run(cmd):
    import subprocess
    subprocess.run(cmd, shell=True)

@mcp.tool()
def execute_tool(user_query: str):
    helper_run(user_query)
"#;
        let file_path = PathBuf::from("server.py");

        let target = ScanTarget {
            name: "test-mcp".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("/test"),
            source_files: vec![crate::ir::SourceFile {
                path: file_path.clone(),
                language: Language::Python,
                content: py_code.into(),
                size_bytes: py_code.len() as u64,
                content_hash: "hash".into(),
            }],
            dependencies: DependencySurface::default(),
            data: DataSurface {
                sources: vec![TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "Tool 'execute_tool' parameter 'user_query'".into(),
                    location: SourceLocation {
                        file: file_path.clone(),
                        line: 7,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    },
                }],
                sinks: vec![TaintSink {
                    sink_type: TaintSinkType::ProcessExec,
                    description: "Process execution via subprocess.run".into(),
                    location: SourceLocation {
                        file: file_path.clone(),
                        line: 4,
                        column: 4,
                        end_line: None,
                        end_column: None,
                    },
                }],
                taint_paths: vec![],
            },
            tools: vec![ToolSurface {
                name: "execute_tool".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                declared_permissions: vec![],
                defined_at: Some(SourceLocation {
                    file: file_path.clone(),
                    line: 7,
                    column: 0,
                    end_line: None,
                    end_column: None,
                }),
                declared_capabilities: std::collections::BTreeSet::new(),
                capability_declarations: vec![],
                observed_capabilities: std::collections::BTreeSet::new(),
                capability_observation_complete: false,
                capability_evidence: vec![],
            }],
            execution: ExecutionSurface::default(),
            provenance: ProvenanceSurface::default(),
        };

        let graph = CallGraph::build(&target);
        assert!(graph.functions.contains_key("helper_run"));
        assert!(graph.functions.contains_key("execute_tool"));

        let paths = propagate_interprocedural_taint(&target, &graph);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source.source_type, TaintSourceType::ToolArgument);
        assert_eq!(paths[0].sink.sink_type, TaintSinkType::ProcessExec);
        assert!(!paths[0].through.is_empty());
    }

    #[test]
    fn test_cross_function_typescript_ssrf_propagation() {
        let ts_code = r#"
async function sendHttpRequest(targetUrl: string) {
    return await fetch(targetUrl);
}

export async function handleApiRequest(urlInput: string) {
    return await sendHttpRequest(urlInput);
}
"#;
        let file_path = PathBuf::from("index.ts");

        let target = ScanTarget {
            name: "test-ts-agent".into(),
            framework: crate::ir::Framework::OpenClaw,
            root_path: PathBuf::from("/test-ts"),
            source_files: vec![crate::ir::SourceFile {
                path: file_path.clone(),
                language: Language::TypeScript,
                content: ts_code.into(),
                size_bytes: ts_code.len() as u64,
                content_hash: "hash-ts".into(),
            }],
            dependencies: DependencySurface::default(),
            data: DataSurface {
                sources: vec![TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "Tool 'handleApiRequest' parameter 'urlInput'".into(),
                    location: SourceLocation {
                        file: file_path.clone(),
                        line: 6,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    },
                }],
                sinks: vec![TaintSink {
                    sink_type: TaintSinkType::HttpRequest,
                    description: "HTTP fetch request".into(),
                    location: SourceLocation {
                        file: file_path.clone(),
                        line: 3,
                        column: 4,
                        end_line: None,
                        end_column: None,
                    },
                }],
                taint_paths: vec![],
            },
            tools: vec![ToolSurface {
                name: "handleApiRequest".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                declared_permissions: vec![],
                defined_at: Some(SourceLocation {
                    file: file_path.clone(),
                    line: 6,
                    column: 0,
                    end_line: None,
                    end_column: None,
                }),
                declared_capabilities: std::collections::BTreeSet::new(),
                capability_declarations: vec![],
                observed_capabilities: std::collections::BTreeSet::new(),
                capability_observation_complete: false,
                capability_evidence: vec![],
            }],
            execution: ExecutionSurface::default(),
            provenance: ProvenanceSurface::default(),
        };

        let graph = CallGraph::build(&target);
        assert!(graph.functions.contains_key("sendHttpRequest"));
        assert!(graph.functions.contains_key("handleApiRequest"));

        let paths = propagate_interprocedural_taint(&target, &graph);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source.source_type, TaintSourceType::ToolArgument);
        assert_eq!(paths[0].sink.sink_type, TaintSinkType::HttpRequest);
        assert!(!paths[0].through.is_empty());
    }
}
