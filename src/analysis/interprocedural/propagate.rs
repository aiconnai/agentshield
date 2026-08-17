use std::collections::HashSet;

use crate::analysis::AnalysisBundle;
use crate::ir::data_surface::{TaintPath, TaintSource};
use crate::ir::{ScanTarget, SourceLocation};

use super::types::CallGraph;

pub const MAX_PROPAGATION_DEPTH: usize = 16;

pub(crate) struct TraversalContext<'a> {
    graph: &'a CallGraph,
    source: &'a TaintSource,
    trace: Vec<SourceLocation>,
    visited_functions: HashSet<String>,
    visited_paths: &'a mut HashSet<(
        std::path::PathBuf,
        usize,
        std::path::PathBuf,
        usize,
        crate::ir::data_surface::TaintSinkType,
    )>,
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
                        self.source.location.file.clone(),
                        self.source.location.line,
                        sink.location.file.clone(),
                        sink.location.line,
                        sink.sink_type,
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

/// Analyze analysis bundles and enrich target DataSurface with interprocedural taint paths.
pub(crate) fn analyze_and_enrich_targets(bundles: &mut [AnalysisBundle]) {
    for bundle in bundles {
        let call_graph = CallGraph::build(&bundle.target);
        let interprocedural_paths = propagate_interprocedural_taint(&bundle.target, &call_graph);

        for path in interprocedural_paths {
            if !bundle.target.data.taint_paths.iter().any(|p| {
                p.source.location.file == path.source.location.file
                    && p.source.location.line == path.source.location.line
                    && p.sink.location.file == path.sink.location.file
                    && p.sink.location.line == path.sink.location.line
            }) {
                bundle.target.data.taint_paths.push(path);
            }
        }
    }
}
