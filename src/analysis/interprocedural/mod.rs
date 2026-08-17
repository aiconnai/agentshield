//! Interprocedural call-graph and cross-function taint propagation engine (milestone v1.0.0).
//!
//! Analyzes cross-function and cross-method control/data flow across Python and TypeScript
//! agent extensions. Connects tool input parameters that are passed through intermediate
//! helper functions, utility wrappers, and class methods to downstream execution sinks.

pub mod propagate;
pub mod python;
pub mod types;
pub mod typescript;

pub(crate) use propagate::analyze_and_enrich_targets;
pub use propagate::propagate_interprocedural_taint;
pub use types::{CallGraph, CallSite, FunctionNode};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::data_surface::{
        DataSurface, TaintSink, TaintSinkType, TaintSource, TaintSourceType,
    };
    use crate::ir::dependency_surface::DependencySurface;
    use crate::ir::execution_surface::ExecutionSurface;
    use crate::ir::provenance_surface::ProvenanceSurface;
    use crate::ir::tool_surface::ToolSurface;
    use crate::ir::{Language, ScanTarget, SourceLocation};
    use std::path::PathBuf;

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

    #[test]
    fn test_allman_style_typescript_function_brace() {
        let ts_code =
            "function executeCommand(cmd: string)\n{\n    return child_process.execSync(cmd);\n}\n";
        let file_path = PathBuf::from("exec.ts");

        let target = ScanTarget {
            name: "test-allman-ts".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("/test-allman"),
            source_files: vec![crate::ir::SourceFile {
                path: file_path.clone(),
                language: Language::TypeScript,
                content: ts_code.into(),
                size_bytes: ts_code.len() as u64,
                content_hash: "hash-allman".into(),
            }],
            dependencies: DependencySurface::default(),
            data: DataSurface {
                sources: vec![TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "Tool parameter 'cmd'".into(),
                    location: SourceLocation {
                        file: file_path.clone(),
                        line: 1,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    },
                }],
                sinks: vec![TaintSink {
                    sink_type: TaintSinkType::ProcessExec,
                    description: "ExecSync command".into(),
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
            tools: vec![],
            execution: ExecutionSurface::default(),
            provenance: ProvenanceSurface::default(),
        };

        let graph = CallGraph::build(&target);
        assert!(graph.functions.contains_key("executeCommand"));
        let node = &graph.functions["executeCommand"][0];
        assert_eq!(
            node.sinks.len(),
            1,
            "Sink on line 3 must be captured inside Allman brace function boundary"
        );
    }

    #[test]
    fn test_multi_file_line_collision_preserves_distinct_sinks() {
        let py_code_a = "def run_task(q):\n    return helper(q)\n";
        let py_code_b = "def helper(q):\n    subprocess.run(q, shell=True)\n";
        let file_a = PathBuf::from("pkg/a.py");
        let file_b = PathBuf::from("pkg/b.py");

        let target = ScanTarget {
            name: "test-multi-file-collision".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("/test-multi"),
            source_files: vec![
                crate::ir::SourceFile {
                    path: file_a.clone(),
                    language: Language::Python,
                    content: py_code_a.into(),
                    size_bytes: py_code_a.len() as u64,
                    content_hash: "hash-a".into(),
                },
                crate::ir::SourceFile {
                    path: file_b.clone(),
                    language: Language::Python,
                    content: py_code_b.into(),
                    size_bytes: py_code_b.len() as u64,
                    content_hash: "hash-b".into(),
                },
            ],
            dependencies: DependencySurface::default(),
            data: DataSurface {
                sources: vec![TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "Param 'q'".into(),
                    location: SourceLocation {
                        file: file_a.clone(),
                        line: 1,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    },
                }],
                sinks: vec![TaintSink {
                    sink_type: TaintSinkType::ProcessExec,
                    description: "Subprocess sink".into(),
                    location: SourceLocation {
                        file: file_b.clone(),
                        line: 2,
                        column: 4,
                        end_line: None,
                        end_column: None,
                    },
                }],
                taint_paths: vec![],
            },
            tools: vec![],
            execution: ExecutionSurface::default(),
            provenance: ProvenanceSurface::default(),
        };

        let graph = CallGraph::build(&target);
        let paths = propagate_interprocedural_taint(&target, &graph);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source.location.file, file_a);
        assert_eq!(paths[0].sink.location.file, file_b);
    }
}
