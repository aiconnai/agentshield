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

    fn python_target(code: &str, source_line: usize, sink_line: usize) -> ScanTarget {
        let file_path = PathBuf::from("server.py");
        let location = |line| SourceLocation {
            file: file_path.clone(),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        };
        ScanTarget {
            name: "test-mcp".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("/test"),
            source_files: vec![crate::ir::SourceFile {
                path: file_path.clone(),
                language: Language::Python,
                content: code.into(),
                size_bytes: code.len() as u64,
                content_hash: "hash".into(),
            }],
            dependencies: DependencySurface::default(),
            data: DataSurface {
                sources: vec![TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "Tool 'entry' parameter 'q'".into(),
                    location: location(source_line),
                }],
                sinks: vec![TaintSink {
                    sink_type: TaintSinkType::ProcessExec,
                    description: "Process execution via subprocess.run".into(),
                    location: location(sink_line),
                }],
                taint_paths: vec![],
            },
            tools: vec![],
            execution: ExecutionSurface::default(),
            provenance: ProvenanceSurface::default(),
        }
    }

    #[test]
    fn shorter_path_reexpands_function_first_reached_at_depth_limit() {
        // `a` reaches `g` first through a chain that lands exactly on the
        // depth limit, then calls `g` directly. The direct call must still
        // reach the sink behind `g`.
        let chain = propagate::MAX_PROPAGATION_DEPTH - 1;
        let mut code = String::from("def sink_fn(x):\n    subprocess.run(x, shell=True)\n\n");
        code.push_str("def g(x):\n    sink_fn(x)\n\n");
        for i in (1..=chain).rev() {
            let next = if i == chain {
                "g".to_string()
            } else {
                format!("c{}", i + 1)
            };
            code.push_str(&format!("def c{i}(x):\n    {next}(x)\n\n"));
        }
        code.push_str("def a(x):\n    c1(x)\n    g(x)\n\n");
        code.push_str("@mcp.tool()\ndef entry(q: str):\n    a(q)\n");
        let source_line = code
            .lines()
            .position(|l| l.starts_with("def entry"))
            .unwrap()
            + 1;
        let target = python_target(&code, source_line, 2);

        let graph = CallGraph::build(&target);
        let paths = propagate_interprocedural_taint(&target, &graph);

        assert!(
            paths.iter().any(|path| path.sink.location.line == 2),
            "expected a taint path to sink_fn, got {paths:?}"
        );
    }

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

    #[test]
    fn test_typed_arrow_function_and_no_spurious_call_sites() {
        let ts_code = r#"
const helperExec = async (cmd: string): Promise<void> => {
    child_process.execSync(cmd);
};

export async function runTool(userInput: string) {
    return await helperExec(userInput);
}
"#;
        let file_path = PathBuf::from("index.ts");
        let target = ScanTarget {
            name: "test-ts-arrow".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("/test-ts-arrow"),
            source_files: vec![crate::ir::SourceFile {
                path: file_path.clone(),
                language: Language::TypeScript,
                content: ts_code.into(),
                size_bytes: ts_code.len() as u64,
                content_hash: "hash-arrow".into(),
            }],
            dependencies: DependencySurface::default(),
            data: DataSurface {
                sources: vec![TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "Tool param 'userInput'".into(),
                    location: SourceLocation {
                        file: file_path.clone(),
                        line: 6,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    },
                }],
                sinks: vec![TaintSink {
                    sink_type: TaintSinkType::ProcessExec,
                    description: "ExecSync sink".into(),
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
        assert!(
            graph.functions.contains_key("helperExec"),
            "Typed arrow function must be captured in CallGraph"
        );
        assert!(graph.functions.contains_key("runTool"));

        // Verify no spurious self-call on runTool definition line
        let self_calls = graph
            .call_sites
            .iter()
            .filter(|c| c.caller_name == "runTool" && c.callee_name == "runTool")
            .count();
        assert_eq!(
            self_calls, 0,
            "Function signature must not create spurious self-call"
        );

        let paths = propagate_interprocedural_taint(&target, &graph);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].sink.sink_type, TaintSinkType::ProcessExec);
    }
}
