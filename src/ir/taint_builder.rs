//! Builds a populated `DataSurface` from parsed tool definitions and execution surfaces.
//!
//! Called by each adapter after merging `ParsedFile` results into `ExecutionSurface`
//! and `ToolSurface`. Constructs taint sources, sinks, and 1-hop taint paths.

use std::path::PathBuf;

use super::data_surface::*;
use super::execution_surface::*;
use super::tool_surface::ToolSurface;
use super::ArgumentSource;
use super::SourceLocation;

/// Build a `DataSurface` from tool definitions and execution surface.
///
/// Extracts taint sources (tool parameters, env vars), sinks (process exec,
/// HTTP requests, file writes, dynamic eval), and connects them with 1-hop
/// taint paths when an operation uses a tainted argument.
pub fn build_data_surface(tools: &[ToolSurface], execution: &ExecutionSurface) -> DataSurface {
    let sources = collect_sources(tools, execution);
    let sinks = collect_sinks(execution);
    let taint_paths = build_taint_paths(&sources, execution);

    DataSurface {
        sources,
        sinks,
        taint_paths,
    }
}

/// Collect taint sources from tool input schemas and environment accesses.
fn collect_sources(tools: &[ToolSurface], execution: &ExecutionSurface) -> Vec<TaintSource> {
    let mut sources = Vec::new();

    // Sources from tool input parameters
    for tool in tools {
        let location = tool.defined_at.clone().unwrap_or_else(|| SourceLocation {
            file: PathBuf::from("<unknown>"),
            line: 0,
            column: 0,
            end_line: None,
            end_column: None,
        });

        if let Some(ref schema) = tool.input_schema {
            if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
                for param_name in props.keys() {
                    sources.push(TaintSource {
                        source_type: TaintSourceType::ToolArgument,
                        description: format!("Tool '{}' parameter '{}'", tool.name, param_name),
                        location: location.clone(),
                    });
                }
            }
        }
    }

    // Sources from environment variable accesses
    for env in &execution.env_accesses {
        let var_desc = match &env.var_name {
            ArgumentSource::Literal(name) => name.clone(),
            ArgumentSource::EnvVar { name } => name.clone(),
            ArgumentSource::Parameter { name } => format!("(dynamic: {})", name),
            _ => "(dynamic)".to_string(),
        };
        sources.push(TaintSource {
            source_type: TaintSourceType::EnvVariable,
            description: format!("Environment variable '{}'", var_desc),
            location: env.location.clone(),
        });
    }

    sources
}

/// Collect taint sinks from execution surface operations.
fn collect_sinks(execution: &ExecutionSurface) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    for cmd in &execution.commands {
        sinks.push(TaintSink {
            sink_type: TaintSinkType::ProcessExec,
            description: format!("Process execution via {}", cmd.function),
            location: cmd.location.clone(),
        });
    }

    for net in &execution.network_operations {
        sinks.push(TaintSink {
            sink_type: TaintSinkType::HttpRequest,
            description: format!("HTTP request via {}", net.function),
            location: net.location.clone(),
        });
    }

    for file_op in &execution.file_operations {
        if matches!(file_op.operation, FileOpType::Write) {
            sinks.push(TaintSink {
                sink_type: TaintSinkType::FileWrite,
                description: "File write operation".to_string(),
                location: file_op.location.clone(),
            });
        }
    }

    for dyn_exec in &execution.dynamic_exec {
        sinks.push(TaintSink {
            sink_type: TaintSinkType::DynamicEval,
            description: format!("Dynamic code execution via {}", dyn_exec.function),
            location: dyn_exec.location.clone(),
        });
    }

    sinks
}

/// Build 1-hop taint paths connecting sources to sinks via tainted arguments.
///
/// For each operation that uses a tainted `ArgumentSource`, finds or creates
/// a matching `TaintSource` and connects it to the operation's sink.
fn build_taint_paths(sources: &[TaintSource], execution: &ExecutionSurface) -> Vec<TaintPath> {
    let mut paths = Vec::new();

    // Commands with tainted args
    for cmd in &execution.commands {
        if cmd.command_arg.is_tainted() {
            let source = resolve_source(sources, &cmd.command_arg, &cmd.location);
            paths.push(TaintPath {
                source,
                sink: TaintSink {
                    sink_type: TaintSinkType::ProcessExec,
                    description: format!("Process execution via {}", cmd.function),
                    location: cmd.location.clone(),
                },
                through: vec![],
                confidence: confidence_for_arg(&cmd.command_arg),
            });
        }
    }

    // Network operations with tainted URL args
    for net in &execution.network_operations {
        if net.url_arg.is_tainted() {
            let source = resolve_source(sources, &net.url_arg, &net.location);
            paths.push(TaintPath {
                source,
                sink: TaintSink {
                    sink_type: TaintSinkType::HttpRequest,
                    description: format!("HTTP request via {}", net.function),
                    location: net.location.clone(),
                },
                through: vec![],
                confidence: confidence_for_arg(&net.url_arg),
            });
        }
    }

    // File write operations with tainted path args
    for file_op in &execution.file_operations {
        if matches!(file_op.operation, FileOpType::Write) && file_op.path_arg.is_tainted() {
            let source = resolve_source(sources, &file_op.path_arg, &file_op.location);
            paths.push(TaintPath {
                source,
                sink: TaintSink {
                    sink_type: TaintSinkType::FileWrite,
                    description: "File write operation".to_string(),
                    location: file_op.location.clone(),
                },
                through: vec![],
                confidence: confidence_for_arg(&file_op.path_arg),
            });
        }
    }

    // Dynamic exec with tainted code args
    for dyn_exec in &execution.dynamic_exec {
        if dyn_exec.code_arg.is_tainted() {
            let source = resolve_source(sources, &dyn_exec.code_arg, &dyn_exec.location);
            paths.push(TaintPath {
                source,
                sink: TaintSink {
                    sink_type: TaintSinkType::DynamicEval,
                    description: format!("Dynamic code execution via {}", dyn_exec.function),
                    location: dyn_exec.location.clone(),
                },
                through: vec![],
                confidence: confidence_for_arg(&dyn_exec.code_arg),
            });
        }
    }

    paths
}

/// Resolve an `ArgumentSource` to a matching `TaintSource` from the collected sources.
///
/// If the argument references a known parameter or env var that matches a source,
/// returns that source. Otherwise, creates a synthetic source for the argument.
fn resolve_source(
    sources: &[TaintSource],
    arg: &ArgumentSource,
    fallback_location: &SourceLocation,
) -> TaintSource {
    match arg {
        ArgumentSource::Parameter { name } => {
            // Try to find a matching tool argument source
            if let Some(found) = sources.iter().find(|s| {
                s.source_type == TaintSourceType::ToolArgument && s.description.contains(name)
            }) {
                return found.clone();
            }
            TaintSource {
                source_type: TaintSourceType::ToolArgument,
                description: format!("Function parameter '{}'", name),
                location: fallback_location.clone(),
            }
        }
        ArgumentSource::EnvVar { name } => {
            if let Some(found) = sources.iter().find(|s| {
                s.source_type == TaintSourceType::EnvVariable && s.description.contains(name)
            }) {
                return found.clone();
            }
            TaintSource {
                source_type: TaintSourceType::EnvVariable,
                description: format!("Environment variable '{}'", name),
                location: fallback_location.clone(),
            }
        }
        ArgumentSource::Interpolated => TaintSource {
            source_type: TaintSourceType::ToolArgument,
            description: "Interpolated string (potentially user-controlled)".to_string(),
            location: fallback_location.clone(),
        },
        ArgumentSource::Unknown => TaintSource {
            source_type: TaintSourceType::ToolArgument,
            description: "Unknown source (could not determine origin)".to_string(),
            location: fallback_location.clone(),
        },
        // Literal and Sanitized are not tainted, so they shouldn't reach here
        ArgumentSource::Literal(_) | ArgumentSource::Sanitized { .. } => TaintSource {
            source_type: TaintSourceType::ToolArgument,
            description: "Unexpected safe source".to_string(),
            location: fallback_location.clone(),
        },
    }
}

/// Assign confidence based on the argument source type.
fn confidence_for_arg(arg: &ArgumentSource) -> f32 {
    match arg {
        ArgumentSource::Parameter { .. } => 0.9,
        ArgumentSource::Interpolated => 0.8,
        ArgumentSource::EnvVar { .. } => 0.7,
        ArgumentSource::Unknown => 0.5,
        ArgumentSource::Literal(_) | ArgumentSource::Sanitized { .. } => 0.1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::tool_surface::ToolSurface;
    use crate::ir::ArgumentSource;
    use serde_json::json;
    use std::path::PathBuf;

    fn make_location(line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("test.py"),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn make_tool(name: &str, params: &[&str]) -> ToolSurface {
        let mut properties = serde_json::Map::new();
        for p in params {
            properties.insert(p.to_string(), json!({"type": "string"}));
        }
        ToolSurface {
            name: name.to_string(),
            description: Some("test tool".to_string()),
            input_schema: Some(json!({"properties": properties})),
            output_schema: None,
            declared_permissions: vec![],
            defined_at: Some(make_location(1)),
        }
    }

    #[test]
    fn test_sources_from_tool_parameters() {
        let tools = vec![make_tool("run_cmd", &["command", "cwd"])];
        let execution = ExecutionSurface::default();

        let surface = build_data_surface(&tools, &execution);

        assert_eq!(surface.sources.len(), 2);
        assert!(surface
            .sources
            .iter()
            .all(|s| s.source_type == TaintSourceType::ToolArgument));
        assert!(surface
            .sources
            .iter()
            .any(|s| s.description.contains("command")));
        assert!(surface
            .sources
            .iter()
            .any(|s| s.description.contains("cwd")));
    }

    #[test]
    fn test_sources_from_env_accesses() {
        let tools = vec![];
        let execution = ExecutionSurface {
            env_accesses: vec![EnvAccess {
                var_name: ArgumentSource::Literal("API_KEY".to_string()),
                is_sensitive: true,
                location: make_location(10),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&tools, &execution);

        assert_eq!(surface.sources.len(), 1);
        assert_eq!(surface.sources[0].source_type, TaintSourceType::EnvVariable);
        assert!(surface.sources[0].description.contains("API_KEY"));
    }

    #[test]
    fn test_sinks_from_commands() {
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "subprocess.run".to_string(),
                command_arg: ArgumentSource::Parameter {
                    name: "cmd".to_string(),
                },
                location: make_location(5),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.sinks.len(), 1);
        assert_eq!(surface.sinks[0].sink_type, TaintSinkType::ProcessExec);
        assert!(surface.sinks[0].description.contains("subprocess.run"));
    }

    #[test]
    fn test_sinks_from_network_operations() {
        let execution = ExecutionSurface {
            network_operations: vec![NetworkOperation {
                function: "requests.get".to_string(),
                url_arg: ArgumentSource::Interpolated,
                method: Some("GET".to_string()),
                sends_data: false,
                location: make_location(8),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.sinks.len(), 1);
        assert_eq!(surface.sinks[0].sink_type, TaintSinkType::HttpRequest);
    }

    #[test]
    fn test_sinks_from_file_write_only() {
        let execution = ExecutionSurface {
            file_operations: vec![
                FileOperation {
                    operation: FileOpType::Read,
                    path_arg: ArgumentSource::Parameter {
                        name: "path".to_string(),
                    },
                    location: make_location(3),
                },
                FileOperation {
                    operation: FileOpType::Write,
                    path_arg: ArgumentSource::Parameter {
                        name: "out".to_string(),
                    },
                    location: make_location(7),
                },
            ],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        // Only the Write should produce a sink
        assert_eq!(surface.sinks.len(), 1);
        assert_eq!(surface.sinks[0].sink_type, TaintSinkType::FileWrite);
        assert_eq!(surface.sinks[0].location.line, 7);
    }

    #[test]
    fn test_sinks_from_dynamic_exec() {
        let execution = ExecutionSurface {
            dynamic_exec: vec![DynamicExec {
                function: "eval".to_string(),
                code_arg: ArgumentSource::Unknown,
                location: make_location(12),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.sinks.len(), 1);
        assert_eq!(surface.sinks[0].sink_type, TaintSinkType::DynamicEval);
    }

    #[test]
    fn test_taint_path_from_parameter_to_command() {
        let tools = vec![make_tool("exec_tool", &["command"])];
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "subprocess.run".to_string(),
                command_arg: ArgumentSource::Parameter {
                    name: "command".to_string(),
                },
                location: make_location(10),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&tools, &execution);

        assert_eq!(surface.taint_paths.len(), 1);
        let path = &surface.taint_paths[0];
        assert_eq!(path.source.source_type, TaintSourceType::ToolArgument);
        assert!(path.source.description.contains("command"));
        assert_eq!(path.sink.sink_type, TaintSinkType::ProcessExec);
        assert!((path.confidence - 0.9).abs() < f32::EPSILON);
        assert!(path.through.is_empty());
    }

    #[test]
    fn test_no_taint_path_for_literal() {
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "subprocess.run".to_string(),
                command_arg: ArgumentSource::Literal("ls -la".to_string()),
                location: make_location(5),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        // Sink should exist, but no taint path (literal is safe)
        assert_eq!(surface.sinks.len(), 1);
        assert!(
            surface.taint_paths.is_empty(),
            "literal args should not produce taint paths"
        );
    }

    #[test]
    fn test_no_taint_path_for_sanitized() {
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "subprocess.run".to_string(),
                command_arg: ArgumentSource::Sanitized {
                    sanitizer: "validateCommand".to_string(),
                },
                location: make_location(5),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.sinks.len(), 1);
        assert!(
            surface.taint_paths.is_empty(),
            "sanitized args should not produce taint paths"
        );
    }

    #[test]
    fn test_interpolated_confidence() {
        let execution = ExecutionSurface {
            network_operations: vec![NetworkOperation {
                function: "requests.get".to_string(),
                url_arg: ArgumentSource::Interpolated,
                method: Some("GET".to_string()),
                sends_data: false,
                location: make_location(15),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.taint_paths.len(), 1);
        assert!((surface.taint_paths[0].confidence - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_envvar_confidence() {
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "os.system".to_string(),
                command_arg: ArgumentSource::EnvVar {
                    name: "CMD".to_string(),
                },
                location: make_location(3),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.taint_paths.len(), 1);
        assert!((surface.taint_paths[0].confidence - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_unknown_confidence() {
        let execution = ExecutionSurface {
            dynamic_exec: vec![DynamicExec {
                function: "eval".to_string(),
                code_arg: ArgumentSource::Unknown,
                location: make_location(20),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert_eq!(surface.taint_paths.len(), 1);
        assert!((surface.taint_paths[0].confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_tool_without_schema_produces_no_sources() {
        let tools = vec![ToolSurface {
            name: "no_schema".to_string(),
            description: None,
            input_schema: None,
            output_schema: None,
            declared_permissions: vec![],
            defined_at: None,
        }];

        let surface = build_data_surface(&tools, &ExecutionSurface::default());

        assert!(surface.sources.is_empty());
        assert!(surface.sinks.is_empty());
        assert!(surface.taint_paths.is_empty());
    }

    #[test]
    fn test_combined_sources_sinks_paths() {
        let tools = vec![make_tool("fetch", &["url"])];
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "subprocess.run".to_string(),
                command_arg: ArgumentSource::Literal("echo hi".to_string()),
                location: make_location(5),
            }],
            network_operations: vec![NetworkOperation {
                function: "requests.get".to_string(),
                url_arg: ArgumentSource::Parameter {
                    name: "url".to_string(),
                },
                method: Some("GET".to_string()),
                sends_data: false,
                location: make_location(10),
            }],
            env_accesses: vec![EnvAccess {
                var_name: ArgumentSource::Literal("TOKEN".to_string()),
                is_sensitive: true,
                location: make_location(2),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&tools, &execution);

        // 1 tool param source + 1 env source = 2 sources
        assert_eq!(surface.sources.len(), 2);
        // 1 command sink + 1 network sink = 2 sinks
        assert_eq!(surface.sinks.len(), 2);
        // Only network op is tainted (command is literal) = 1 path
        assert_eq!(surface.taint_paths.len(), 1);
        assert_eq!(
            surface.taint_paths[0].sink.sink_type,
            TaintSinkType::HttpRequest
        );
    }

    #[test]
    fn test_data_surface_from_vuln_fixture() {
        use crate::adapter::Adapter;

        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/vuln_cmd_inject");
        let adapter = crate::adapter::mcp::McpAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        assert_eq!(targets.len(), 1);

        let target = &targets[0];

        // The vuln_cmd_inject fixture has tainted commands, so DataSurface should be populated
        assert!(
            !target.data.sinks.is_empty(),
            "vuln_cmd_inject should produce taint sinks"
        );

        // Should have ProcessExec sinks from subprocess calls
        assert!(
            target
                .data
                .sinks
                .iter()
                .any(|s| s.sink_type == TaintSinkType::ProcessExec),
            "expected ProcessExec sink from subprocess usage"
        );

        // Should have taint paths connecting tainted args to sinks
        assert!(
            !target.data.taint_paths.is_empty(),
            "vuln_cmd_inject should produce taint paths from parameter to subprocess"
        );

        // At least one path should have high confidence (parameter source)
        assert!(
            target.data.taint_paths.iter().any(|p| p.confidence >= 0.8),
            "expected high-confidence taint path"
        );
    }
}
