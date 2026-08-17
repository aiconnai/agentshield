//! Builds a populated `DataSurface` from parsed tool definitions and execution surfaces.
//!
//! Called by each adapter after merging `ParsedFile` results into `ExecutionSurface`
//! and `ToolSurface`. Constructs taint sources, sinks, and 1-hop taint paths.

pub(crate) mod paths;
pub(crate) mod sinks;
pub(crate) mod sources;

pub(crate) use paths::build_taint_paths;
pub(crate) use sinks::collect_sinks;
pub(crate) use sources::collect_sources;

use crate::ir::data_surface::DataSurface;
use crate::ir::execution_surface::ExecutionSurface;
use crate::ir::tool_surface::ToolSurface;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
    use crate::ir::execution_surface::*;
    use crate::ir::tool_surface::ToolSurface;
    use crate::ir::{ArgumentSource, SourceLocation};

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
            declared_capabilities: Default::default(),
            capability_declarations: Vec::new(),
            observed_capabilities: Default::default(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
        }
    }

    #[test]
    fn test_sources_from_tool_parameters() {
        let tools = vec![make_tool("run_cmd", &["command", "cwd"])];
        let execution = ExecutionSurface::default();

        let surface = build_data_surface(&tools, &execution);

        assert_eq!(surface.sources.len(), 2);
        assert!(
            surface
                .sources
                .iter()
                .all(|s| s.source_type == TaintSourceType::ToolArgument)
        );
        assert!(
            surface
                .sources
                .iter()
                .any(|s| s.description.contains("command"))
        );
        assert!(
            surface
                .sources
                .iter()
                .any(|s| s.description.contains("cwd"))
        );
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
    fn test_sanitized_mismatched_sink_still_tainted() {
        // A `Sanitized` arg only suppresses a taint path when its sanitizer
        // matches the sink category. `validateCommand` is NOT a recognized
        // command sanitizer (the design only honors Path→FilePath and
        // Network→NetworkUrl), so the command sink stays tainted and a
        // taint path is still produced (issue #36).
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
            !surface.taint_paths.is_empty(),
            "sanitizer that does not match the sink must not suppress the taint path"
        );
    }

    #[test]
    fn test_sanitized_matching_sink_suppresses_path() {
        // A path sanitizer on a FilePath (write) sink IS recognized, so the
        // taint path is suppressed.
        let execution = ExecutionSurface {
            file_operations: vec![FileOperation {
                operation: FileOpType::Write,
                path_arg: ArgumentSource::Sanitized {
                    sanitizer: "validatePath".to_string(),
                },
                location: make_location(5),
            }],
            ..Default::default()
        };

        let surface = build_data_surface(&[], &execution);

        assert!(
            surface.taint_paths.is_empty(),
            "matching sanitizer should suppress the taint path"
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
            declared_capabilities: Default::default(),
            capability_declarations: Vec::new(),
            observed_capabilities: Default::default(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
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
