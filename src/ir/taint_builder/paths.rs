use crate::ir::data_surface::{TaintPath, TaintSink, TaintSinkType, TaintSource, TaintSourceType};
use crate::ir::execution_surface::{ExecutionSurface, FileOpType};
use crate::ir::{ArgumentSource, SinkClass, SourceLocation};

/// Build 1-hop taint paths connecting sources to sinks via tainted arguments.
///
/// For each operation that uses a tainted `ArgumentSource`, finds or creates
/// a matching `TaintSource` and connects it to the operation's sink.
pub(crate) fn build_taint_paths(
    sources: &[TaintSource],
    execution: &ExecutionSurface,
) -> Vec<TaintPath> {
    let mut paths = Vec::new();

    // Commands with tainted args
    for cmd in &execution.commands {
        if cmd.command_arg.is_tainted_for_sink(SinkClass::Command) {
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
        if net.url_arg.is_tainted_for_sink(SinkClass::NetworkUrl) {
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
        if matches!(file_op.operation, FileOpType::Write)
            && file_op.path_arg.is_tainted_for_sink(SinkClass::FilePath)
        {
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
        if dyn_exec
            .code_arg
            .is_tainted_for_sink(SinkClass::DynamicExec)
        {
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
pub(crate) fn resolve_source(
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
pub(crate) fn confidence_for_arg(arg: &ArgumentSource) -> f32 {
    match arg {
        ArgumentSource::Parameter { .. } => 0.9,
        ArgumentSource::Interpolated => 0.8,
        ArgumentSource::EnvVar { .. } => 0.7,
        ArgumentSource::Unknown => 0.5,
        ArgumentSource::Literal(_) | ArgumentSource::Sanitized { .. } => 0.1,
    }
}
