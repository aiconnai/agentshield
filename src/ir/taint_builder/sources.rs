use std::path::PathBuf;

use crate::ir::data_surface::{TaintSource, TaintSourceType};
use crate::ir::execution_surface::ExecutionSurface;
use crate::ir::tool_surface::ToolSurface;
use crate::ir::{ArgumentSource, SourceLocation};

/// Collect taint sources from tool input schemas and environment accesses.
pub(crate) fn collect_sources(
    tools: &[ToolSurface],
    execution: &ExecutionSurface,
) -> Vec<TaintSource> {
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
