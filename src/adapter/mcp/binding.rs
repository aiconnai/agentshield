use std::path::PathBuf;

use crate::ir::SourceLocation;
use crate::ir::execution_surface::ExecutionSurface;
use crate::parser;

use super::tools::{McpToolDeclaration, McpToolHandler};

#[derive(Debug, Clone)]
pub(crate) struct McpToolOperationBinding {
    pub(crate) execution: ExecutionSurface,
    pub(crate) handler_resolved: bool,
    pub(crate) observation_complete: bool,
    pub(crate) resolved_callees: Vec<String>,
    pub(crate) handler_location: Option<SourceLocation>,
}

impl McpToolOperationBinding {
    pub(crate) fn is_consistent(&self) -> bool {
        self.handler_resolved
            || (self.execution.commands.is_empty()
                && self.execution.file_operations.is_empty()
                && self.execution.network_operations.is_empty()
                && self.execution.env_accesses.is_empty()
                && self.execution.dynamic_exec.is_empty()
                && !self.observation_complete
                && self.resolved_callees.is_empty())
    }
}

#[cfg(feature = "typescript")]
pub(crate) struct ResolvedMcpHandler {
    pub(crate) span: SourceLocation,
    pub(crate) caller: Option<String>,
}

#[cfg(feature = "typescript")]
pub(crate) fn bind_mcp_tool_operations(
    declarations: &[McpToolDeclaration],
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Vec<McpToolOperationBinding> {
    declarations
        .iter()
        .map(|declaration| {
            let Some(handler) = resolve_handler(declaration, parsed_files) else {
                return McpToolOperationBinding {
                    execution: ExecutionSurface::default(),
                    handler_resolved: false,
                    observation_complete: false,
                    resolved_callees: Vec::new(),
                    handler_location: None,
                };
            };

            let mut resolved_callees = call_sites_for_handler(parsed_files, &handler)
                .filter_map(|call_site| {
                    resolve_unique_function_span(&call_site.callee, parsed_files)
                        .map(|span| (call_site.callee.clone(), span))
                })
                .collect::<Vec<_>>();
            resolved_callees.sort_by(|left, right| left.0.cmp(&right.0));
            resolved_callees.dedup_by(|left, right| left.0 == right.0);

            let handler_span = handler.span.clone();
            let mut scopes = Vec::with_capacity(resolved_callees.len() + 1);
            scopes.push((handler_span.clone(), handler.caller));
            scopes.extend(
                resolved_callees
                    .iter()
                    .map(|(name, span)| (span.clone(), Some(name.clone()))),
            );

            let execution = execution_within_scopes(parsed_files, &scopes);
            let observation_complete =
                binding_observation_complete(parsed_files, &scopes, &resolved_callees, &execution);

            McpToolOperationBinding {
                execution,
                handler_resolved: true,
                observation_complete,
                resolved_callees: resolved_callees.into_iter().map(|(name, _)| name).collect(),
                handler_location: Some(handler_span),
            }
        })
        .collect()
}

#[cfg(not(feature = "typescript"))]
pub(crate) fn bind_mcp_tool_operations(
    declarations: &[McpToolDeclaration],
    _parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Vec<McpToolOperationBinding> {
    declarations
        .iter()
        .map(|_| McpToolOperationBinding {
            execution: ExecutionSurface::default(),
            handler_resolved: false,
            observation_complete: false,
            resolved_callees: Vec::new(),
            handler_location: None,
        })
        .collect()
}

#[cfg(feature = "typescript")]
pub(crate) fn resolve_handler(
    declaration: &McpToolDeclaration,
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Option<ResolvedMcpHandler> {
    match declaration.handler.as_ref()? {
        McpToolHandler::Inline { location } => parsed_files
            .iter()
            .any(|(path, _)| path == &location.file)
            .then(|| ResolvedMcpHandler {
                span: location.clone(),
                caller: None,
            }),
        McpToolHandler::Named { symbol } => {
            resolve_unique_function_span(symbol, parsed_files).map(|span| ResolvedMcpHandler {
                span,
                caller: Some(symbol.clone()),
            })
        }
    }
}

#[cfg(feature = "typescript")]
pub(crate) fn resolve_unique_function_span(
    symbol: &str,
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> Option<SourceLocation> {
    let mut matches = parsed_files.iter().flat_map(|(_, parsed)| {
        parsed
            .function_defs
            .iter()
            .filter(move |definition| definition.name == symbol)
    });
    let location = matches.next()?.location.clone();
    matches.next().is_none().then_some(location)
}

#[cfg(feature = "typescript")]
pub(crate) fn call_sites_for_handler<'a>(
    parsed_files: &'a [(PathBuf, parser::ParsedFile)],
    handler: &'a ResolvedMcpHandler,
) -> impl Iterator<Item = &'a parser::CallSite> {
    parsed_files
        .iter()
        .flat_map(|(_, parsed)| parsed.call_sites.iter())
        .filter(|call_site| {
            location_within_span(&call_site.location, &handler.span)
                && match handler.caller.as_deref() {
                    Some(caller) => call_site.caller.as_deref() == Some(caller),
                    None => call_site.caller.is_none(),
                }
        })
}

#[cfg(feature = "typescript")]
pub(crate) fn execution_within_scopes(
    parsed_files: &[(PathBuf, parser::ParsedFile)],
    scopes: &[(SourceLocation, Option<String>)],
) -> ExecutionSurface {
    let contains = |location: &SourceLocation| {
        scopes.iter().any(|(span, function_name)| {
            operation_belongs_to_scope(location, span, function_name.as_deref(), parsed_files)
        })
    };
    let mut execution = ExecutionSurface::default();
    for (_, parsed) in parsed_files {
        execution.commands.extend(
            parsed
                .commands
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.file_operations.extend(
            parsed
                .file_operations
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.network_operations.extend(
            parsed
                .network_operations
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.env_accesses.extend(
            parsed
                .env_accesses
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
        execution.dynamic_exec.extend(
            parsed
                .dynamic_exec
                .iter()
                .filter(|operation| contains(&operation.location))
                .cloned(),
        );
    }
    execution
}

#[cfg(feature = "typescript")]
pub(crate) fn binding_observation_complete(
    parsed_files: &[(PathBuf, parser::ParsedFile)],
    scopes: &[(SourceLocation, Option<String>)],
    resolved_callees: &[(String, SourceLocation)],
    execution: &ExecutionSurface,
) -> bool {
    if !execution.dynamic_exec.is_empty() {
        return false;
    }

    parsed_files
        .iter()
        .flat_map(|(_, parsed)| parsed.call_sites.iter())
        .filter(|call_site| {
            scopes.iter().any(|(span, function_name)| {
                operation_belongs_to_scope(
                    &call_site.location,
                    span,
                    function_name.as_deref(),
                    parsed_files,
                )
            })
        })
        .all(|call_site| {
            call_is_modeled(call_site, execution)
                || resolved_callees
                    .iter()
                    .any(|(name, _)| name == &call_site.callee)
        })
}

#[cfg(feature = "typescript")]
pub(crate) fn call_is_modeled(call_site: &parser::CallSite, execution: &ExecutionSurface) -> bool {
    execution
        .commands
        .iter()
        .any(|operation| operation.location == call_site.location)
        || execution
            .file_operations
            .iter()
            .any(|operation| operation.location == call_site.location)
        || execution
            .network_operations
            .iter()
            .any(|operation| operation.location == call_site.location)
        || execution
            .env_accesses
            .iter()
            .any(|operation| operation.location == call_site.location)
}

#[cfg(feature = "typescript")]
pub(crate) fn operation_belongs_to_scope(
    location: &SourceLocation,
    span: &SourceLocation,
    function_name: Option<&str>,
    parsed_files: &[(PathBuf, parser::ParsedFile)],
) -> bool {
    if !location_within_span(location, span) {
        return false;
    }

    let innermost = parsed_files
        .iter()
        .flat_map(|(_, parsed)| parsed.function_defs.iter())
        .filter(|definition| {
            location_within_span(&definition.location, span)
                && location_within_span(location, &definition.location)
        })
        .max_by_key(|definition| (definition.location.line, definition.location.column));

    match (function_name, innermost) {
        (Some(expected), Some(definition)) => definition.name == expected,
        (Some(_), None) => false,
        (None, None) => true,
        (None, Some(_)) => false,
    }
}

#[cfg(feature = "typescript")]
pub(crate) fn location_within_span(location: &SourceLocation, span: &SourceLocation) -> bool {
    if location.file != span.file {
        return false;
    }
    let start = (location.line, location.column);
    let span_start = (span.line, span.column);
    let span_end = (
        span.end_line.unwrap_or(span.line),
        span.end_column.unwrap_or(usize::MAX),
    );
    start >= span_start && start < span_end
}
