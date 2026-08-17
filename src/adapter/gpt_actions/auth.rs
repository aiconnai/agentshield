use std::path::Path;

use crate::analysis::sensitivity::looks_sensitive_name;
use crate::ir::execution_surface::{EnvAccess, ExecutionSurface};
use crate::ir::{ArgumentSource, SourceLocation};

/// Extract security schemes from OpenAPI components and register them as sensitive environment accesses
pub(crate) fn extract_security_schemes(
    spec: &serde_json::Value,
    spec_path: &Path,
    execution: &mut ExecutionSurface,
) {
    let schemes = match spec
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(|s| s.as_object())
    {
        Some(s) => s,
        None => return,
    };

    for (name, scheme) in schemes {
        let scheme_type = scheme
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("apiKey");
        let header_or_var_name = scheme
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or(name.as_str());

        let is_sensitive = looks_sensitive_name(header_or_var_name)
            || scheme_type == "oauth2"
            || scheme_type == "http"
            || scheme_type == "apiKey";

        execution.env_accesses.push(EnvAccess {
            is_sensitive,
            var_name: ArgumentSource::Literal(format!("auth:{header_or_var_name}")),
            location: SourceLocation {
                file: spec_path.to_path_buf(),
                line: 1,
                column: 0,
                end_line: None,
                end_column: None,
            },
        });
    }
}
