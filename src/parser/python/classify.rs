use crate::analysis::cross_file::SanitizerCategory;
use crate::ir::ArgumentSource;
use crate::ir::SourceLocation;
use std::path::Path;

/// Classify a call argument string to determine its source.
pub(crate) fn classify_argument(
    args_str: &str,
    param_names: &std::collections::HashSet<String>,
    sanitized_vars: &std::collections::HashSet<String>,
) -> ArgumentSource {
    let first_arg = args_str.split(',').next().unwrap_or("").trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // Check if this is a sanitized variable first
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    let ident = ident.split('[').next().unwrap_or(ident);
    if let Some(sanitizer) = sanitized_label_for_var(ident, sanitized_vars) {
        return ArgumentSource::Sanitized { sanitizer };
    }

    // String literal. Single quote tokens can appear when a regex-level parse
    // sees an incomplete multiline literal; keep those conservative.
    if let Some(val) = strip_python_string_literal(first_arg) {
        return ArgumentSource::Literal(val.to_string());
    }

    // f-string or format
    if first_arg.starts_with("f\"") || first_arg.starts_with("f'") || first_arg.contains(".format(")
    {
        return ArgumentSource::Interpolated;
    }

    // os.environ / env var
    if first_arg.contains("os.environ") || first_arg.contains("os.getenv") {
        return ArgumentSource::EnvVar {
            name: first_arg.to_string(),
        };
    }

    // Known function parameter
    if param_names.contains(ident) {
        return ArgumentSource::Parameter {
            name: ident.to_string(),
        };
    }

    ArgumentSource::Unknown
}

pub(crate) fn strip_python_string_literal(arg: &str) -> Option<&str> {
    arg.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            arg.strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
}

pub(crate) fn sanitized_var_marker(var_name: &str, sanitizer_label: &str) -> String {
    format!("{var_name}::{sanitizer_label}")
}

pub(crate) fn sanitized_label_for_var(
    ident: &str,
    sanitized_vars: &std::collections::HashSet<String>,
) -> Option<String> {
    for category in [
        SanitizerCategory::Path,
        SanitizerCategory::Network,
        SanitizerCategory::TypeCoercion,
    ] {
        let prefix = format!("{}:", category.as_str());
        if let Some(marker) = sanitized_vars
            .iter()
            .find(|value| value.starts_with(&format!("{ident}::{prefix}")))
        {
            return marker.split_once("::").map(|(_, label)| label.to_string());
        }
    }

    sanitized_vars.contains(ident).then(|| ident.to_string())
}

pub(crate) fn loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: Some(line),
        end_column: Some(0),
    }
}

pub(crate) fn loc_from_range(
    file: &Path,
    line: usize,
    source_line: &str,
    start_byte: usize,
    end_byte: usize,
) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: source_line[..start_byte].chars().count(),
        end_line: Some(line),
        end_column: Some(source_line[..end_byte].chars().count()),
    }
}
