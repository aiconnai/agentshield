use super::patterns::{SANITIZER_ASSIGN_RE, TEMPLATE_LITERAL_RE};
use crate::analysis::cross_file::{SanitizerCategory, sanitizer_category, sanitizer_label};
use crate::ir::ArgumentSource;
use std::collections::HashSet;

/// Classify all arguments in a call expression (tree-sitter path).
#[cfg(feature = "typescript")]
pub(super) fn classify_all_arguments(
    args_node: Option<tree_sitter::Node>,
    source: &[u8],
    param_names: &HashSet<String>,
    sanitized_vars: &HashSet<String>,
) -> Vec<ArgumentSource> {
    let Some(args) = args_node else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for i in 0..args.named_child_count() {
        if let Some(arg) = args.named_child(i) {
            let arg_text = super::ast::node_text(arg, source).to_string();
            result.push(classify_argument_with_sanitizers(
                &arg_text,
                param_names,
                sanitized_vars,
            ));
        }
    }
    result
}

/// Detect sanitizer assignments in source code and populate sanitized_vars.
/// Matches patterns like: `const validPath = await validatePath(x)`
pub(super) fn detect_sanitizer_assignments(content: &str, sanitized_vars: &mut HashSet<String>) {
    for cap in SANITIZER_ASSIGN_RE.captures_iter(content) {
        let var_name = &cap[1];
        let func_name = &cap[2];
        if sanitizer_category(func_name)
            .is_some_and(|category| !matches!(category, SanitizerCategory::Redaction))
        {
            sanitized_vars.insert(var_name.to_string());
            if let Some(label) = sanitizer_label(func_name) {
                sanitized_vars.insert(sanitized_var_marker(var_name, &label));
            }
        }
    }
}

pub(super) fn sanitized_var_marker(var_name: &str, sanitizer_label: &str) -> String {
    format!("{var_name}::{sanitizer_label}")
}

pub(super) fn sanitized_label_for_var(
    ident: &str,
    sanitized_vars: &HashSet<String>,
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

/// Classify an argument, considering sanitized variables.
pub(super) fn classify_argument_with_sanitizers(
    arg_text: &str,
    param_names: &HashSet<String>,
    sanitized_vars: &HashSet<String>,
) -> ArgumentSource {
    let first_arg = arg_text.split(',').next().unwrap_or("").trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // Check if this is a sanitized variable (before other checks)
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    let ident = ident.split('[').next().unwrap_or(ident);
    if let Some(sanitizer) = sanitized_label_for_var(ident, sanitized_vars) {
        return ArgumentSource::Sanitized { sanitizer };
    }

    // Delegate to existing classification
    classify_argument_text(first_arg, param_names)
}

/// Classify an argument text to determine its source.
pub(super) fn classify_argument_text(
    arg_text: &str,
    param_names: &HashSet<String>,
) -> ArgumentSource {
    let first_arg = arg_text.split(',').next().unwrap_or("").trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // String literal (double or single quoted)
    if (first_arg.starts_with('"') && first_arg.ends_with('"'))
        || (first_arg.starts_with('\'') && first_arg.ends_with('\''))
    {
        if first_arg.len() >= 2 {
            let val = &first_arg[1..first_arg.len() - 1];
            return ArgumentSource::Literal(val.to_string());
        }
        return ArgumentSource::Literal(String::new());
    }

    // Template literal with interpolation: `...${var}...`
    if first_arg.starts_with('`') {
        if TEMPLATE_LITERAL_RE.is_match(first_arg) {
            return ArgumentSource::Interpolated;
        }
        let val = first_arg.trim_matches('`');
        return ArgumentSource::Literal(val.to_string());
    }

    // String concatenation with +
    if first_arg.contains('+') && (first_arg.contains('"') || first_arg.contains('\'')) {
        return ArgumentSource::Interpolated;
    }

    // process.env reference
    if first_arg.contains("process.env") {
        return ArgumentSource::EnvVar {
            name: first_arg.to_string(),
        };
    }

    // Known function parameter
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    let ident = ident.split('[').next().unwrap_or(ident);
    if param_names.contains(ident) {
        return ArgumentSource::Parameter {
            name: ident.to_string(),
        };
    }

    ArgumentSource::Unknown
}
