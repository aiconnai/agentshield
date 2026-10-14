use std::collections::HashSet;

use crate::analysis::cross_file::SanitizerCategory;

pub(crate) fn sanitized_var_marker(var_name: &str, sanitizer_label: &str) -> String {
    format!("{var_name}::{sanitizer_label}")
}

pub(crate) fn sanitized_label_for_var(
    ident: &str,
    sanitized_vars: &HashSet<String>,
) -> Option<String> {
    for category in [
        SanitizerCategory::Path,
        SanitizerCategory::Network,
        SanitizerCategory::TypeCoercion,
    ] {
        let prefix = format!("{ident}::{}:", category.as_str());
        let mut matches: Vec<&str> = sanitized_vars
            .iter()
            .filter(|value| value.starts_with(&prefix))
            .map(|s| s.as_str())
            .collect();
        matches.sort();
        if let Some(marker) = matches.first() {
            return marker.split_once("::").map(|(_, label)| label.to_string());
        }
    }

    sanitized_vars.contains(ident).then(|| ident.to_string())
}
