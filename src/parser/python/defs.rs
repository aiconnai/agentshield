use std::collections::HashSet;
use std::path::Path;

use crate::analysis::cross_file::{SanitizerCategory, sanitizer_category, sanitizer_label};
use crate::parser::{FunctionDef, FunctionParam, ParsedFile};

use super::classify::{loc, sanitized_var_marker};
use super::patterns::{FUNC_DEF_RE, HTTP_CLIENT_CTX_RE, SANITIZER_ASSIGN_RE};

pub(crate) fn collect_sanitizer_vars(content: &str, parsed: &mut ParsedFile) {
    for cap in SANITIZER_ASSIGN_RE.captures_iter(content) {
        let var_name = &cap[1];
        let func_name = &cap[2];
        if sanitizer_category(func_name)
            .is_some_and(|category| !matches!(category, SanitizerCategory::Redaction))
        {
            parsed.sanitized_vars.insert(var_name.to_string());
            if let Some(label) = sanitizer_label(func_name) {
                parsed
                    .sanitized_vars
                    .insert(sanitized_var_marker(var_name, &label));
            }
        }
    }
}

pub(crate) fn collect_function_defs_and_params(
    content: &str,
    file_path: &Path,
    parsed: &mut ParsedFile,
) -> HashSet<String> {
    let mut param_names = HashSet::new();
    for cap in FUNC_DEF_RE.captures_iter(content) {
        let func_name = &cap[1];
        let params_str = &cap[2];
        // In Python, functions starting with _ are conventionally private
        let is_exported = !func_name.starts_with('_');
        let func_line = content[..cap.get(0).map(|m| m.start()).unwrap_or(0)]
            .lines()
            .count()
            + 1;
        let function_location = loc(file_path, func_line);

        let mut func_params = Vec::new();
        for param in params_str.split(',') {
            let param = param.trim().split(':').next().unwrap_or("").trim();
            let param = param.split('=').next().unwrap_or("").trim();
            if !param.is_empty() && param != "self" && param != "cls" {
                param_names.insert(param.to_string());
                func_params.push(param.to_string());
                parsed.function_params.push(FunctionParam {
                    function_name: func_name.to_string(),
                    param_name: param.to_string(),
                    location: function_location.clone(),
                });
            }
        }

        parsed.function_defs.push(FunctionDef {
            name: func_name.to_string(),
            params: func_params,
            is_exported,
            location: function_location,
        });
    }
    param_names
}

pub(crate) fn collect_http_client_vars(content: &str) -> HashSet<String> {
    let mut http_client_vars = HashSet::new();
    for cap in HTTP_CLIENT_CTX_RE.captures_iter(content) {
        http_client_vars.insert(cap[1].to_string());
    }
    http_client_vars
}
