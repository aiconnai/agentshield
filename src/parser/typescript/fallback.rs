#[cfg(not(feature = "typescript"))]
use std::collections::HashSet;
#[cfg(not(feature = "typescript"))]
use std::path::{Path, PathBuf};

#[cfg(not(feature = "typescript"))]
use crate::analysis::sensitivity::looks_sensitive_name;
#[cfg(not(feature = "typescript"))]
use crate::error::Result;
#[cfg(not(feature = "typescript"))]
use crate::ir::execution_surface::*;
#[cfg(not(feature = "typescript"))]
use crate::ir::{ArgumentSource, SourceLocation};
#[cfg(not(feature = "typescript"))]
use crate::parser::{CallSite, FunctionDef, FunctionParam, ParsedFile};

#[cfg(not(feature = "typescript"))]
use super::classify::{classify_argument_with_sanitizers, detect_sanitizer_assignments};
#[cfg(not(feature = "typescript"))]
use super::patterns::{
    CALL_RE, DYNAMIC_EXEC_PATTERNS, ENV_ACCESS_RE, EXEC_PATTERNS, FILE_PATTERNS, FUNC_DEF_RE,
    NETWORK_PATTERNS, matches_pattern,
};

#[cfg(not(feature = "typescript"))]
pub(super) fn parse_file_fallback(path: &Path, content: &str) -> Result<ParsedFile> {
    let mut parsed = ParsedFile::default();
    let file_path = PathBuf::from(path);
    let mut param_names = HashSet::new();

    // Phase 0: Detect sanitizer assignments
    detect_sanitizer_assignments(content, &mut parsed.sanitized_vars);

    // Collect function parameter names + FunctionDef entries
    for cap in FUNC_DEF_RE.captures_iter(content) {
        let params_str = cap
            .get(2)
            .or_else(|| cap.get(4))
            .or_else(|| cap.get(6))
            .map(|m| m.as_str())
            .unwrap_or("");
        let func_name = cap
            .get(1)
            .or_else(|| cap.get(3))
            .or_else(|| cap.get(5))
            .map(|m| m.as_str())
            .unwrap_or("");

        let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        let is_exported = full_match.starts_with("export");

        let mut func_params = Vec::new();
        for param in params_str.split(',') {
            let param = param.trim();
            if param.starts_with('{') || param.starts_with('[') {
                continue;
            }
            let param = param.split(':').next().unwrap_or("").trim();
            let param = param.split('=').next().unwrap_or("").trim();
            let param = param.trim_start_matches("...");
            let param = param.trim_end_matches('?');
            if !param.is_empty() && param != "this" {
                param_names.insert(param.to_string());
                func_params.push(param.to_string());
                parsed.function_params.push(FunctionParam {
                    function_name: func_name.to_string(),
                    param_name: param.to_string(),
                    location: regex_loc(&file_path, 0),
                });
            }
        }

        if !func_name.is_empty() {
            parsed.function_defs.push(FunctionDef {
                name: func_name.to_string(),
                params: func_params,
                is_exported,
                location: regex_loc(&file_path, 0),
            });
        }
    }

    // Scan line by line
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
            continue;
        }

        for cap in ENV_ACCESS_RE.captures_iter(line) {
            let var_name = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let is_sensitive = looks_sensitive_name(&var_name);
            parsed.env_accesses.push(EnvAccess {
                var_name: ArgumentSource::Literal(var_name),
                is_sensitive,
                location: regex_loc(&file_path, line_num),
            });
        }

        for cap in CALL_RE.captures_iter(line) {
            let func_name = &cap[1];
            let args_str = &cap[2];
            let arg_source = classify_argument_with_sanitizers(
                args_str,
                &param_names,
                &parsed.sanitized_vars,
            );

            // Record CallSite
            let all_args = args_str
                .split(',')
                .map(|a| {
                    classify_argument_with_sanitizers(
                        a.trim(),
                        &param_names,
                        &parsed.sanitized_vars,
                    )
                })
                .collect::<Vec<_>>();
            parsed.call_sites.push(CallSite {
                callee: func_name.to_string(),
                arguments: all_args,
                caller: None, // Regex path can't easily determine enclosing function
                location: regex_loc(&file_path, line_num),
            });

            if matches_pattern(func_name, &EXEC_PATTERNS) {
                parsed.commands.push(CommandInvocation {
                    function: func_name.to_string(),
                    command_arg: arg_source.clone(),
                    location: regex_loc(&file_path, line_num),
                });
            }

            if matches_pattern(func_name, &NETWORK_PATTERNS) {
                let sends_data = func_name.contains("post")
                    || func_name.contains("put")
                    || func_name.contains("patch")
                    || args_str.contains("body:")
                    || args_str.contains("data:");
                let method = if func_name.contains("get") {
                    Some("GET".into())
                } else if func_name.contains("post") {
                    Some("POST".into())
                } else if func_name.contains("put") {
                    Some("PUT".into())
                } else {
                    None
                };
                parsed.network_operations.push(NetworkOperation {
                    function: func_name.to_string(),
                    url_arg: arg_source.clone(),
                    method,
                    sends_data,
                    location: regex_loc(&file_path, line_num),
                });
            }

            if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                parsed.dynamic_exec.push(DynamicExec {
                    function: func_name.to_string(),
                    code_arg: arg_source.clone(),
                    location: regex_loc(&file_path, line_num),
                });
            }

            if matches_pattern(func_name, &FILE_PATTERNS) {
                let op_type = if func_name.contains("write") || func_name.contains("append") {
                    FileOpType::Write
                } else if func_name.contains("unlink") {
                    FileOpType::Delete
                } else if func_name.contains("readdir") {
                    FileOpType::List
                } else {
                    FileOpType::Read
                };
                parsed.file_operations.push(FileOperation {
                    operation: op_type,
                    path_arg: arg_source.clone(),
                    location: regex_loc(&file_path, line_num),
                });
            }
        }
    }

    Ok(parsed)
}

#[cfg(not(feature = "typescript"))]
fn regex_loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}
