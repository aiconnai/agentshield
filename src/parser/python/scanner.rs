use std::collections::HashSet;
use std::path::Path;

use crate::analysis::sensitivity::looks_sensitive_name;
use crate::ir::ArgumentSource;
use crate::ir::execution_surface::*;
use crate::parser::{CallSite, ParsedFile};

use super::classify::{classify_argument, loc, loc_from_range};
use super::patterns::*;

pub(crate) fn scan_python_source(
    content: &str,
    file_path: &Path,
    param_names: &HashSet<String>,
    http_client_vars: &HashSet<String>,
    parsed: &mut ParsedFile,
) {
    let lines: Vec<&str> = content.lines().collect();
    let mut current_functions: Vec<(String, usize)> = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();

        if !trimmed.is_empty() {
            while current_functions
                .last()
                .is_some_and(|(_, function_indent)| indent <= *function_indent)
            {
                current_functions.pop();
            }
        }
        if let Some(cap) = FUNC_DEF_RE.captures(line) {
            current_functions.push((cap[1].to_string(), indent));
        }

        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // A definition header has the same `name(args)` shape as a call
        // for the regex below. It establishes scope, but is not a call
        // site and must not participate in cross-file analysis.
        if FUNC_DEF_RE.is_match(line) {
            continue;
        }

        // Check env var access
        for cap in ENV_ACCESS_RE.captures_iter(line) {
            let var_name = cap
                .get(1)
                .or_else(|| cap.get(2))
                .or_else(|| cap.get(3))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let is_sensitive = looks_sensitive_name(&var_name);
            parsed.env_accesses.push(EnvAccess {
                var_name: ArgumentSource::Literal(var_name),
                is_sensitive,
                location: loc(file_path, line_num),
            });
        }

        // Check function calls
        for cap in CALL_RE.captures_iter(line) {
            let func_name = &cap[1];
            let args_str = &cap[2];
            let call_range = cap.get(0).expect("call capture");
            let call_location = loc_from_range(
                file_path,
                line_num,
                line,
                call_range.start(),
                call_range.end(),
            );

            let arg_source = classify_argument(args_str, param_names, &parsed.sanitized_vars);

            // Record CallSite for cross-file analysis
            let all_args = args_str
                .split(',')
                .map(|a| classify_argument(a.trim(), param_names, &parsed.sanitized_vars))
                .collect::<Vec<_>>();
            parsed.call_sites.push(CallSite {
                callee: func_name.to_string(),
                arguments: all_args,
                caller: current_functions.last().map(|(name, _)| name.clone()),
                location: call_location.clone(),
            });

            // Subprocess/command execution
            if SUBPROCESS_PATTERNS
                .iter()
                .any(|p| func_name.ends_with(p) || func_name == *p)
            {
                parsed.commands.push(CommandInvocation {
                    function: func_name.to_string(),
                    command_arg: arg_source.clone(),
                    location: call_location.clone(),
                });
            }

            // Network operations
            if NETWORK_PATTERNS
                .iter()
                .any(|p| func_name.ends_with(p) || func_name == *p)
            {
                let sends_data = func_name.contains("post")
                    || func_name.contains("put")
                    || func_name.contains("patch")
                    || args_str.contains("data=")
                    || args_str.contains("json=");
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
                    location: call_location.clone(),
                });
            }

            // Dynamic exec
            if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                parsed.dynamic_exec.push(DynamicExec {
                    function: func_name.to_string(),
                    code_arg: arg_source.clone(),
                    location: call_location.clone(),
                });
            }

            // File operations (open with write mode)
            if FILE_READ_PATTERNS
                .iter()
                .any(|p| func_name.ends_with(p) || func_name == *p)
            {
                let op_type = if args_str.contains("'w")
                    || args_str.contains("\"w")
                    || args_str.contains("'a")
                    || args_str.contains("\"a")
                {
                    FileOpType::Write
                } else {
                    FileOpType::Read
                };
                parsed.file_operations.push(FileOperation {
                    operation: op_type,
                    path_arg: arg_source.clone(),
                    location: call_location.clone(),
                });
            }

            // HTTP client variable method calls (FN-1 fix):
            // Detect `client.get(url)` where `client` was bound from
            // `async with AsyncClient() as client:`.
            if func_name.contains('.') {
                let parts: Vec<&str> = func_name.rsplitn(2, '.').collect();
                if parts.len() == 2 {
                    let method = parts[0];
                    let obj = parts[1];
                    if http_client_vars.contains(obj) && HTTP_CLIENT_METHODS.contains(&method) {
                        let sends_data = method == "post"
                            || method == "put"
                            || method == "patch"
                            || args_str.contains("data=")
                            || args_str.contains("json=");
                        let http_method = match method {
                            "get" => Some("GET".into()),
                            "post" => Some("POST".into()),
                            "put" => Some("PUT".into()),
                            "delete" => Some("DELETE".into()),
                            "head" => Some("HEAD".into()),
                            "patch" => Some("PATCH".into()),
                            _ => None,
                        };
                        parsed.network_operations.push(NetworkOperation {
                            function: func_name.to_string(),
                            url_arg: arg_source.clone(),
                            method: http_method,
                            sends_data,
                            location: call_location.clone(),
                        });
                    }
                }
            }
        }

        // GitPython command execution (FN-2 fix):
        // Detect `repo.git.log(...)`, `repo.git.add(...)`, etc.
        for cap in GITPYTHON_RE.captures_iter(line) {
            let full_call = format!("{}.git.{}", &cap[1], &cap[2]);
            let args_str = &cap[3];
            let arg_source = classify_argument(args_str, param_names, &parsed.sanitized_vars);
            let call_range = cap.get(0).expect("GitPython call capture");
            parsed.commands.push(CommandInvocation {
                function: full_call,
                command_arg: arg_source,
                location: loc_from_range(
                    file_path,
                    line_num,
                    line,
                    call_range.start(),
                    call_range.end(),
                ),
            });
        }

        // Multi-line call detection: handle calls like
        //   client.get(
        //       url,
        //       follow_redirects=True,
        //   )
        // where CALL_RE fails because `(` and `)` are on different lines.
        if let Some(cap) = PARTIAL_CALL_RE.captures(trimmed) {
            let func_name = &cap[1];
            let call_range = cap.get(1).expect("partial call name capture");
            let trim_offset = line.find(trimmed).unwrap_or_default();
            let call_location = loc_from_range(
                file_path,
                line_num,
                line,
                trim_offset + call_range.start(),
                trim_offset + call_range.end(),
            );

            let is_http_client_var_call = if func_name.contains('.') {
                let parts: Vec<&str> = func_name.rsplitn(2, '.').collect();
                parts.len() == 2
                    && http_client_vars.contains(parts[1])
                    && HTTP_CLIENT_METHODS.contains(&parts[0])
            } else {
                false
            };

            let is_network = NETWORK_PATTERNS
                .iter()
                .any(|p| func_name.ends_with(p) || func_name == *p)
                || is_http_client_var_call;

            let is_subprocess = SUBPROCESS_PATTERNS
                .iter()
                .any(|p| func_name.ends_with(p) || func_name == *p);

            let is_dynamic = DYNAMIC_EXEC_PATTERNS.contains(&func_name);

            if is_network || is_subprocess || is_dynamic {
                // Look ahead up to 10 lines to find the first non-kwarg argument
                let lookahead_limit = (line_idx + 10).min(lines.len());
                let mut first_arg: Option<ArgumentSource> = None;
                for future_line in &lines[line_idx + 1..lookahead_limit] {
                    let trimmed_arg = future_line.trim().trim_end_matches(',');
                    if trimmed_arg.is_empty() || trimmed_arg.starts_with('#') {
                        continue;
                    }
                    if trimmed_arg == ")" || trimmed_arg.starts_with("):") {
                        break;
                    }
                    if trimmed_arg.contains('=') && !trimmed_arg.starts_with("url=") {
                        continue;
                    }
                    let candidate = if let Some(stripped) = trimmed_arg.strip_prefix("url=") {
                        stripped.trim()
                    } else {
                        trimmed_arg
                    };
                    first_arg = Some(classify_argument(
                        candidate,
                        param_names,
                        &parsed.sanitized_vars,
                    ));
                    break;
                }

                let arg_source = first_arg.unwrap_or(ArgumentSource::Unknown);

                if is_network {
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
                        url_arg: arg_source,
                        method,
                        sends_data: false,
                        location: call_location,
                    });
                } else if is_subprocess {
                    parsed.commands.push(CommandInvocation {
                        function: func_name.to_string(),
                        command_arg: arg_source,
                        location: call_location,
                    });
                } else if is_dynamic {
                    parsed.dynamic_exec.push(DynamicExec {
                        function: func_name.to_string(),
                        code_arg: arg_source,
                        location: call_location,
                    });
                }
            }
        }
    }
}
