use std::path::{Path, PathBuf};

use super::{CallSite, FunctionDef, FunctionParam, LanguageParser, ParsedFile};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language};

pub struct PythonParser;

pub mod classify;
pub mod patterns;

use crate::analysis::cross_file::{SanitizerCategory, sanitizer_category, sanitizer_label};
use crate::analysis::sensitivity::looks_sensitive_name;
use classify::*;
use patterns::*;

impl LanguageParser for PythonParser {
    fn language(&self) -> Language {
        Language::Python
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parsed = ParsedFile::default();
        let file_path = PathBuf::from(path);

        // Detect sanitizer assignments: safe_path = validate_path(x)
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

        // Collect function parameter names + FunctionDef entries
        let mut param_names = std::collections::HashSet::new();
        for cap in FUNC_DEF_RE.captures_iter(content) {
            let func_name = &cap[1];
            let params_str = &cap[2];
            // In Python, functions starting with _ are conventionally private
            let is_exported = !func_name.starts_with('_');
            let func_line = content[..cap.get(0).map(|m| m.start()).unwrap_or(0)]
                .lines()
                .count()
                + 1;
            let function_location = loc(&file_path, func_line);

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

        // Collect variable names bound to HTTP clients via async context managers
        // e.g. `async with httpx.AsyncClient() as client:` → "client"
        let mut http_client_vars = std::collections::HashSet::new();
        for cap in HTTP_CLIENT_CTX_RE.captures_iter(content) {
            http_client_vars.insert(cap[1].to_string());
        }

        // Collect lines for look-ahead on multi-line calls
        let lines: Vec<&str> = content.lines().collect();

        // Scan line by line for patterns. Keep the enclosing function context
        // so Python call sites have the same caller metadata as TypeScript.
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
                    location: loc(&file_path, line_num),
                });
            }

            // Check function calls
            for cap in CALL_RE.captures_iter(line) {
                let func_name = &cap[1];
                let args_str = &cap[2];
                let call_range = cap.get(0).expect("call capture");
                let call_location = loc_from_range(
                    &file_path,
                    line_num,
                    line,
                    call_range.start(),
                    call_range.end(),
                );

                let arg_source = classify_argument(args_str, &param_names, &parsed.sanitized_vars);

                // Record CallSite for cross-file analysis
                let all_args = args_str
                    .split(',')
                    .map(|a| classify_argument(a.trim(), &param_names, &parsed.sanitized_vars))
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
                let arg_source = classify_argument(args_str, &param_names, &parsed.sanitized_vars);
                let call_range = cap.get(0).expect("GitPython call capture");
                parsed.commands.push(CommandInvocation {
                    function: full_call,
                    command_arg: arg_source,
                    location: loc_from_range(
                        &file_path,
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
                    &file_path,
                    line_num,
                    line,
                    trim_offset + call_range.start(),
                    trim_offset + call_range.end(),
                );
                // Look ahead to find the first argument on the next non-empty line
                let first_arg_str = lines
                    .get(line_idx + 1)
                    .map(|l| l.trim().trim_end_matches(','))
                    .unwrap_or("");
                let arg_source =
                    classify_argument(first_arg_str, &param_names, &parsed.sanitized_vars);
                parsed.call_sites.push(CallSite {
                    callee: func_name.to_string(),
                    arguments: vec![arg_source.clone()],
                    caller: current_functions.last().map(|(name, _)| name.clone()),
                    location: call_location.clone(),
                });

                // Check all pattern categories for partial calls
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
                if NETWORK_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    let sends_data = func_name.contains("post")
                        || func_name.contains("put")
                        || func_name.contains("patch");
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
                if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                    parsed.dynamic_exec.push(DynamicExec {
                        function: func_name.to_string(),
                        code_arg: arg_source.clone(),
                        location: call_location.clone(),
                    });
                }
                if FILE_READ_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    parsed.file_operations.push(FileOperation {
                        operation: FileOpType::Read,
                        path_arg: arg_source.clone(),
                        location: call_location.clone(),
                    });
                }

                // HTTP client variable methods (multi-line)
                if func_name.contains('.') {
                    let parts: Vec<&str> = func_name.rsplitn(2, '.').collect();
                    if parts.len() == 2 {
                        let method = parts[0];
                        let obj = parts[1];
                        if http_client_vars.contains(obj) && HTTP_CLIENT_METHODS.contains(&method) {
                            let sends_data =
                                method == "post" || method == "put" || method == "patch";
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
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_subprocess_with_param() {
        let code = r#"
def handle(cmd: str):
    subprocess.run(cmd, shell=True)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(
            parsed.commands[0].command_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_requests_get_with_param() {
        let code = r#"
def fetch(url: str):
    requests.get(url)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn safe_literal_not_flagged_as_param() {
        let code = r#"
def fetch():
    requests.get("https://api.example.com")
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Literal(_)
        ));
    }

    #[test]
    fn incomplete_quote_argument_is_unknown_not_panic() {
        let code = r#"
def fetch():
    requests.get(
        "
    )
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Unknown
        ));
    }

    #[test]
    fn detects_env_var_access() {
        let code = r#"
key = os.environ["AWS_SECRET_ACCESS_KEY"]
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.env_accesses.len(), 1);
        assert!(parsed.env_accesses[0].is_sensitive);
    }

    #[test]
    fn detects_eval() {
        let code = r#"
def run(code):
    eval(code)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.dynamic_exec.len(), 1);
        assert!(matches!(
            parsed.dynamic_exec[0].code_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_httpx_async_client_get() {
        let code = r#"
async def fetch(url: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert_eq!(parsed.network_operations[0].function, "client.get");
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_aiohttp_client_session_post() {
        let code = r#"
async def send_data(url: str, data):
    async with aiohttp.ClientSession() as session:
        await session.post(url, json=data)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert_eq!(parsed.network_operations[0].function, "session.post");
        assert!(parsed.network_operations[0].sends_data);
    }

    #[test]
    fn detects_gitpython_command_execution() {
        let code = r#"
def git_log(repo, args):
    repo.git.log(*args)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].function, "repo.git.log");
    }

    #[test]
    fn detects_gitpython_add_with_user_files() {
        let code = r#"
def stage_files(repo, files):
    repo.git.add("--", *files)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].function, "repo.git.add");
    }

    #[test]
    fn no_false_positive_on_non_client_get() {
        let code = r#"
def process():
    result = cache.get("key")
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert!(parsed.network_operations.is_empty());
    }

    #[test]
    fn detects_multiline_async_client_get() {
        // Real-world pattern from the MCP fetch server
        let code = r#"
async def fetch_url(url: str):
    async with AsyncClient(proxies=proxy_url) as client:
        response = await client.get(
            url,
            follow_redirects=True,
            headers={"User-Agent": user_agent},
        )
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(
            parsed.network_operations.len(),
            1,
            "should detect multi-line client.get() call"
        );
        assert_eq!(parsed.network_operations[0].function, "client.get");
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_multiline_subprocess_run() {
        let code = r#"
def execute(cmd: str):
    subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
    )
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(
            parsed.commands.len(),
            1,
            "should detect multi-line subprocess.run() call"
        );
    }

    // ── Cross-file support tests ──

    #[test]
    fn extracts_python_function_defs() {
        let code = r#"
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

def _internal_helper(x):
    return x + 1
"#;
        let parsed = PythonParser.parse_file(Path::new("lib.py"), code).unwrap();
        assert!(parsed.function_defs.len() >= 2);

        let read_file = parsed.function_defs.iter().find(|d| d.name == "read_file");
        assert!(read_file.is_some());
        assert!(read_file.unwrap().is_exported); // no underscore prefix
        assert_eq!(read_file.unwrap().params, vec!["path"]);

        let helper = parsed
            .function_defs
            .iter()
            .find(|d| d.name == "_internal_helper");
        assert!(helper.is_some());
        assert!(!helper.unwrap().is_exported); // underscore prefix = private
    }

    #[test]
    fn records_nested_and_method_params_with_locations() {
        let code = r#"
class Handler:
    def handle(self, url: str):
        def inner(path: str):
            return open(path)
        return inner(url)
"#;
        let parsed = PythonParser
            .parse_file(Path::new("handler.py"), code)
            .unwrap();

        let handle = parsed
            .function_defs
            .iter()
            .find(|def| def.name == "handle")
            .unwrap();
        let inner = parsed
            .function_defs
            .iter()
            .find(|def| def.name == "inner")
            .unwrap();
        assert_eq!(handle.params, vec!["url"]);
        assert_eq!(inner.params, vec!["path"]);
        assert!(
            parsed
                .function_params
                .iter()
                .any(|param| param.function_name == "inner" && param.param_name == "path")
        );
        assert_eq!(inner.location.end_line, Some(inner.location.line));

        let inner_call = parsed
            .call_sites
            .iter()
            .find(|site| site.callee == "inner")
            .unwrap();
        assert_eq!(inner_call.caller.as_deref(), Some("handle"));
        assert_eq!(inner_call.location.end_line, Some(inner_call.location.line));
        assert!(inner_call.location.column > 0);
    }

    #[test]
    fn detects_python_sanitizer_assignment() {
        let code = r#"
def handler(raw_path: str):
    safe_path = os.path.realpath(raw_path)
    with open(safe_path) as f:
        return f.read()
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert!(parsed.sanitized_vars.contains("safe_path"));
    }

    #[test]
    fn extracts_python_call_sites() {
        let code = r#"
def handler(args):
    safe_path = os.path.realpath(args.path)
    content = read_file(safe_path)
    return content
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        let rf_call = parsed.call_sites.iter().find(|cs| cs.callee == "read_file");
        assert!(rf_call.is_some(), "Should find read_file call site");
        let rf = rf_call.unwrap();
        assert!(!rf.arguments.is_empty());
        assert!(
            matches!(&rf.arguments[0], ArgumentSource::Sanitized { .. }),
            "safe_path should be Sanitized, got: {:?}",
            rf.arguments[0]
        );
    }

    #[test]
    fn urlparse_assignment_is_not_sanitized_for_ssrf() {
        let code = r#"
from urllib.parse import urlparse
import requests

def handler(url: str):
    parsed_url = urlparse(url)
    return requests.get(parsed_url)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();

        assert!(!parsed.sanitized_vars.contains("parsed_url"));
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(
            parsed.network_operations[0].url_arg.is_tainted(),
            "urlparse output must remain tainted for network sinks"
        );
    }

    #[test]
    fn redaction_assignment_is_not_sanitized_for_file_paths() {
        let code = r#"
def redactSecret(value: str) -> str:
    return value.replace("secret", "[REDACTED]")

def handler(path: str):
    redacted_path = redactSecret(path)
    return open(redacted_path).read()
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();

        assert!(!parsed.sanitized_vars.contains("redacted_path"));
        assert_eq!(parsed.file_operations.len(), 1);
        assert!(
            parsed.file_operations[0].path_arg.is_tainted(),
            "redaction output must remain tainted for file path sinks"
        );
    }
}
