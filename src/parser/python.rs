use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use super::{CallSite, FunctionDef, LanguageParser, ParsedFile};
use crate::analysis::cross_file::{sanitizer_category, sanitizer_label, SanitizerCategory};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language, SourceLocation};

pub struct PythonParser;

// Dangerous subprocess/exec functions
static SUBPROCESS_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "os.exec",
        "os.execv",
        "os.execve",
        "os.execvp",
    ]
});

// GitPython's `repo.git.*` methods are dynamic dispatchers that execute
// `git <method> ...` as shell commands. We match the `.git.` segment.
static GITPYTHON_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(\w+)\.git\.(\w+)\s*\(([^)]*)\)").unwrap());

static NETWORK_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.request",
        "urllib.request.urlopen",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        // httpx.AsyncClient and aiohttp.ClientSession are tracked via
        // HTTP_CLIENT_CTX_RE + HTTP_CLIENT_METHODS instead, so their actual
        // method calls (client.get, session.post) are detected as network ops.
    ]
});

// HTTP method names used on client variables (e.g. `client.get(url)` where
// `client` was bound from `httpx.AsyncClient()` or `aiohttp.ClientSession()`).
// Checked separately from NETWORK_PATTERNS because the caller object is a
// variable, not a known module.
static HTTP_CLIENT_METHODS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "get", "post", "put", "patch", "delete", "head", "options", "request", "fetch", "send",
    ]
});

// Regex to detect async context managers that produce HTTP clients.
// Matches: `async with httpx.AsyncClient(...) as <name>:`
//          `async with aiohttp.ClientSession(...) as <name>:`
static HTTP_CLIENT_CTX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)async\s+with\s+(?:\w+\.)*(?:AsyncClient|ClientSession)\s*\([^)]*\)\s+as\s+(\w+)",
    )
    .unwrap()
});

static DYNAMIC_EXEC_PATTERNS: Lazy<Vec<&str>> =
    Lazy::new(|| vec!["eval", "exec", "compile", "__import__"]);

static SENSITIVE_ENV_VARS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)").unwrap()
});

static FILE_READ_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["open", "pathlib.Path"]);

// Regex to find function calls with arguments: func_name(args)
static CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(\w+(?:\.\w+)*)\s*\(([^)]*)\)").unwrap());

// Regex to find the start of a multi-line call: func_name( with no closing )
// Captures the function name so we can match it against patterns, then look
// ahead to the next line(s) for the first argument.
static PARTIAL_CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+(?:\.\w+)*)\s*\(\s*$").unwrap());

// Regex to find os.environ / os.getenv patterns
static ENV_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)os\.(?:environ\s*(?:\[\s*["']([^"']+)["']\s*\]|\.get\s*\(\s*["']([^"']+)["'])|getenv\s*\(\s*["']([^"']+)["']\s*\))"#,
    )
    .unwrap()
});

// Regex to find function definitions and their parameters
static FUNC_DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)").unwrap());

// Sanitizer assignment: valid_path = validate_path(x) or valid_path = await validate_path(x)
static SANITIZER_ASSIGN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+)\s*=\s*(?:await\s+)?(\w+(?:\.\w+)*)\s*\(").unwrap());

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

            let mut func_params = Vec::new();
            for param in params_str.split(',') {
                let param = param.trim().split(':').next().unwrap_or("").trim();
                let param = param.split('=').next().unwrap_or("").trim();
                if !param.is_empty() && param != "self" && param != "cls" {
                    param_names.insert(param.to_string());
                    func_params.push(param.to_string());
                }
            }

            // Find line number for this function def
            let func_line = content[..cap.get(0).map(|m| m.start()).unwrap_or(0)]
                .lines()
                .count()
                + 1;

            parsed.function_defs.push(FunctionDef {
                name: func_name.to_string(),
                params: func_params,
                is_exported,
                location: loc(&file_path, func_line),
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

        // Scan line by line for patterns
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with('#') {
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
                let is_sensitive = SENSITIVE_ENV_VARS.is_match(&var_name);
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

                let arg_source = classify_argument(args_str, &param_names, &parsed.sanitized_vars);

                // Record CallSite for cross-file analysis
                let all_args = args_str
                    .split(',')
                    .map(|a| classify_argument(a.trim(), &param_names, &parsed.sanitized_vars))
                    .collect::<Vec<_>>();
                parsed.call_sites.push(CallSite {
                    callee: func_name.to_string(),
                    arguments: all_args,
                    caller: None, // Could be improved with indentation tracking
                    location: loc(&file_path, line_num),
                });

                // Subprocess/command execution
                if SUBPROCESS_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    parsed.commands.push(CommandInvocation {
                        function: func_name.to_string(),
                        command_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
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
                        location: loc(&file_path, line_num),
                    });
                }

                // Dynamic exec
                if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                    parsed.dynamic_exec.push(DynamicExec {
                        function: func_name.to_string(),
                        code_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
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
                        location: loc(&file_path, line_num),
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
                                location: loc(&file_path, line_num),
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
                parsed.commands.push(CommandInvocation {
                    function: full_call,
                    command_arg: arg_source,
                    location: loc(&file_path, line_num),
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
                // Look ahead to find the first argument on the next non-empty line
                let first_arg_str = lines
                    .get(line_idx + 1)
                    .map(|l| l.trim().trim_end_matches(','))
                    .unwrap_or("");
                let arg_source =
                    classify_argument(first_arg_str, &param_names, &parsed.sanitized_vars);

                // Check all pattern categories for partial calls
                if SUBPROCESS_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    parsed.commands.push(CommandInvocation {
                        function: func_name.to_string(),
                        command_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
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
                        location: loc(&file_path, line_num),
                    });
                }
                if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                    parsed.dynamic_exec.push(DynamicExec {
                        function: func_name.to_string(),
                        code_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
                    });
                }
                if FILE_READ_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    parsed.file_operations.push(FileOperation {
                        operation: FileOpType::Read,
                        path_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
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
                                location: loc(&file_path, line_num),
                            });
                        }
                    }
                }
            }
        }

        Ok(parsed)
    }
}

/// Classify a call argument string to determine its source.
fn classify_argument(
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

    // String literal
    if (first_arg.starts_with('"') && first_arg.ends_with('"'))
        || (first_arg.starts_with('\'') && first_arg.ends_with('\''))
    {
        let val = &first_arg[1..first_arg.len() - 1];
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

fn sanitized_var_marker(var_name: &str, sanitizer_label: &str) -> String {
    format!("{var_name}::{sanitizer_label}")
}

fn sanitized_label_for_var(
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

fn loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
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
