use std::path::{Path, PathBuf};

use super::{LanguageParser, ParsedFile};
use crate::error::Result;
#[cfg(test)]
use crate::ir::ArgumentSource;
use crate::ir::Language;

pub struct PythonParser;

pub mod calls;
pub mod classify;
pub mod defs;
pub mod imports;
pub mod patterns;
pub mod scanner;

use defs::{
    collect_entry_points, collect_function_defs_and_params, collect_http_client_vars,
    collect_sanitizer_vars,
};
use scanner::scan_python_source;

impl LanguageParser for PythonParser {
    fn language(&self) -> Language {
        Language::Python
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parsed = ParsedFile::default();
        let file_path = PathBuf::from(path);

        // Detect sanitizer assignments: safe_path = validate_path(x)
        collect_sanitizer_vars(content, &mut parsed);

        // Collect function parameter names + FunctionDef entries
        let param_names = collect_function_defs_and_params(content, &file_path, &mut parsed);
        collect_entry_points(content, &mut parsed);

        // Collect variable names bound to HTTP clients via async context managers
        let http_client_vars = collect_http_client_vars(content);

        // Scan line by line for patterns and call sites
        scan_python_source(
            content,
            &file_path,
            &param_names,
            &http_client_vars,
            &mut parsed,
        );

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

    fn first_command(code: &str) -> crate::ir::execution_surface::CommandInvocation {
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1, "commands: {:?}", parsed.commands);
        parsed.commands.into_iter().next().unwrap()
    }

    #[test]
    fn multiline_concatenation_is_interpolated() {
        let code = "def f(user):\n    return os.system(\n        \"ls \"\n        + user\n        + \" -la\"\n    )\n";
        let command = first_command(code);
        assert!(matches!(command.command_arg, ArgumentSource::Interpolated));
        assert_eq!(command.location.line, 2);
    }

    #[test]
    fn multiline_subprocess_with_keyword_after_concatenation() {
        let code = "def f(user):\n    subprocess.run(\n        \"ls \"\n        + user,\n        shell=True)\n";
        assert!(matches!(
            first_command(code).command_arg,
            ArgumentSource::Interpolated
        ));
    }

    #[test]
    fn multiline_literal_and_adjacent_literals_stay_literal() {
        let one = "def f():\n    os.system(\n        \"ls -la\"\n    )\n";
        assert!(matches!(
            first_command(one).command_arg,
            ArgumentSource::Literal(ref v) if v == "ls -la"
        ));
        let adjacent = "def f():\n    os.system(\n        \"ls \"\n        \"-la\"\n    )\n";
        assert!(matches!(
            first_command(adjacent).command_arg,
            ArgumentSource::Literal(ref v) if v == "ls -la"
        ));
    }

    #[test]
    fn multiline_call_closing_paren_inside_string_or_comment_is_ignored() {
        let code =
            "def f(user):\n    os.system(\n        \"echo ) \"  # )\n        + user\n    )\n";
        assert!(matches!(
            first_command(code).command_arg,
            ArgumentSource::Interpolated
        ));
    }

    #[test]
    fn comma_inside_literal_does_not_truncate_first_argument() {
        let code = "def f():\n    os.system(\"echo a, b\")\n";
        assert!(matches!(
            first_command(code).command_arg,
            ArgumentSource::Literal(ref v) if v == "echo a, b"
        ));
    }

    #[test]
    fn multiline_call_is_recorded_once_as_a_call_site() {
        let code = "def f(user):\n    helper(\n        user,\n        1,\n    )\n";
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        let sites: Vec<_> = parsed
            .call_sites
            .iter()
            .filter(|site| site.callee == "helper")
            .collect();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].arguments.len(), 2);
        assert!(matches!(
            sites[0].arguments[0],
            ArgumentSource::Parameter { .. }
        ));
        assert_eq!(sites[0].caller.as_deref(), Some("f"));
    }

    #[test]
    fn multiline_def_header_is_not_a_call_site() {
        let code = "def helper(\n    a,\n    b,\n):\n    return a\n";
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert!(parsed.call_sites.iter().all(|site| site.callee != "helper"));
    }

    #[test]
    fn from_import_alias_is_a_subprocess_sink() {
        let code = "from subprocess import run\n\ndef f(cmd):\n    run(cmd, shell=True)\n";
        let command = first_command(code);
        assert_eq!(command.function, "subprocess.run");
        assert!(matches!(
            command.command_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn module_alias_is_a_subprocess_sink() {
        let code = "import subprocess as sp\n\ndef f(cmd):\n    sp.check_output(cmd)\n";
        assert_eq!(first_command(code).function, "subprocess.check_output");
    }

    #[test]
    fn unimported_run_is_not_a_subprocess_sink() {
        let code = "def run(cmd):\n    return cmd\n\ndef f(cmd):\n    run(cmd)\n";
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert!(parsed.commands.is_empty());
    }
}
