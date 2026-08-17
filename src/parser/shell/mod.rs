pub(crate) mod classify;
pub(crate) mod patterns;
pub(crate) mod quote;

use std::path::{Path, PathBuf};

use classify::{loc, network_argument, shell_arg_source};
use patterns::{
    BACKTICK_RE, CURL_WGET_RE, EVAL_RE, INSTALL_RE, PATH_SANITIZER_ASSIGN_RE, SENSITIVE_VAR_RE,
};
use quote::is_active_backtick;

use super::{LanguageParser, ParsedFile};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language};

pub struct ShellParser;

impl LanguageParser for ShellParser {
    fn language(&self) -> Language {
        Language::Shell
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parsed = ParsedFile::default();
        let file_path = PathBuf::from(path);

        for capture in PATH_SANITIZER_ASSIGN_RE.captures_iter(content) {
            let variable = capture.get(1).expect("sanitizer variable capture").as_str();
            let helper = capture.get(2).expect("sanitizer helper capture").as_str();
            parsed.sanitized_vars.insert(variable.to_string());
            parsed
                .sanitized_vars
                .insert(format!("{variable}::path:{helper}"));
        }

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // curl/wget = network operations
            if let Some(cap) = CURL_WGET_RE.find(trimmed) {
                let func = cap.as_str().trim();
                let command_offset = line.find(trimmed).unwrap_or_default() + cap.end();
                let (url_arg, url_location) = network_argument(
                    func,
                    &line[command_offset..],
                    command_offset,
                    &file_path,
                    line_num,
                );
                let arg_source = shell_arg_source(&url_arg, &parsed.sanitized_vars);
                parsed.network_operations.push(NetworkOperation {
                    function: func.to_string(),
                    url_arg: arg_source,
                    method: None,
                    sends_data: trimmed.contains("-d ") || trimmed.contains("--data"),
                    location: url_location,
                });
            }

            // eval
            if EVAL_RE.is_match(trimmed) {
                parsed.dynamic_exec.push(DynamicExec {
                    function: "eval".into(),
                    code_arg: shell_arg_source(trimmed, &parsed.sanitized_vars),
                    location: loc(&file_path, line_num),
                });
            }

            // backtick execution
            for mat in BACKTICK_RE.find_iter(trimmed) {
                if is_active_backtick(trimmed, mat.start()) {
                    parsed.commands.push(CommandInvocation {
                        function: "backtick".into(),
                        command_arg: ArgumentSource::Interpolated,
                        location: loc(&file_path, line_num),
                    });
                }
            }

            // pip/npm install
            if INSTALL_RE.is_match(trimmed) {
                parsed.commands.push(CommandInvocation {
                    function: "package_install".into(),
                    command_arg: shell_arg_source(trimmed, &parsed.sanitized_vars),
                    location: loc(&file_path, line_num),
                });
            }

            // Sensitive env var access
            for cap in SENSITIVE_VAR_RE.captures_iter(trimmed) {
                let var = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                parsed.env_accesses.push(EnvAccess {
                    var_name: ArgumentSource::Literal(var.to_string()),
                    is_sensitive: true,
                    location: loc(&file_path, line_num),
                });
            }
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_curl() {
        let code = "curl https://example.com/data\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Literal(_)
        ));
        assert_eq!(parsed.network_operations[0].location.end_line, Some(1));
    }

    #[test]
    fn classifies_positional_environment_and_sanitized_shell_sources() {
        let code = r#"
curl "$1"
curl "https://$API_HOST/v1"
safe_path="$(realpath "$1")"
curl "$safe_path"
"#;
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { ref name } if name == "$1"
        ));
        assert!(matches!(
            parsed.network_operations[1].url_arg,
            ArgumentSource::EnvVar { ref name } if name == "API_HOST"
        ));
        assert!(matches!(
            parsed.network_operations[2].url_arg,
            ArgumentSource::Sanitized { ref sanitizer } if sanitizer == "path:realpath"
        ));
    }

    #[test]
    fn classifies_the_curl_url_not_a_data_option() {
        let code = "curl --data \"$payload\" https://api.example.test/v1\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Literal(ref url) if url == "https://api.example.test/v1"
        ));
        assert!(parsed.network_operations[0].location.column > 0);
    }

    #[test]
    fn classifies_explicit_curl_url_option() {
        let code = "curl --url \"$1\" --data payload\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { ref name } if name == "$1"

        ));
    }

    #[test]
    fn detects_eval() {
        let code = "eval $USER_INPUT\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.dynamic_exec.len(), 1);
    }

    #[test]
    fn detects_pip_install() {
        let code = "pip install requests\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(parsed.commands[0].function.contains("package_install"));
    }

    #[test]
    fn detects_backticks() {
        let code = "echo `whoami`";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].function, "backtick");
    }

    #[test]
    fn ignores_escaped_backticks() {
        let code = "echo \\`whoami\\`";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 0);
    }

    #[test]
    fn ignores_single_quoted_backticks() {
        let code = "echo '`whoami`'\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 0);
    }

    #[test]
    fn detects_backticks_after_apostrophe_in_double_quotes() {
        let code = "echo \"it's\" `whoami`";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
    }

    #[test]
    fn detects_double_escaped_backticks() {
        // e.g. \\`whoami` - the backslash is escaped, so the backtick is active
        let code = "echo \\\\`whoami`";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
    }

    #[test]
    fn detects_multiple_backticks_per_line() {
        let code = "res=\"`cmd1` `cmd2`\"";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 2);
    }

    #[test]
    fn detects_aria2c_and_httpie() {
        let code = "aria2c https://example.com/file.tar.gz\nhttp https://api.example.com/data\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 2);
        assert_eq!(parsed.network_operations[0].function, "aria2c");
        assert_eq!(parsed.network_operations[1].function, "http");
    }

    #[test]
    fn detects_cargo_gem_and_go_install() {
        let code = "cargo install evil-crate\ngem install evil-gem\ngo install github.com/evil/pkg@latest\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.commands.len(), 3);
        assert!(
            parsed
                .commands
                .iter()
                .all(|c| c.function == "package_install")
        );
    }
}
