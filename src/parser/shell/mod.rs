pub(crate) mod classify;
pub(crate) mod patterns;
pub(crate) mod position;
pub(crate) mod quote;

use std::path::{Path, PathBuf};

use classify::{loc, network_argument, shell_arg_source};
use patterns::{
    BACKTICK_RE, CURL_WGET_RE, EVAL_RE, INSTALL_RE, PATH_SANITIZER_ASSIGN_RE, SENSITIVE_VAR_RE,
    SHELL_C_RE,
};
use position::is_command_position;
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
            if EVAL_RE
                .find_iter(trimmed)
                .any(|found| is_command_position(trimmed, found.start()))
            {
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

            // sh -c "$script": the script argument runs as shell code
            let mut runs_shell_script = false;
            for cap in SHELL_C_RE.captures_iter(trimmed) {
                let shell = cap.get(1).expect("shell capture");
                if !is_command_position(trimmed, shell.start()) {
                    continue;
                }
                runs_shell_script = true;
                let command_arg = if let Some(script) = cap.get(3) {
                    // Single quotes: the calling shell expands nothing.
                    ArgumentSource::Literal(script.as_str().to_string())
                } else {
                    let script = cap.get(2).or_else(|| cap.get(4)).map_or("", |m| m.as_str());
                    shell_arg_source(script, &parsed.sanitized_vars)
                };
                parsed.commands.push(CommandInvocation {
                    function: format!("{} -c", shell.as_str()),
                    command_arg,
                    location: loc(&file_path, line_num),
                });
            }

            // pip/npm install. Only where the package manager is executed:
            // `echo "cargo install ${x}"` just prints the words. A `sh -c`
            // script on the same line is already recorded above.
            if !runs_shell_script
                && INSTALL_RE
                    .find_iter(trimmed)
                    .any(|found| is_command_position(trimmed, found.start()))
            {
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

    fn shell_commands(code: &str) -> Vec<crate::ir::execution_surface::CommandInvocation> {
        ShellParser
            .parse_file(Path::new("test.sh"), code)
            .unwrap()
            .commands
    }

    #[test]
    fn echo_mentioning_cargo_install_is_not_a_command() {
        let code = "echo \"docs/site.js cargo install snippet does not match v${version}\"\n";
        assert!(shell_commands(code).is_empty());
    }

    #[test]
    fn grep_pattern_with_variable_is_not_a_command_or_eval() {
        let code =
            "grep -Fq \"agentshield ${version}\" README.md\ngrep -Fq \"eval ${version}\" notes\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert!(parsed.commands.is_empty());
        assert!(parsed.dynamic_exec.is_empty());
    }

    #[test]
    fn executed_install_in_substitution_or_chain_is_still_a_command() {
        let code = "cd app && npm install \"$pkg\"\nout=\"$(pip install $pkg)\"\n";
        let commands = shell_commands(code);
        assert_eq!(commands.len(), 2);
        assert!(commands.iter().all(|c| c.function == "package_install"));
    }

    #[test]
    fn eval_stays_dynamic_exec() {
        let code = "eval \"$x\"\nx=$(eval \"$y\")\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.dynamic_exec.len(), 2);
    }

    #[test]
    fn shell_dash_c_with_variable_is_a_command() {
        let code = "sh -c \"$1\"\nbash -c \"$cmd\"\n/bin/sh -c \"echo $user\"\n";
        let commands = shell_commands(code);
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].function, "sh -c");
        assert!(matches!(
            commands[0].command_arg,
            ArgumentSource::Parameter { .. }
        ));
        assert_eq!(commands[1].function, "bash -c");
        assert!(matches!(
            commands[1].command_arg,
            ArgumentSource::EnvVar { .. }
        ));
        assert_eq!(commands[2].function, "/bin/sh -c");
    }

    #[test]
    fn shell_dash_c_with_fixed_or_single_quoted_script_is_literal() {
        let code = "sh -c 'echo $HOME'\nbash -c \"echo hello\"\n";
        let commands = shell_commands(code);
        assert_eq!(commands.len(), 2);
        assert!(
            commands
                .iter()
                .all(|c| matches!(c.command_arg, ArgumentSource::Literal(_)))
        );
    }

    #[test]
    fn script_named_like_a_shell_is_not_dash_c() {
        let code = "./deploy.sh -c \"$1\"\necho \"sh -c $1\"\n";
        assert!(shell_commands(code).is_empty());
    }

    #[test]
    fn install_inside_dash_c_is_reported_once() {
        let code = "bash -c \"npm install $pkg\"\n";
        assert_eq!(shell_commands(code).len(), 1);
    }
}
