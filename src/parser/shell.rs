use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use super::{LanguageParser, ParsedFile};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language, SourceLocation};

pub struct ShellParser;

static CURL_WGET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)\b(curl|wget)\s+").unwrap());

static EVAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)\beval\s+").unwrap());

static INSTALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)\b(pip3?\s+install|npm\s+install|npm\s+i\b|yarn\s+add|pnpm\s+add)").unwrap()
});

static BACKTICK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"`[^`]+`").unwrap());

static SENSITIVE_VAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\$\{?(AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)").unwrap());

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellQuoteState {
    Unquoted,
    SingleQuoted,
    DoubleQuoted,
}

impl LanguageParser for ShellParser {
    fn language(&self) -> Language {
        Language::Shell
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parsed = ParsedFile::default();
        let file_path = PathBuf::from(path);

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // curl/wget = network operations
            if let Some(cap) = CURL_WGET_RE.find(trimmed) {
                let func = cap.as_str().trim();
                let arg_source = if trimmed.contains('$') {
                    ArgumentSource::Interpolated
                } else {
                    ArgumentSource::Literal(trimmed.to_string())
                };
                parsed.network_operations.push(NetworkOperation {
                    function: func.to_string(),
                    url_arg: arg_source,
                    method: None,
                    sends_data: trimmed.contains("-d ") || trimmed.contains("--data"),
                    location: loc(&file_path, line_num),
                });
            }

            // eval
            if EVAL_RE.is_match(trimmed) {
                parsed.dynamic_exec.push(DynamicExec {
                    function: "eval".into(),
                    code_arg: ArgumentSource::Interpolated,
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
                    command_arg: ArgumentSource::Literal(trimmed.to_string()),
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

fn is_active_backtick(line: &str, backtick_idx: usize) -> bool {
    let mut state = ShellQuoteState::Unquoted;
    let mut escaped = false;

    for (idx, ch) in line.char_indices() {
        if idx >= backtick_idx {
            return state != ShellQuoteState::SingleQuoted && !escaped;
        }

        if escaped {
            escaped = false;
            continue;
        }

        match (state, ch) {
            (ShellQuoteState::SingleQuoted, '\'') => state = ShellQuoteState::Unquoted,
            (ShellQuoteState::SingleQuoted, _) => {}
            (_, '\\') => escaped = state != ShellQuoteState::SingleQuoted,
            (ShellQuoteState::Unquoted, '\'') => state = ShellQuoteState::SingleQuoted,
            (ShellQuoteState::Unquoted, '"') => state = ShellQuoteState::DoubleQuoted,
            (ShellQuoteState::DoubleQuoted, '"') => state = ShellQuoteState::Unquoted,
            _ => {}
        }
    }

    false
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
    fn detects_curl() {
        let code = "curl https://example.com/data\n";
        let parsed = ShellParser.parse_file(Path::new("test.sh"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
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
}
