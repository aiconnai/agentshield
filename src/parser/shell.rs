use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use super::{LanguageParser, ParsedFile};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language, SourceLocation};

pub struct ShellParser;

static CURL_WGET_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)\b(curl|wget)\s+").expect("static regex pattern is valid"));

static EVAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)\beval\s+").expect("static regex pattern is valid"));

static INSTALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)\b(pip3?\s+install|npm\s+install|npm\s+i\b|yarn\s+add|pnpm\s+add)")
        .expect("static regex pattern is valid")
});

static BACKTICK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"`[^`]+`").expect("static regex pattern is valid"));

static SENSITIVE_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\$\{?(AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)")
        .expect("static regex pattern is valid")
});

// Shell positional arguments represent values supplied to a function or script
// invocation. Named variables can come from the caller environment.
static SHELL_VARIABLE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*)|([0-9]+|[@*#?]))")
        .expect("static regex pattern is valid")
});

// Recognize only canonicalization helpers that map to the existing path
// sanitizer contract. Quoting by itself is not a sanitizer.
static PATH_SANITIZER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)^\s*(?:local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?\$\(\s*(realpath|readlink\s+-f)\b"#,
    )
    .expect("static regex pattern is valid")
});

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

fn shell_arg_source(
    command: &str,
    sanitized_vars: &std::collections::HashSet<String>,
) -> ArgumentSource {
    if command.contains('`') || command.contains("$(") {
        return ArgumentSource::Interpolated;
    }

    let variables = SHELL_VARIABLE_RE.captures_iter(command).collect::<Vec<_>>();
    if variables.is_empty() {
        return ArgumentSource::Literal(command.to_string());
    }
    if variables.len() != 1 {
        return ArgumentSource::Interpolated;
    }

    let variable = &variables[0];
    if let Some(positional) = variable.get(3).map(|value| value.as_str()) {
        return ArgumentSource::Parameter {
            name: format!("${positional}"),
        };
    }
    let name = variable
        .get(1)
        .or_else(|| variable.get(2))
        .expect("named variable capture")
        .as_str();
    if let Some(marker) = sanitized_vars
        .iter()
        .find(|value| value.starts_with(&format!("{name}::path:")))
    {
        return ArgumentSource::Sanitized {
            sanitizer: marker
                .split_once("::")
                .expect("sanitizer marker includes separator")
                .1
                .to_string(),
        };
    }
    ArgumentSource::EnvVar {
        name: name.to_string(),
    }
}

#[derive(Debug)]
struct ShellToken {
    value: String,
    start: usize,
    end: usize,
}

fn network_argument(
    command: &str,
    args: &str,
    offset: usize,
    file: &Path,
    line: usize,
) -> (String, SourceLocation) {
    let tokens = shell_tokens(args, offset);
    let mut skip_next = false;

    for token in &tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        if let Some(url) = token.value.strip_prefix("--url=") {
            return (
                url.to_string(),
                loc_from_range(file, line, token.start + "--url=".len(), token.end),
            );
        }
        if token.value == "--url" {
            skip_next = false;
            continue;
        }
        if takes_value(command, &token.value) {
            skip_next = true;
            continue;
        }
        if token.value.starts_with('-') {
            continue;
        }
        return (
            token.value.clone(),
            loc_from_range(file, line, token.start, token.end),
        );
    }

    (String::new(), loc(file, line))
}

fn takes_value(command: &str, option: &str) -> bool {
    matches!(
        option,
        "-d" | "--data"
            | "--data-raw"
            | "--data-binary"
            | "-H"
            | "--header"
            | "-X"
            | "--request"
            | "-o"
            | "--output"
            | "-O"
            | "--output-document"
            | "-e"
            | "--referer"
            | "-A"
            | "--user-agent"
            | "-u"
            | "--user"
    ) || (command == "wget" && matches!(option, "-P" | "--directory-prefix"))
}

fn shell_tokens(input: &str, offset: usize) -> Vec<ShellToken> {
    let mut tokens = Vec::new();
    let mut token_start = None;
    let mut value = String::new();
    let mut quote = None;

    for (index, ch) in input.char_indices() {
        match quote {
            Some(current) if ch == current => quote = None,
            Some(_) => value.push(ch),
            None if matches!(ch, '\'' | '"') => {
                quote = Some(ch);
                token_start.get_or_insert(index);
            }
            None if ch.is_whitespace() => {
                if let Some(start) = token_start.take() {
                    tokens.push(ShellToken {
                        value: std::mem::take(&mut value),
                        start: offset + start,
                        end: offset + index,
                    });
                }
            }
            None => {
                token_start.get_or_insert(index);
                value.push(ch);
            }
        }
    }
    if let Some(start) = token_start {
        tokens.push(ShellToken {
            value,
            start: offset + start,
            end: offset + input.len(),
        });
    }
    tokens
}

fn loc_from_range(file: &Path, line: usize, start: usize, end: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: start,
        end_line: Some(line),
        end_column: Some(end),
    }
}

fn loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: Some(line),
        end_column: Some(0),
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
}
