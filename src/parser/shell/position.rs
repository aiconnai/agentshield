//! Whether a word on a shell line is in command position, i.e. is executed as
//! a command rather than passed as data to another command.
//!
//! `echo "see cargo install ${tool}"` mentions `cargo install` but only prints
//! it; `grep -Fq "eval ${x}" file` only searches for it. Neither runs the
//! text, so neither is a command-execution sink.

use super::quote::ShellQuoteState;

/// Commands that print, search, or test their arguments and never execute
/// them. `awk` and `sed` are deliberately absent: both can run commands.
const DATA_COMMANDS: &[&str] = &[
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "cat", "head", "tail", "wc", "tr",
    "cut", "sort", "uniq", "test", "[", "[[", "diff", "cmp",
];

/// Words that precede the real command without changing what it executes.
const WRAPPER_WORDS: &[&str] = &[
    "!", "if", "then", "elif", "else", "do", "while", "until", "time", "exec", "command", "nohup",
    "sudo", "doas", "env", "builtin",
];

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

/// True when the text at byte `start` of `line` is the start of a command that
/// the shell would execute: unquoted, or quoted as the script argument of
/// `sh -c` / `eval`, and not an argument of a print/search command.
pub(crate) fn is_command_position(line: &str, start: usize) -> bool {
    let prefix = &line[..start];
    let (state, segment) = scan_prefix(prefix);

    let mut words = segment
        .split_whitespace()
        .skip_while(|word| is_wrapper(word));
    let first = words.next();
    if first.is_some_and(|word| DATA_COMMANDS.contains(&word)) {
        return false;
    }
    if state == ShellQuoteState::Unquoted {
        return true;
    }

    // Quoted text is data, except as the script of `sh -c "..."` or `eval "..."`.
    match first {
        Some("eval") => true,
        Some(shell) => SHELLS.contains(&shell) && segment.contains(" -c"),
        None => false,
    }
}

/// Quote state at the end of `prefix`, and the text of the current simple
/// command (after the last unquoted `;`, `|`, `&`, `(`, or `` ` ``).
fn scan_prefix(prefix: &str) -> (ShellQuoteState, &str) {
    let mut state = ShellQuoteState::Unquoted;
    // Quote states suspended by an open `$(` command substitution.
    let mut suspended: Vec<ShellQuoteState> = Vec::new();
    let mut segment_start = 0;
    let mut escaped = false;
    let mut previous = '\0';

    for (idx, ch) in prefix.char_indices() {
        if escaped {
            escaped = false;
            previous = ch;
            continue;
        }
        let next_start = idx + ch.len_utf8();
        match (state, ch) {
            (ShellQuoteState::SingleQuoted, '\'') => state = ShellQuoteState::Unquoted,
            (ShellQuoteState::SingleQuoted, _) => {}
            (_, '\\') => escaped = true,
            // `$(` starts a command substitution, even inside double quotes.
            (_, '(') if previous == '$' => {
                suspended.push(state);
                state = ShellQuoteState::Unquoted;
                segment_start = next_start;
            }
            (ShellQuoteState::Unquoted, ')') if !suspended.is_empty() => {
                state = suspended.pop().unwrap_or(ShellQuoteState::Unquoted);
            }
            (ShellQuoteState::Unquoted, '\'') => state = ShellQuoteState::SingleQuoted,
            (ShellQuoteState::Unquoted, '"') => state = ShellQuoteState::DoubleQuoted,
            (ShellQuoteState::DoubleQuoted, '"') => state = ShellQuoteState::Unquoted,
            (ShellQuoteState::Unquoted, ';' | '|' | '&' | '(' | '`') => {
                segment_start = next_start;
            }
            _ => {}
        }
        previous = ch;
    }

    (state, &prefix[segment_start..])
}

fn is_wrapper(word: &str) -> bool {
    WRAPPER_WORDS.contains(&word) || word.starts_with('-') || is_assignment(word)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !name.starts_with(|ch: char| ch.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::is_command_position;

    fn at(line: &str, needle: &str) -> bool {
        is_command_position(line, line.find(needle).expect("needle in line"))
    }

    #[test]
    fn plain_and_chained_commands_are_command_positions() {
        assert!(at("npm install $pkg", "npm"));
        assert!(at("cd app && npm install", "npm"));
        assert!(at("true; npm install", "npm"));
        assert!(at("sudo npm install", "npm"));
        assert!(at("FOO=1 npm install", "npm"));
        assert!(at("if ! npm install x; then", "npm"));
        assert!(at("x=$(cargo install foo)", "cargo"));
        assert!(at("x=\"$(cargo install foo)\"", "cargo"));
        assert!(at("x=`cargo install foo`", "cargo"));
    }

    #[test]
    fn quoted_text_and_print_commands_are_data() {
        assert!(!at("echo \"cargo install snippet ${v}\"", "cargo"));
        assert!(!at("echo cargo install ${v}", "cargo"));
        assert!(!at("msg=\"cargo install ${v}\"", "cargo"));
        assert!(!at("printf 'npm install %s' \"$x\"", "npm"));
        assert!(!at("grep -Fq \"eval ${x}\" file", "eval"));
        assert!(!at("die \"npm install failed\"", "npm"));
        assert!(!at("echo done; echo 'eval it'", "eval"));
    }

    #[test]
    fn shell_dash_c_and_eval_scripts_are_command_positions() {
        assert!(at("bash -c \"npm install $x\"", "npm"));
        assert!(at("sh -c 'npm install x'", "npm"));
        assert!(at("eval \"npm install $x\"", "npm"));
        assert!(!at("echo \"bash -c 'npm install'\"", "npm"));
    }

    #[test]
    fn semicolon_inside_quotes_does_not_start_a_command() {
        assert!(!at("echo \"a; npm install\"", "npm"));
    }
}
