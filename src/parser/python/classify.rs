use crate::ir::ArgumentSource;
use crate::ir::SourceLocation;
use std::path::Path;

/// Classify a call argument string to determine its source.
pub(crate) fn classify_argument(
    args_str: &str,
    param_names: &std::collections::HashSet<String>,
    sanitized_vars: &std::collections::HashSet<String>,
) -> ArgumentSource {
    let first_arg = split_top_level_args(args_str)
        .first()
        .copied()
        .unwrap_or("")
        .trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // Check if this is a sanitized variable first
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    let ident = ident.split('[').next().unwrap_or(ident);
    if let Some(sanitizer) = sanitized_label_for_var(ident, sanitized_vars) {
        return ArgumentSource::Sanitized { sanitizer };
    }

    // String literal. Single quote tokens can appear when a regex-level parse
    // sees an incomplete multiline literal; keep those conservative.
    if let Some(val) = python_string_literal(first_arg) {
        return ArgumentSource::Literal(val);
    }

    // f-string or format
    if first_arg.starts_with("f\"") || first_arg.starts_with("f'") || first_arg.contains(".format(")
    {
        return ArgumentSource::Interpolated;
    }

    // A quoted piece that is not a single literal is a concatenation or
    // `%` formatting carrying non-literal data (`"ls " + user + " -la"`).
    // An incomplete lone quote token stays `Unknown` (still tainted).
    if (first_arg.starts_with('"') || first_arg.starts_with('\''))
        && (first_arg.contains('+') || first_arg.contains('%'))
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

/// Split call arguments on the commas that are not nested inside brackets or
/// string literals. Like `str::split(',')`, an empty input yields one empty
/// piece; a trailing comma does not add a phantom argument.
pub(crate) fn split_top_level_args(args: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start = 0;

    for (idx, ch) in args.char_indices() {
        if let Some(current) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == current {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                pieces.push(&args[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    pieces.push(&args[start..]);
    if pieces.len() > 1 && pieces.last().is_some_and(|last| last.trim().is_empty()) {
        pieces.pop();
    }
    pieces
}

/// Keyword names that carry the command, URL, or path of a call.
const PRIMARY_KEYWORDS: &[&str] = &["url", "args", "command", "cmd"];

/// The argument text to classify as the call's primary argument: the first
/// positional argument, or the value of a well-known keyword
/// (`url=...`, `args=...`) when every argument is a keyword.
pub(crate) fn command_argument_text(args: &str) -> &str {
    let pieces = split_top_level_args(args);
    let mut keyword_value = None;
    for piece in &pieces {
        let piece = piece.trim();
        match keyword_argument(piece) {
            None => return piece,
            Some((name, value)) => {
                if keyword_value.is_none() && PRIMARY_KEYWORDS.contains(&name) {
                    keyword_value = Some(value);
                }
            }
        }
    }
    keyword_value.unwrap_or_else(|| pieces.first().copied().unwrap_or("").trim())
}

/// `(name, value)` for a `name=value` keyword argument.
fn keyword_argument(piece: &str) -> Option<(&str, &str)> {
    let (name, value) = piece.split_once('=')?;
    let name = name.trim();
    let is_name = !name.is_empty() && name.chars().all(|ch| ch.is_alphanumeric() || ch == '_');
    (is_name && !value.starts_with('=')).then_some((name, value.trim()))
}

/// Value of `arg` when it is entirely string literals: one literal, or
/// several adjacent ones that Python joins implicitly (`"ls " "-la"`).
pub(crate) fn python_string_literal(arg: &str) -> Option<String> {
    let mut value = String::new();
    let mut rest = arg;
    loop {
        let (inner, consumed) = crate::parser::common::leading_string_literal(rest)?;
        value.push_str(inner);
        rest = rest[consumed..].trim_start();
        if rest.is_empty() {
            return Some(value);
        }
    }
}

pub(crate) use crate::parser::common::{sanitized_label_for_var, sanitized_var_marker};

pub(crate) fn loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: Some(line),
        end_column: Some(0),
    }
}

pub(crate) fn loc_from_range(
    file: &Path,
    line: usize,
    source_line: &str,
    start_byte: usize,
    end_byte: usize,
) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: source_line[..start_byte].chars().count(),
        end_line: Some(line),
        end_column: Some(source_line[..end_byte].chars().count()),
    }
}

#[cfg(test)]
mod tests {
    use super::{command_argument_text, python_string_literal, split_top_level_args};

    #[test]
    fn splits_only_top_level_commas() {
        assert_eq!(
            split_top_level_args("\"a, b\" + x, f(1, 2), [3, 4]"),
            vec!["\"a, b\" + x", " f(1, 2)", " [3, 4]"]
        );
        assert_eq!(split_top_level_args(""), vec![""]);
        assert_eq!(split_top_level_args("a, b,"), vec!["a", " b"]);
        assert_eq!(split_top_level_args("a"), vec!["a"]);
    }

    #[test]
    fn primary_argument_skips_keywords_before_positional_values() {
        assert_eq!(command_argument_text("cmd, shell=True"), "cmd");
        assert_eq!(command_argument_text("shell=True, args=cmd"), "cmd");
        assert_eq!(command_argument_text("timeout=5, url=target"), "target");
        assert_eq!(command_argument_text("a == b"), "a == b");
        assert_eq!(command_argument_text("\"echo a, b\""), "\"echo a, b\"");
    }

    #[test]
    fn joins_adjacent_literals() {
        assert_eq!(
            python_string_literal("\"ls -la\"").as_deref(),
            Some("ls -la")
        );
        assert_eq!(
            python_string_literal("\"ls \" '-la'").as_deref(),
            Some("ls -la")
        );
        assert_eq!(
            python_string_literal("\"\"\"a\"\"\" \"b\"").as_deref(),
            Some("ab")
        );
    }

    #[test]
    fn rejects_anything_beyond_literals() {
        assert_eq!(python_string_literal("\"ls \" + user"), None);
        assert_eq!(python_string_literal("\"ls \" user"), None);
        assert_eq!(python_string_literal("\"ls \" \"open"), None);
        assert_eq!(python_string_literal("user"), None);
    }
}
