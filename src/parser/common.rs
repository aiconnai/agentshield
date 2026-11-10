use std::collections::HashSet;

use crate::analysis::cross_file::SanitizerCategory;

pub(crate) fn sanitized_var_marker(var_name: &str, sanitizer_label: &str) -> String {
    format!("{var_name}::{sanitizer_label}")
}

pub(crate) fn sanitized_label_for_var(
    ident: &str,
    sanitized_vars: &HashSet<String>,
) -> Option<String> {
    for category in [
        SanitizerCategory::Path,
        SanitizerCategory::Network,
        SanitizerCategory::TypeCoercion,
    ] {
        let prefix = format!("{ident}::{}:", category.as_str());
        let mut matches: Vec<&str> = sanitized_vars
            .iter()
            .filter(|value| value.starts_with(&prefix))
            .map(|s| s.as_str())
            .collect();
        matches.sort();
        if let Some(marker) = matches.first() {
            return marker.split_once("::").map(|(_, label)| label.to_string());
        }
    }

    sanitized_vars.contains(ident).then(|| ident.to_string())
}

/// Return the inner text of `arg` only when it is exactly ONE quoted string
/// literal.
///
/// An expression that merely starts and ends with a quote, such as
/// `"ls " + user + " -la"`, is a concatenation carrying non-literal data and
/// must not be classified as a safe literal. The check walks the text and
/// requires the opening quote to be closed for the first time at the very
/// last character (backslash escapes are honoured).
pub(crate) fn single_string_literal(arg: &str) -> Option<&str> {
    let (inner, consumed) = leading_string_literal(arg)?;
    (consumed == arg.len()).then_some(inner)
}

/// Parse the quoted string literal at the start of `arg`, returning its inner
/// text and the number of bytes it spans (quotes included).
pub(crate) fn leading_string_literal(arg: &str) -> Option<(&str, usize)> {
    let quote = arg.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    if arg.len() < 2 {
        return None;
    }
    // Python triple-quoted literal: `"""..."""` / `'''...'''`.
    let triple = if quote == '"' { "\"\"\"" } else { "'''" };
    if arg.len() >= 6 && arg.starts_with(triple) {
        let body = &arg[3..];
        return body.find(triple).map(|idx| (&body[..idx], idx + 6));
    }
    let inner = &arg[1..];
    let mut escaped = false;
    for (idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Some((&inner[..idx], idx + 2));
        }
    }
    None
}

#[cfg(test)]
mod single_string_literal_tests {
    use super::single_string_literal;

    #[test]
    fn accepts_plain_literals() {
        assert_eq!(single_string_literal("\"ls -la\""), Some("ls -la"));
        assert_eq!(single_string_literal("'ls'"), Some("ls"));
        assert_eq!(single_string_literal("\"\""), Some(""));
        assert_eq!(single_string_literal(r#""a \" b""#), Some(r#"a \" b"#));
        assert_eq!(single_string_literal("\"it's\""), Some("it's"));
        assert_eq!(single_string_literal("\"\"\"ls -la\"\"\""), Some("ls -la"));
    }

    #[test]
    fn rejects_quote_bounded_concatenation() {
        assert_eq!(single_string_literal("\"ls \" + user + \" -la\""), None);
        assert_eq!(single_string_literal("'ls ' + dir + ' -la'"), None);
        assert_eq!(single_string_literal("\"a\" \"b\""), None);
        assert_eq!(
            single_string_literal("\"\"\"a\"\"\" + x + \"\"\"b\"\"\""),
            None
        );
    }

    #[test]
    fn rejects_incomplete_or_non_literals() {
        assert_eq!(single_string_literal("\""), None);
        assert_eq!(single_string_literal("\"open"), None);
        assert_eq!(single_string_literal("user"), None);
        assert_eq!(single_string_literal(""), None);
    }
}
