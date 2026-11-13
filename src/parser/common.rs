use std::collections::{HashMap, HashSet};

use crate::analysis::cross_file::SanitizerCategory;

/// Sanitized variables recorded per function scope. A name sanitized in one
/// function must not read as sanitized in a sibling function that merely
/// reuses it.
///
/// A scope is a path of `/`-separated function keys, outermost first (the
/// empty path is module level). A scope sees its own entries, those of every
/// enclosing function, and module-level ones (closures read outer variables).
#[derive(Debug, Default, Clone)]
pub(crate) struct ScopedSanitizers {
    by_scope: HashMap<String, HashSet<String>>,
}

impl ScopedSanitizers {
    /// Record `var` as sanitized by `label` in `scope`.
    pub(crate) fn insert(&mut self, scope: &str, var: &str, label: &str) {
        let entries = self.by_scope.entry(scope.to_string()).or_default();
        entries.insert(var.to_string());
        entries.insert(sanitized_var_marker(var, label));
    }

    #[cfg(feature = "typescript")]
    pub(crate) fn is_empty(&self) -> bool {
        self.by_scope.is_empty()
    }

    /// Every entry, regardless of scope.
    pub(crate) fn all(&self) -> HashSet<String> {
        self.by_scope.values().flatten().cloned().collect()
    }

    /// Entries visible from `scope`.
    pub(crate) fn view(&self, scope: &str) -> HashSet<String> {
        self.by_scope
            .iter()
            .filter(|(key, _)| {
                key.is_empty()
                    || scope == key.as_str()
                    || scope
                        .strip_prefix(key.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
            .flat_map(|(_, entries)| entries.iter().cloned())
            .collect()
    }
}

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
mod scoped_sanitizers_tests {
    use super::ScopedSanitizers;

    #[test]
    fn scope_sees_itself_enclosing_functions_and_module_level() {
        let mut scoped = ScopedSanitizers::default();
        scoped.insert("", "root", "path:validatePath");
        scoped.insert("a@1", "outer", "path:validatePath");
        scoped.insert("a@1/b@2", "inner", "path:validatePath");
        scoped.insert("c@9", "other", "path:validatePath");

        let view = scoped.view("a@1/b@2");
        assert!(view.contains("root"));
        assert!(view.contains("outer"));
        assert!(view.contains("inner"));
        assert!(!view.contains("other"));
        assert!(view.contains("inner::path:validatePath"));
    }

    #[test]
    fn sibling_and_prefix_lookalike_scopes_do_not_leak() {
        let mut scoped = ScopedSanitizers::default();
        scoped.insert("a@1", "safe", "path:validatePath");

        assert!(!scoped.view("a@10").contains("safe"));
        assert!(!scoped.view("b@2").contains("safe"));
        assert!(!scoped.view("").contains("safe"));
        assert!(scoped.view("a@1/inner@2").contains("safe"));
        assert_eq!(scoped.all().len(), 2);
    }
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
