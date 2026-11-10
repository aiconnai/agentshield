//! Call recording for the Python scanner: single-line and multi-line calls
//! share one pipeline, so a call formatted across several lines is classified
//! exactly like the same call on one line.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, SourceLocation};
use crate::parser::{CallSite, ParsedFile};

use super::classify::{classify_argument, command_argument_text, split_top_level_args};
use super::imports::PythonImports;
use super::patterns::*;

/// How many physical lines a single call may span before it is cut off.
const MAX_CALL_LINES: usize = 60;

/// Name immediately before an opening parenthesis, e.g. `os.system` in
/// `return os.system(`.
pub(crate) static CALL_NAME_BEFORE_PAREN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+(?:\.\w+)*)\s*$").expect("static regex pattern is valid"));

const NON_CALL_KEYWORDS: &[&str] = &[
    "if", "elif", "while", "for", "with", "return", "yield", "assert", "in", "and", "or", "not",
    "is", "lambda", "del", "raise", "except",
];

pub(crate) struct CallContext<'a> {
    pub(crate) param_names: &'a HashSet<String>,
    pub(crate) http_client_vars: &'a HashSet<String>,
    pub(crate) imports: &'a PythonImports,
    pub(crate) caller: Option<&'a str>,
}

/// A definition header has the same `name(args)` shape as a call but is not
/// one.
pub(crate) fn is_definition_header(trimmed: &str) -> bool {
    trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("class ")
}

pub(crate) fn is_non_call_keyword(name: &str) -> bool {
    NON_CALL_KEYWORDS.contains(&name)
}

/// Byte offset of the first `(` on `line` that is still open at the end of
/// the line. Parentheses inside string literals and comments are ignored.
pub(crate) fn first_unclosed_paren(line: &str) -> Option<usize> {
    let mut open: Vec<usize> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for (idx, ch) in line.char_indices() {
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
            '#' => break,
            '"' | '\'' => quote = Some(ch),
            '(' => open.push(idx),
            ')' => {
                open.pop();
            }
            _ => {}
        }
    }
    open.first().copied()
}

/// Join the arguments of the call whose `(` is at byte `open` of
/// `lines[start]`, up to the balanced closing paren. Comments are dropped and
/// line breaks become spaces. Parens inside strings and comments do not count.
/// Returns the joined text and the index of the line holding the close.
pub(crate) fn join_call_arguments(lines: &[&str], start: usize, open: usize) -> (String, usize) {
    let mut joined = String::new();
    let mut depth = 1usize;
    let mut quote: Option<(char, bool)> = None;
    let last = (start + MAX_CALL_LINES).min(lines.len());

    for (idx, line) in lines.iter().enumerate().take(last).skip(start) {
        let text = if idx == start {
            &line[open + 1..]
        } else {
            line
        };
        let chars: Vec<char> = text.chars().collect();
        let mut pos = 0;
        let mut escaped = false;

        while pos < chars.len() {
            let ch = chars[pos];
            if let Some((current, triple)) = quote {
                joined.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == current {
                    if !triple {
                        quote = None;
                    } else if chars[pos + 1..].starts_with(&[current, current]) {
                        joined.extend([current, current]);
                        pos += 2;
                        quote = None;
                    }
                }
                pos += 1;
                continue;
            }
            match ch {
                '#' => break,
                '"' | '\'' => {
                    let triple = chars[pos + 1..].starts_with(&[ch, ch]);
                    joined.push(ch);
                    if triple {
                        joined.extend([ch, ch]);
                        pos += 2;
                    }
                    quote = Some((ch, triple));
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    joined.push(ch);
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return (joined, idx);
                    }
                    joined.push(ch);
                }
                _ => joined.push(ch),
            }
            pos += 1;
        }

        // A single-quoted string cannot continue on the next line.
        if matches!(quote, Some((_, false))) {
            quote = None;
        }
        joined.push(' ');
    }

    (joined, last.saturating_sub(1))
}

/// Record one call: its call site, and every sink family it belongs to.
pub(crate) fn record_call(
    ctx: &CallContext<'_>,
    raw_name: &str,
    args_str: &str,
    call_location: SourceLocation,
    parsed: &mut ParsedFile,
) {
    // Sink patterns are written against canonical names (`subprocess.run`),
    // so resolve import aliases before matching them.
    let canonical = ctx.imports.canonical_call_name(raw_name);
    let func_name = canonical.as_str();

    let arg_source = classify_argument(
        command_argument_text(args_str),
        ctx.param_names,
        &parsed.sanitized_vars,
    );

    // Record CallSite for cross-file analysis
    let all_args = split_top_level_args(args_str)
        .iter()
        .map(|a| classify_argument(a.trim(), ctx.param_names, &parsed.sanitized_vars))
        .collect::<Vec<_>>();
    parsed.call_sites.push(CallSite {
        callee: raw_name.to_string(),
        arguments: all_args,
        caller: ctx.caller.map(str::to_string),
        location: call_location.clone(),
    });

    // Subprocess/command execution
    if SUBPROCESS_PATTERNS
        .iter()
        .any(|p| func_name.ends_with(p) || func_name == *p)
    {
        parsed.commands.push(CommandInvocation {
            function: func_name.to_string(),
            command_arg: arg_source.clone(),
            location: call_location.clone(),
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
            location: call_location.clone(),
        });
    }

    // Dynamic exec
    if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
        parsed.dynamic_exec.push(DynamicExec {
            function: func_name.to_string(),
            code_arg: arg_source.clone(),
            location: call_location.clone(),
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
            location: call_location.clone(),
        });
    }

    record_http_client_call(ctx, raw_name, args_str, &arg_source, &call_location, parsed);
}

/// HTTP client variable method calls (FN-1 fix): `client.get(url)` where
/// `client` was bound from `async with AsyncClient() as client:`.
fn record_http_client_call(
    ctx: &CallContext<'_>,
    raw_name: &str,
    args_str: &str,
    arg_source: &ArgumentSource,
    call_location: &SourceLocation,
    parsed: &mut ParsedFile,
) {
    let Some((obj, method)) = raw_name.rsplit_once('.') else {
        return;
    };
    if !ctx.http_client_vars.contains(obj) || !HTTP_CLIENT_METHODS.contains(&method) {
        return;
    }
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
        function: raw_name.to_string(),
        url_arg: arg_source.clone(),
        method: http_method,
        sends_data,
        location: call_location.clone(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_first_unclosed_paren() {
        assert_eq!(first_unclosed_paren("return os.system("), Some(16));
        assert_eq!(first_unclosed_paren("f(a) + g("), Some(8));
        assert_eq!(first_unclosed_paren("f(a)"), None);
        assert_eq!(first_unclosed_paren("x = \"(\"  # (("), None);
    }

    #[test]
    fn joins_arguments_to_the_balanced_close() {
        let lines = [
            "os.system(",
            "    \"ls \"",
            "    + user",
            "    + \" -la\"",
            ")",
            "next()",
        ];
        let (args, end) = join_call_arguments(&lines, 0, 9);
        assert_eq!(
            args.split_whitespace().collect::<Vec<_>>().join(" "),
            "\"ls \" + user + \" -la\""
        );
        assert_eq!(end, 4);
    }

    #[test]
    fn ignores_parens_in_strings_and_comments() {
        let lines = [
            "run(",
            "    \"a ) b\"  # ) here",
            "    + user,",
            "    shell=True)",
            "x",
        ];
        let (args, end) = join_call_arguments(&lines, 0, 3);
        assert!(args.contains("+ user"));
        assert!(args.contains("shell=True"));
        assert!(!args.contains("here"));
        assert_eq!(end, 3);
    }

    #[test]
    fn handles_nested_brackets_and_triple_quotes() {
        let lines = [
            "f(",
            "    \"\"\"a ) \"b\" (\"\"\" + [1, (2)],",
            "    x)",
            "y",
        ];
        let (args, end) = join_call_arguments(&lines, 0, 1);
        assert!(args.contains("[1, (2)]"));
        assert!(args.trim_end().ends_with("x"));
        assert_eq!(end, 2);
    }

    #[test]
    fn unterminated_call_is_cut_off_at_end_of_input() {
        let lines = ["f(", "    a,"];
        let (args, end) = join_call_arguments(&lines, 0, 1);
        assert!(args.contains('a'));
        assert_eq!(end, 1);
    }
}
