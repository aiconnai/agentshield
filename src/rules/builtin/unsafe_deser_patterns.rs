use crate::ir::Language;

pub(super) const YAML_LOAD: &str = "yaml.load";

pub(super) const JS_UNSAFE_PATTERNS: &[&str] = &[
    "vm.runInContext",
    "vm.runInNewContext",
    "vm.runInThisContext",
    "Function(",
    "new Function(",
];

const UNSAFE_DESERIALIZERS: &[&str] = &[
    "pickle.loads",
    "pickle.load",
    "yaml.unsafe_load",
    "yaml.full_load",
    "marshal.loads",
    "marshal.load",
    "shelve.open",
    "jsonpickle.decode",
    "jsonpickle.loads",
];

#[derive(Default)]
pub(super) struct LiteralScanState {
    python_triple_quote: Option<&'static str>,
}

pub(super) fn is_unsafe_deserializer(function: &str) -> Option<&'static str> {
    let func_lower = function.to_lowercase();
    UNSAFE_DESERIALIZERS
        .iter()
        .find(|deser| func_lower.contains(&deser.to_lowercase()))
        .copied()
}

pub(super) fn code_outside_literals(
    line: &str,
    language: Language,
    state: &mut LiteralScanState,
) -> String {
    let mut output = String::with_capacity(line.len());
    let mut quote = None;
    let mut escaped = false;
    let mut idx = 0;

    while idx < line.len() {
        let rest = &line[idx..];
        let ch = rest.chars().next().expect("line slice is non-empty");

        if let Some(delimiter) = state.python_triple_quote {
            output.push(' ');
            if rest.starts_with(delimiter) {
                state.python_triple_quote = None;
                idx += delimiter.len();
            } else {
                idx += ch.len_utf8();
            }
            continue;
        }

        if escaped {
            escaped = false;
            output.push(' ');
            idx += ch.len_utf8();
            continue;
        }

        match quote {
            Some(_) if ch == '\\' => {
                escaped = true;
                output.push(' ');
                idx += ch.len_utf8();
            }
            Some(current) if ch == current => {
                quote = None;
                output.push(' ');
                idx += ch.len_utf8();
            }
            Some(_) => {
                output.push(' ');
                idx += ch.len_utf8();
            }
            None if is_python_triple_quote_start(rest, language) => {
                let delimiter = if rest.starts_with("'''") {
                    "'''"
                } else {
                    "\"\"\""
                };
                state.python_triple_quote = Some(delimiter);
                output.push_str("   ");
                idx += delimiter.len();
            }
            None if is_comment_start(line, idx, language) => break,
            None if is_quote(ch, language) => {
                quote = Some(ch);
                output.push(' ');
                idx += ch.len_utf8();
            }
            None => {
                output.push(ch);
                idx += ch.len_utf8();
            }
        }
    }

    output
}

fn is_python_triple_quote_start(rest: &str, language: Language) -> bool {
    language == Language::Python && (rest.starts_with("'''") || rest.starts_with("\"\"\""))
}

fn is_quote(ch: char, language: Language) -> bool {
    match language {
        Language::JavaScript | Language::TypeScript => matches!(ch, '\'' | '"' | '`'),
        _ => matches!(ch, '\'' | '"'),
    }
}

fn is_comment_start(line: &str, idx: usize, language: Language) -> bool {
    match language {
        Language::Python | Language::Shell => line[idx..].starts_with('#'),
        Language::JavaScript | Language::TypeScript => line[idx..].starts_with("//"),
        _ => line[idx..].starts_with('#') || line[idx..].starts_with("//"),
    }
}
