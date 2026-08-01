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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Language;

    #[test]
    fn detects_unsafe_deserializer_case_insensitive() {
        assert_eq!(is_unsafe_deserializer("PickLe.LoaDs"), Some("pickle.loads"));
        assert_eq!(
            is_unsafe_deserializer("Yaml.UnSafe_Load"),
            Some("yaml.unsafe_load")
        );
    }

    #[test]
    fn strips_python_literals_from_code_scan() {
        let mut state = LiteralScanState::default();
        let yaml_quote = code_outside_literals(
            "cfg = \"pickle.loads(user_input)\"",
            Language::Python,
            &mut state,
        );
        assert!(!yaml_quote.contains("pickle.loads"));
        assert!(yaml_quote.contains("cfg = "));

        let yaml_quote = code_outside_literals(
            "val = 'yaml.unsafe_load(data)'",
            Language::Python,
            &mut state,
        );
        assert!(!yaml_quote.contains("yaml.unsafe_load"));
    }

    #[test]
    fn strips_python_triple_quoted_blocks() {
        let mut state = LiteralScanState::default();
        let before = code_outside_literals("yaml.load(data)", Language::Python, &mut state);
        assert_eq!(before, "yaml.load(data)");

        assert_eq!(
            code_outside_literals("\"\"\"", Language::Python, &mut state),
            "   "
        );
        let in_block =
            code_outside_literals("  pickle.loads(user_input)", Language::Python, &mut state);
        assert!(!in_block.contains("pickle.loads"));
        let _ = code_outside_literals("\"\"\"", Language::Python, &mut state);
        let after = code_outside_literals("yaml.load(real)", Language::Python, &mut state);
        assert_eq!(after, "yaml.load(real)");
    }

    #[test]
    fn strips_js_comments_and_string_literals() {
        assert!(
            !code_outside_literals(
                "console.log('eval()') // vm.runInContext('x')",
                Language::TypeScript,
                &mut LiteralScanState::default()
            )
            .contains("vm.runInContext")
        );
    }

    #[test]
    fn keeps_non_literal_js_function_calls() {
        let line = "payload = JSON.parse(user_input)";
        let mut state = LiteralScanState::default();
        let output = code_outside_literals(line, Language::TypeScript, &mut state);
        assert_eq!(output, line);
    }
}
