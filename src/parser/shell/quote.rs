#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellQuoteState {
    Unquoted,
    SingleQuoted,
    DoubleQuoted,
}

#[derive(Debug)]
pub(crate) struct ShellToken {
    pub(crate) value: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub(crate) fn is_active_backtick(line: &str, backtick_idx: usize) -> bool {
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

pub(crate) fn shell_tokens(input: &str, offset: usize) -> Vec<ShellToken> {
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
