use std::path::Path;

use super::{McpToolHandler, source_loc_span};

pub(crate) fn find_next_mcp_tool_call(content: &str) -> Option<usize> {
    let mut cursor = 0;
    while cursor < content.len() {
        if let Some(next) = skip_js_string_or_comment(content, cursor, content.len()) {
            cursor = next;
            continue;
        }
        if let Some(rest) = content.get(cursor..) {
            if rest.starts_with(".tool(") || rest.starts_with(".registerTool(") {
                return Some(cursor);
            }
            if let Some(ch) = rest.chars().next() {
                cursor += ch.len_utf8();
                continue;
            }
        }
        cursor += 1;
    }
    None
}

pub(crate) fn parse_mcp_tool_handler(
    path: &Path,
    content: &str,
    start: usize,
    end: usize,
) -> Option<McpToolHandler> {
    let (start, end) = trim_range(content, start, end);
    let candidate = &content[start..end];
    if is_inline_handler(candidate) {
        return Some(McpToolHandler::Inline {
            location: source_loc_span(path, content, start, end),
        });
    }

    is_js_symbol(candidate).then(|| McpToolHandler::Named {
        symbol: candidate.to_string(),
    })
}

pub(crate) fn is_inline_handler(candidate: &str) -> bool {
    if candidate.starts_with('{') || candidate.starts_with('[') {
        return false;
    }
    if is_function_expression(candidate) {
        return true;
    }

    let arrow_candidate = candidate
        .strip_prefix("async")
        .filter(|rest| {
            rest.starts_with('(') || rest.chars().next().is_some_and(char::is_whitespace)
        })
        .map(str::trim_start)
        .unwrap_or(candidate);

    if arrow_candidate.starts_with('(') {
        return find_matching_delimiter(arrow_candidate, 0, b'(', b')')
            .is_some_and(|close| arrow_candidate[close + 1..].trim_start().starts_with("=>"));
    }

    arrow_candidate
        .split_once("=>")
        .is_some_and(|(parameter, _)| is_js_identifier(parameter.trim()))
}

pub(crate) fn is_function_expression(candidate: &str) -> bool {
    let candidate = candidate
        .strip_prefix("async")
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        .map(str::trim_start)
        .unwrap_or(candidate);
    candidate.strip_prefix("function").is_some_and(|rest| {
        rest.is_empty()
            || rest.starts_with('(')
            || rest.starts_with('*')
            || rest.chars().next().is_some_and(char::is_whitespace)
    })
}

pub(crate) fn is_js_symbol(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    !is_js_reserved_word(first) && is_js_identifier(first) && segments.all(is_js_identifier)
}

pub(crate) fn is_js_identifier(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || matches!(ch, '_' | '$'))
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
}

pub(crate) fn is_js_reserved_word(candidate: &str) -> bool {
    matches!(
        candidate,
        "async"
            | "await"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "let"
            | "new"
            | "null"
            | "return"
            | "static"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "undefined"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
    )
}

pub(crate) fn parse_object_string_property(
    content: &str,
    start: usize,
    end: usize,
    property: &str,
) -> Option<String> {
    let (start, end) = trim_range(content, start, end);
    if content.as_bytes().get(start) != Some(&b'{')
        || content.as_bytes().get(end.saturating_sub(1)) != Some(&b'}')
    {
        return None;
    }

    for (property_start, property_end) in top_level_segments(content, start + 1, end - 1) {
        let Some(colon) = find_top_level_byte(content, property_start, property_end, b':') else {
            continue;
        };
        let (key_start, key_end) = trim_range(content, property_start, colon);
        let key = parse_string_literal_at(content, key_start)
            .filter(|(_, after)| *after <= key_end)
            .map(|(value, _)| value)
            .unwrap_or_else(|| content[key_start..key_end].to_string());
        if key != property {
            continue;
        }

        let (value_start, value_end) = trim_range(content, colon + 1, property_end);
        return parse_string_literal_at(content, value_start)
            .filter(|(_, after)| *after <= value_end)
            .map(|(value, _)| value);
    }

    None
}

pub(crate) fn top_level_segments(content: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut segments = Vec::new();
    let mut segment_start = start;
    let mut cursor = start;
    let mut depths = [0usize; 3];

    while cursor < end {
        if let Some(next) = skip_js_string_or_comment(content, cursor, end) {
            cursor = next;
            continue;
        }

        match content.as_bytes()[cursor] {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'{' => depths[1] += 1,
            b'}' => depths[1] = depths[1].saturating_sub(1),
            b'[' => depths[2] += 1,
            b']' => depths[2] = depths[2].saturating_sub(1),
            b',' if depths == [0, 0, 0] => {
                let segment = trim_range(content, segment_start, cursor);
                if segment.0 < segment.1 {
                    segments.push(segment);
                }
                segment_start = cursor + 1;
            }
            _ => {}
        }
        cursor += 1;
    }

    let segment = trim_range(content, segment_start, end);
    if segment.0 < segment.1 {
        segments.push(segment);
    }
    segments
}

pub(crate) fn find_matching_delimiter(
    content: &str,
    open: usize,
    open_byte: u8,
    close_byte: u8,
) -> Option<usize> {
    let mut depth = 0usize;
    let mut cursor = open;
    while cursor < content.len() {
        if let Some(next) = skip_js_string_or_comment(content, cursor, content.len()) {
            cursor = next;
            continue;
        }

        let byte = content.as_bytes()[cursor];
        if byte == open_byte {
            depth += 1;
        } else if byte == close_byte {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(cursor);
            }
        }
        cursor += 1;
    }
    None
}

pub(crate) fn find_top_level_byte(
    content: &str,
    start: usize,
    end: usize,
    needle: u8,
) -> Option<usize> {
    let mut cursor = start;
    let mut depths = [0usize; 3];
    while cursor < end {
        if let Some(next) = skip_js_string_or_comment(content, cursor, end) {
            cursor = next;
            continue;
        }

        let byte = content.as_bytes()[cursor];
        if byte == needle && depths == [0, 0, 0] {
            return Some(cursor);
        }
        match byte {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'{' => depths[1] += 1,
            b'}' => depths[1] = depths[1].saturating_sub(1),
            b'[' => depths[2] += 1,
            b']' => depths[2] = depths[2].saturating_sub(1),
            _ => {}
        }
        cursor += 1;
    }
    None
}

pub(crate) fn skip_js_string_or_comment(content: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let quote = *bytes.get(start)?;
    if matches!(quote, b'\'' | b'"' | b'`') {
        let mut cursor = start + 1;
        while cursor < end {
            if bytes[cursor] == b'\\' {
                cursor = (cursor + 2).min(end);
            } else if bytes[cursor] == quote {
                return Some(cursor + 1);
            } else {
                cursor += 1;
            }
        }
        return Some(end);
    }

    if quote == b'/' && bytes.get(start + 1) == Some(&b'/') {
        let mut cursor = start + 2;
        while cursor < end && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        return Some(cursor);
    }
    if quote == b'/' && bytes.get(start + 1) == Some(&b'*') {
        let mut cursor = start + 2;
        while cursor + 1 < end {
            if bytes[cursor] == b'*' && bytes[cursor + 1] == b'/' {
                return Some(cursor + 2);
            }
            cursor += 1;
        }
        return Some(end);
    }

    None
}

pub(crate) fn trim_range(content: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && content.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && content.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

pub(crate) fn parse_string_literal_at(content: &str, offset: usize) -> Option<(String, usize)> {
    let offset = skip_whitespace(content, offset);
    let quote = content[offset..].chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }

    let mut value = String::new();
    let mut escaped = false;
    for (relative_index, ch) in content[offset + quote.len_utf8()..].char_indices() {
        let absolute_index = offset + quote.len_utf8() + relative_index;
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some((value, absolute_index + quote.len_utf8()));
        }
        value.push(ch);
    }

    None
}

pub(crate) fn skip_whitespace(content: &str, mut offset: usize) -> usize {
    while let Some(ch) = content[offset..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}
