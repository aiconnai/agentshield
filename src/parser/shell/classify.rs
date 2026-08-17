use std::path::Path;

use super::patterns::SHELL_VARIABLE_RE;
use super::quote::shell_tokens;
use crate::ir::{ArgumentSource, SourceLocation};

pub(crate) fn shell_arg_source(
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

pub(crate) fn network_argument(
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

pub(crate) fn takes_value(command: &str, option: &str) -> bool {
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

pub(crate) fn loc_from_range(file: &Path, line: usize, start: usize, end: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: start,
        end_line: Some(line),
        end_column: Some(end),
    }
}

pub(crate) fn loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: Some(line),
        end_column: Some(0),
    }
}
