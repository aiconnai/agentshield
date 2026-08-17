use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{ScanTarget, SourceLocation};

use super::types::{CALL_EXPR_RE, CallGraph, CallSite, FunctionNode};

pub(crate) static PY_FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#).expect("valid regex")
});

pub(crate) fn parse_python_file(
    graph: &mut CallGraph,
    file_path: &Path,
    content: &str,
    target: &ScanTarget,
) {
    let lines: Vec<&str> = content.lines().collect();

    // 1. Extract function definitions
    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        if let Some(cap) = PY_FUNC_DEF_RE.captures(line) {
            let func_name = cap[1].to_string();
            let raw_params = &cap[2];

            let params: Vec<String> = raw_params
                .split(',')
                .map(|p| {
                    p.split(':')
                        .next()
                        .unwrap_or("")
                        .split('=')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                })
                .filter(|p| !p.is_empty() && p != "self" && p != "cls")
                .collect();

            let start_line = line_num;
            let func_indent = line.len() - line.trim_start().len();
            let mut end_line = start_line;

            for (sub_idx, next_line) in lines.iter().enumerate().skip(start_line) {
                let next_trimmed = next_line.trim();
                if next_trimmed.is_empty() || next_trimmed.starts_with('#') {
                    continue;
                }
                let next_indent = next_line.len() - next_line.trim_start().len();
                if next_indent <= func_indent
                    || next_trimmed.starts_with('@')
                    || next_trimmed.starts_with("def ")
                    || next_trimmed.starts_with("async def ")
                    || next_trimmed.starts_with("class ")
                {
                    break;
                }
                end_line = sub_idx + 1;
            }

            let func_sinks = target
                .data
                .sinks
                .iter()
                .filter(|s| {
                    s.location.file == file_path
                        && s.location.line >= start_line
                        && s.location.line <= end_line
                })
                .cloned()
                .collect();

            let node = FunctionNode {
                name: func_name.clone(),
                file_path: file_path.to_path_buf(),
                params,
                start_line,
                end_line,
                location: SourceLocation {
                    file: file_path.to_path_buf(),
                    line: start_line,
                    column: func_indent,
                    end_line: Some(end_line),
                    end_column: None,
                },
                sinks: func_sinks,
            };

            graph.functions.entry(func_name).or_default().push(node);
        }
    }

    // 2. Extract call sites
    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
        {
            continue;
        }

        for cap in CALL_EXPR_RE.captures_iter(line) {
            let callee_name = cap[1].to_string();
            let raw_args = &cap[2];

            // Determine caller function containing this line
            let caller_name = graph.find_enclosing_function(file_path, line_num);

            let args: Vec<String> = raw_args
                .split(',')
                .map(|a| a.split('=').next().unwrap_or("").trim().to_string())
                .filter(|a| !a.is_empty())
                .collect();

            graph.call_sites.push(CallSite {
                caller_name,
                callee_name,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
                args,
                location: SourceLocation {
                    file: file_path.to_path_buf(),
                    line: line_num,
                    column: line.find(&cap[0]).unwrap_or(0),
                    end_line: None,
                    end_column: None,
                },
            });
        }
    }
}
