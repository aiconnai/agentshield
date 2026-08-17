use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{ScanTarget, SourceLocation};

use super::types::{CALL_EXPR_RE, CallGraph, CallSite, FunctionNode};

pub(crate) static TS_FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"#)
        .expect("valid regex")
});

pub(crate) fn parse_typescript_file(
    graph: &mut CallGraph,
    file_path: &Path,
    content: &str,
    target: &ScanTarget,
) {
    let lines: Vec<&str> = content.lines().collect();

    // 1. Extract function definitions
    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        if let Some(cap) = TS_FUNC_DEF_RE.captures(line) {
            let func_name = cap
                .get(1)
                .or_else(|| cap.get(3))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            if func_name.is_empty() {
                continue;
            }

            let raw_params = cap
                .get(2)
                .or_else(|| cap.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");

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
                .filter(|p| !p.is_empty())
                .collect();

            let start_line = line_num;
            let mut end_line = start_line;
            let mut brace_count: i32 = 0;
            let mut seen_open_brace = false;
            for (sub_idx, next_line) in lines.iter().enumerate().skip(start_line.saturating_sub(1))
            {
                let next_trimmed = next_line.trim();
                if next_trimmed.is_empty() || next_trimmed.starts_with("//") {
                    continue;
                }
                let opens = next_line.chars().filter(|&c| c == '{').count() as i32;
                let closes = next_line.chars().filter(|&c| c == '}').count() as i32;
                if opens > 0 {
                    seen_open_brace = true;
                }
                brace_count += opens - closes;
                end_line = sub_idx + 1;
                // Braceless arrow function: expression terminates at semicolon
                if !seen_open_brace && next_trimmed.ends_with(';') {
                    break;
                }
                // Another function definition starts; this function's scope ended
                if !seen_open_brace
                    && sub_idx + 1 > start_line
                    && TS_FUNC_DEF_RE.is_match(next_line)
                {
                    end_line = end_line.saturating_sub(1).max(start_line);
                    break;
                }
                if seen_open_brace && brace_count <= 0 && sub_idx + 1 >= start_line {
                    break;
                }
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
                    column: 0,
                    end_line: Some(end_line),
                    end_column: None,
                },
                sinks: func_sinks,
            };

            graph.functions.entry(func_name).or_default().push(node);
        }
    }

    // 2. Call sites
    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with("function ")
        {
            continue;
        }

        for cap in CALL_EXPR_RE.captures_iter(line) {
            let callee_name = cap[1].to_string();
            let raw_args = &cap[2];
            let caller_name = graph.find_enclosing_function(file_path, line_num);

            let args: Vec<String> = raw_args
                .split(',')
                .map(|a| a.trim().to_string())
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
