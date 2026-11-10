use std::collections::HashSet;
use std::path::Path;

use crate::analysis::sensitivity::looks_sensitive_name;
use crate::ir::ArgumentSource;
use crate::ir::execution_surface::*;
use crate::parser::ParsedFile;

use super::calls::{
    CALL_NAME_BEFORE_PAREN_RE, CallContext, first_unclosed_paren, is_definition_header,
    is_non_call_keyword, join_call_arguments, record_call,
};
use super::classify::{classify_argument, loc, loc_from_range};
use super::imports::PythonImports;
use super::patterns::*;

pub(crate) fn scan_python_source(
    content: &str,
    file_path: &Path,
    param_names: &HashSet<String>,
    http_client_vars: &HashSet<String>,
    parsed: &mut ParsedFile,
) {
    let lines: Vec<&str> = content.lines().collect();
    let imports = PythonImports::from_source(content);
    let mut current_functions: Vec<(String, usize)> = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();

        if !trimmed.is_empty() {
            while current_functions
                .last()
                .is_some_and(|(_, function_indent)| indent <= *function_indent)
            {
                current_functions.pop();
            }
        }
        if let Some(cap) = FUNC_DEF_RE.captures(line) {
            current_functions.push((cap[1].to_string(), indent));
        }

        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // A definition header has the same `name(args)` shape as a call
        // for the regex below. It establishes scope, but is not a call
        // site and must not participate in cross-file analysis.
        if FUNC_DEF_RE.is_match(line) {
            continue;
        }

        // Check env var access
        for cap in ENV_ACCESS_RE.captures_iter(line) {
            let var_name = cap
                .get(1)
                .or_else(|| cap.get(2))
                .or_else(|| cap.get(3))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let is_sensitive = looks_sensitive_name(&var_name);
            parsed.env_accesses.push(EnvAccess {
                var_name: ArgumentSource::Literal(var_name),
                is_sensitive,
                location: loc(file_path, line_num),
            });
        }

        // Check function calls. Calls that close on this line are matched by
        // `CALL_RE`; a call whose parenthesis stays open is joined with its
        // continuation lines below.
        let mut single_line_call_starts: Vec<usize> = Vec::new();
        for cap in CALL_RE.captures_iter(line) {
            let name_match = cap.get(1).expect("call name capture");
            let call_range = cap.get(0).expect("call capture");
            single_line_call_starts.push(name_match.start());
            let call_location = loc_from_range(
                file_path,
                line_num,
                line,
                call_range.start(),
                call_range.end(),
            );
            record_call(
                &CallContext {
                    param_names,
                    http_client_vars,
                    imports: &imports,
                    caller: current_functions.last().map(|(name, _)| name.as_str()),
                },
                name_match.as_str(),
                &cap[2],
                call_location,
                parsed,
            );
        }

        // GitPython command execution (FN-2 fix):
        // Detect `repo.git.log(...)`, `repo.git.add(...)`, etc.
        for cap in GITPYTHON_RE.captures_iter(line) {
            let full_call = format!("{}.git.{}", &cap[1], &cap[2]);
            let args_str = &cap[3];
            let arg_source = classify_argument(args_str, param_names, &parsed.sanitized_vars);
            let call_range = cap.get(0).expect("GitPython call capture");
            parsed.commands.push(CommandInvocation {
                function: full_call,
                command_arg: arg_source,
                location: loc_from_range(
                    file_path,
                    line_num,
                    line,
                    call_range.start(),
                    call_range.end(),
                ),
            });
        }

        // Multi-line calls, e.g. black-formatted:
        //   os.system(
        //       "ls "
        //       + user
        //   )
        // `CALL_RE` cannot see these because `(` and `)` are on different
        // lines. Join the arguments up to the balanced closing paren.
        if !is_definition_header(trimmed) {
            if let Some(open) = first_unclosed_paren(line) {
                if let Some(name_match) = CALL_NAME_BEFORE_PAREN_RE.find(&line[..open]) {
                    let name_start = name_match.start();
                    if !single_line_call_starts.contains(&name_start)
                        && !is_non_call_keyword(name_match.as_str().trim_end())
                    {
                        let (args, _end_line) = join_call_arguments(&lines, line_idx, open);
                        let call_location =
                            loc_from_range(file_path, line_num, line, name_start, line.len());
                        record_call(
                            &CallContext {
                                param_names,
                                http_client_vars,
                                imports: &imports,
                                caller: current_functions.last().map(|(name, _)| name.as_str()),
                            },
                            name_match.as_str().trim_end(),
                            &args,
                            call_location,
                            parsed,
                        );
                    }
                }
            }
        }
    }
}
