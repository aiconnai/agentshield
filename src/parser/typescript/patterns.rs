use once_cell::sync::Lazy;
use regex::Regex;

pub(super) static EXEC_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
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

pub(super) static NETWORK_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
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

pub(super) static FILE_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
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

pub(super) static DYNAMIC_EXEC_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "eval",
        "Function",
        "vm.runInThisContext",
        "vm.runInNewContext",
    ]
});

// Template literal with interpolation: `...${expr}...`
pub(super) static TEMPLATE_LITERAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("static regex pattern is valid"));

// Sanitizer assignment: const validPath = await validatePath(x)
// Captures: (1) variable name, (2) function name (possibly dotted)
pub(super) static SANITIZER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(\w+(?:\.\w+)*)\s*\(")
        .expect("static regex pattern is valid")
});

#[cfg(not(feature = "typescript"))]
pub(super) static CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)(\w+(?:\.\w+)*)\s*\(([^)]*)\)").expect("static regex pattern is valid")
});

#[cfg(not(feature = "typescript"))]
pub(super) static ENV_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)process\.env\s*(?:\[\s*["']([^"']+)["']\s*\]|\.([A-Z_][A-Z0-9_]*))"#)
        .expect("static regex pattern is valid")
});

#[cfg(not(feature = "typescript"))]
pub(super) static FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*(?:=>|:\s*\w+\s*=>)|(\w+)\s*\(([^)]*)\)\s*(?::\s*\w+\s*)?\{)"
    ).expect("static regex pattern is valid")
});

/// Check if a function name matches any pattern in the list.
pub(super) fn matches_pattern(func_name: &str, patterns: &[&str]) -> bool {
    patterns
        .iter()
        .any(|p| func_name == *p || func_name.ends_with(p))
}
