//! Resolution of `exec` / `execSync` calls to the Node `child_process`
//! module. A bare `.exec(` member call is not enough: `RegExp.prototype.exec`,
//! database handles and many other APIs share the name.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;

const MODULE: &str = r#"["'](?:node:)?child_process["']"#;

/// `import { exec, execSync as run } from "child_process"` (with an optional
/// default binding in front).
static IMPORT_NAMED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(
        r"import\s+(?:type\s+)?(?:(\w+)\s*,\s*)?\{{([^}}]*)\}}\s*from\s*{MODULE}"
    ))
    .expect("static regex pattern is valid")
});

/// `import cp from "child_process"` and `import * as cp from "child_process"`.
static IMPORT_MODULE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(
        r"import\s+(?:(\w+)|\*\s*as\s+(\w+))\s+from\s*{MODULE}"
    ))
    .expect("static regex pattern is valid")
});

/// `const cp = require("child_process")`, `import cp = require(...)`, and the
/// dynamic `await import("child_process")` equivalent.
static REQUIRE_MODULE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(
        r"(?:const|let|var|import)\s+(\w+)\s*(?::[^=]+)?=\s*(?:await\s+)?(?:require|import)\(\s*{MODULE}\s*\)"
    ))
    .expect("static regex pattern is valid")
});

/// `const { exec, execSync: run } = require("child_process")`.
static REQUIRE_DESTRUCTURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(
        r"(?:const|let|var)\s*\{{([^}}]*)\}}\s*(?::[^=]+)?=\s*(?:await\s+)?(?:require|import)\(\s*{MODULE}\s*\)"
    ))
    .expect("static regex pattern is valid")
});

/// `const execAsync = promisify(exec)` / `util.promisify(cp.exec)`.
static PROMISIFY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:[\w.]+\.)?promisify\(\s*([\w.]+)\s*\)")
        .expect("static regex pattern is valid")
});

/// `require("child_process").exec` written inline as the callee.
static INLINE_REQUIRE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(r"^(?:require|import)\({MODULE}\)$"))
        .expect("static regex pattern is valid")
});

/// `require("child_process").exec(cmd)` on one line. The regex call scanner
/// used without the `typescript` feature cannot see a call on a call result.
#[cfg(not(feature = "typescript"))]
pub(super) static INLINE_EXEC_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(
        r"(?:require|import)\(\s*{MODULE}\s*\)\s*\.\s*(exec(?:Sync)?)\s*\(([^)]*)\)"
    ))
    .expect("static regex pattern is valid")
});

/// How a file refers to `child_process.exec` and `child_process.execSync`.
#[derive(Debug, Default, Clone)]
pub(crate) struct ChildProcessBindings {
    /// Local names bound to the `child_process` module object.
    modules: HashSet<String>,
    /// Local names bound directly to `exec` or `execSync`.
    exec_functions: HashSet<String>,
}

impl ChildProcessBindings {
    pub(crate) fn from_source(content: &str) -> Self {
        let mut bindings = Self::default();

        for cap in IMPORT_NAMED_RE.captures_iter(content) {
            if let Some(default) = cap.get(1) {
                bindings.modules.insert(default.as_str().to_string());
            }
            bindings.add_specifiers(&cap[2], " as ");
        }
        for cap in IMPORT_MODULE_RE.captures_iter(content) {
            if let Some(name) = cap.get(1).or_else(|| cap.get(2)) {
                bindings.modules.insert(name.as_str().to_string());
            }
        }
        for cap in REQUIRE_MODULE_RE.captures_iter(content) {
            bindings.modules.insert(cap[1].to_string());
        }
        for cap in REQUIRE_DESTRUCTURE_RE.captures_iter(content) {
            bindings.add_specifiers(&cap[1], ":");
        }
        // Wrappers are resolved last so they can wrap any binding above.
        for cap in PROMISIFY_RE.captures_iter(content) {
            if bindings.is_exec_call(&cap[2]) {
                bindings.exec_functions.insert(cap[1].to_string());
            }
        }

        bindings
    }

    fn add_specifiers(&mut self, specifiers: &str, rename: &str) {
        for specifier in specifiers.split(',') {
            let (imported, local) = match specifier.split_once(rename) {
                Some((imported, local)) => (imported.trim(), local.trim()),
                None => (specifier.trim(), specifier.trim()),
            };
            if matches!(imported, "exec" | "execSync") && !local.is_empty() {
                self.exec_functions.insert(local.to_string());
            }
        }
    }

    /// Whether `callee` (as written at the call site, whitespace removed)
    /// resolves to `child_process.exec` or `child_process.execSync`.
    pub(crate) fn is_exec_call(&self, callee: &str) -> bool {
        match callee.rsplit_once('.') {
            None => self.exec_functions.contains(callee),
            Some((receiver, "exec" | "execSync")) => {
                self.modules.contains(receiver)
                    || receiver == "child_process"
                    || INLINE_REQUIRE_RE.is_match(receiver)
            }
            Some(_) => false,
        }
    }
}

/// Whether the last path segment of `callee` is `exec` or `execSync`.
pub(crate) fn is_exec_name(callee: &str) -> bool {
    matches!(callee.rsplit('.').next(), Some("exec" | "execSync"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings(src: &str) -> ChildProcessBindings {
        ChildProcessBindings::from_source(src)
    }

    #[test]
    fn named_imports_and_aliases() {
        let b = bindings(
            "import { exec, spawn, execSync as run } from \"node:child_process\";\nimport type { ChildProcess } from 'child_process';",
        );
        assert!(b.is_exec_call("exec"));
        assert!(b.is_exec_call("run"));
        assert!(!b.is_exec_call("spawn"));
        assert!(!b.is_exec_call("execSync"));
    }

    #[test]
    fn namespace_default_and_require_modules() {
        let b = bindings(
            "import * as a from 'child_process';\nimport b from \"node:child_process\";\nconst c = require('child_process');\nimport d = require(\"child_process\");\nconst e = await import(\"node:child_process\");",
        );
        for name in ["a", "b", "c", "d", "e"] {
            assert!(b.is_exec_call(&format!("{name}.exec")), "{name}.exec");
            assert!(
                b.is_exec_call(&format!("{name}.execSync")),
                "{name}.execSync"
            );
        }
        assert!(!b.is_exec_call("f.exec"));
        assert!(!b.is_exec_call("a.spawn"));
    }

    #[test]
    fn destructured_require() {
        let b = bindings("const { exec, execSync: sh, spawn } = require('child_process');");
        assert!(b.is_exec_call("exec"));
        assert!(b.is_exec_call("sh"));
        assert!(!b.is_exec_call("spawn"));
    }

    #[test]
    fn promisified_exec_is_resolved() {
        let b = bindings(
            "import { exec } from 'child_process';\nimport util from 'util';\nconst run = util.promisify(exec);\nconst other = promisify(unknown);",
        );
        assert!(b.is_exec_call("run"));
        assert!(!b.is_exec_call("other"));
    }

    #[test]
    fn unrelated_receivers_do_not_resolve() {
        let b = bindings("import { Database } from 'sqlite';\nconst re = /x/;");
        assert!(!b.is_exec_call("exec"));
        assert!(!b.is_exec_call("re.exec"));
        assert!(!b.is_exec_call("db.exec"));
        assert!(b.is_exec_call("child_process.exec"));
        assert!(b.is_exec_call("require(\"child_process\").exec"));
    }
}
