//! Per-file import alias tracking, so sink patterns written against canonical
//! names (`subprocess.run`, `os.system`) also match `from subprocess import
//! run`, `import subprocess as sp`, and similar renames.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

static IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^[ \t]*import[ \t]+([^\n#]+)").expect("static regex pattern is valid")
});

static FROM_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[^\n#]*)")
        .expect("static regex pattern is valid")
});

/// Module and function aliases introduced by the imports of one file.
#[derive(Debug, Default, Clone)]
pub(crate) struct PythonImports {
    /// Local name -> module it refers to (`sp` -> `subprocess`).
    modules: HashMap<String, String>,
    /// Local name -> `module.member` it refers to (`run` -> `subprocess.run`).
    members: HashMap<String, String>,
}

impl PythonImports {
    pub(crate) fn from_source(content: &str) -> Self {
        let mut imports = Self::default();

        for cap in IMPORT_RE.captures_iter(content) {
            for item in cap[1].split(',') {
                let mut words = item.split_whitespace();
                let (Some(module), alias) = (words.next(), words.nth(1)) else {
                    continue;
                };
                if !is_dotted_name(module) {
                    continue;
                }
                match alias {
                    // `import a.b as x` binds `x` to `a.b`.
                    Some(alias) if is_identifier(alias) => {
                        imports
                            .modules
                            .insert(alias.to_string(), module.to_string());
                    }
                    // `import a.b` binds `a`, which refers to itself.
                    _ => {
                        let root = module.split('.').next().unwrap_or(module);
                        imports.modules.insert(root.to_string(), root.to_string());
                    }
                }
            }
        }

        for cap in FROM_IMPORT_RE.captures_iter(content) {
            let module = &cap[1];
            let names = strip_comments(&cap[2]);
            let names = names.trim().trim_start_matches('(').trim_end_matches(')');
            for item in names.split(',') {
                let mut words = item.split_whitespace();
                let Some(member) = words.next() else {
                    continue;
                };
                let local = match (words.next(), words.next()) {
                    (Some("as"), Some(alias)) => alias,
                    _ => member,
                };
                if is_identifier(member) && is_identifier(local) {
                    imports
                        .members
                        .insert(local.to_string(), format!("{module}.{member}"));
                }
            }
        }

        imports
    }

    /// Rewrite a call name to the canonical dotted name it refers to. Names
    /// that are not imported are returned unchanged.
    pub(crate) fn canonical_call_name(&self, name: &str) -> String {
        let (head, tail) = match name.split_once('.') {
            Some((head, tail)) => (head, Some(tail)),
            None => (name, None),
        };
        if let Some(target) = self.members.get(head).or_else(|| self.modules.get(head)) {
            return match tail {
                Some(tail) => format!("{target}.{tail}"),
                None => target.clone(),
            };
        }
        name.to_string()
    }
}

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_alphanumeric() || ch == '_')
}

fn is_dotted_name(text: &str) -> bool {
    !text.is_empty() && text.split('.').all(is_identifier)
}

#[cfg(test)]
mod tests {
    use super::PythonImports;

    #[test]
    fn resolves_module_aliases() {
        let imports = PythonImports::from_source("import subprocess as sp\nimport os, json\n");
        assert_eq!(imports.canonical_call_name("sp.run"), "subprocess.run");
        assert_eq!(imports.canonical_call_name("os.system"), "os.system");
        assert_eq!(imports.canonical_call_name("other.run"), "other.run");
    }

    #[test]
    fn resolves_member_aliases() {
        let imports = PythonImports::from_source(
            "from subprocess import run, Popen as P\nfrom os import (\n    system,  # shell\n    popen as po,\n)\n",
        );
        assert_eq!(imports.canonical_call_name("run"), "subprocess.run");
        assert_eq!(imports.canonical_call_name("P"), "subprocess.Popen");
        assert_eq!(imports.canonical_call_name("system"), "os.system");
        assert_eq!(imports.canonical_call_name("po"), "os.popen");
        assert_eq!(imports.canonical_call_name("walk"), "walk");
    }

    #[test]
    fn dotted_module_import_binds_its_root() {
        let imports = PythonImports::from_source("import urllib.request\nimport os.path as osp\n");
        assert_eq!(
            imports.canonical_call_name("urllib.request.urlopen"),
            "urllib.request.urlopen"
        );
        assert_eq!(imports.canonical_call_name("osp.join"), "os.path.join");
    }

    #[test]
    fn unrelated_local_function_is_untouched() {
        let imports = PythonImports::from_source("import subprocess\n");
        assert_eq!(imports.canonical_call_name("run"), "run");
    }
}
