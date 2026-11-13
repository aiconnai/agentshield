/// Sanitizer category. A sanitizer is only safe for matching sink types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerCategory {
    Path,
    Network,
    Redaction,
    TypeCoercion,
}

impl SanitizerCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Network => "network",
            Self::Redaction => "redaction",
            Self::TypeCoercion => "type",
        }
    }
}

/// Path/file sanitizers. These are safe for file/path sinks only.
static PATH_SANITIZER_NAMES: &[&str] = &[
    "validatePath",
    "sanitizePath",
    "normalizePath",
    "resolvePath",
    "canonicalizePath",
    "realpath",
    "os.path.realpath",
];

/// Path canonicalizers that do NOT confine a path: `path.resolve(base,
/// "../../etc/passwd")` and `os.path.abspath(...)` happily leave `base`. A
/// value they produce is sanitized only when the same scope also checks that
/// it stays inside an allowed root (see [`assignment_sanitizer_label`]).
static UNCONFINED_CANONICALIZER_NAMES: &[&str] = &[
    "path.resolve",
    "path.normalize",
    "resolve",
    "normalize",
    "os.path.abspath",
    "os.path.normpath",
    "abspath",
    "normpath",
];

/// Network/url validators. Parse-only helpers such as URL.parse/urlparse are
/// intentionally excluded: parsing is not allowlist validation.
static NETWORK_SANITIZER_NAMES: &[&str] = &[
    "validateUrl",
    "validateURL",
    "validateUri",
    "validateURI",
    "validateAllowedUrl",
    "validateAllowedURL",
    "validateAllowedUri",
    "validateAllowedURI",
    "allowlistUrl",
    "allowlistURL",
    "allowlistUri",
    "allowlistURI",
    "ensureAllowedUrl",
    "ensureAllowedURL",
    "ensureAllowedUri",
    "ensureAllowedURI",
    "assertAllowedUrl",
    "assertAllowedURL",
    "assertAllowedUri",
    "assertAllowedURI",
];

/// Type coercion helpers. These are not path or network validators.
static TYPE_COERCION_SANITIZER_NAMES: &[&str] =
    &["parseInt", "parseFloat", "Number", "int", "float", "str"];

/// Credential/log redaction helpers. These are safe only for credential/log
/// leakage analysis and must not sanitize file, network, command, or eval sinks.
static REDACTION_SANITIZER_NAMES: &[&str] = &[
    "redactSecret",
    "redactSecrets",
    "redactToken",
    "redactCredentials",
    "maskSecret",
    "maskToken",
    "maskCredentials",
    "scrubSecret",
    "scrubToken",
    "scrubCredentials",
];

fn exact_or_method_match(name: &str, names: &[&str]) -> bool {
    if names.contains(&name) {
        return true;
    }

    name.rsplit('.')
        .next()
        .is_some_and(|method| names.contains(&method))
}

fn compact_lower(name: &str) -> String {
    name.chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Categorize a sanitizer helper by the sink family it protects.
pub fn sanitizer_category(name: &str) -> Option<SanitizerCategory> {
    if let Some((prefix, _)) = name.split_once(':') {
        return match prefix {
            "path" => Some(SanitizerCategory::Path),
            "network" => Some(SanitizerCategory::Network),
            "redaction" => Some(SanitizerCategory::Redaction),
            "type" => Some(SanitizerCategory::TypeCoercion),
            _ => None,
        };
    }

    if exact_or_method_match(name, REDACTION_SANITIZER_NAMES) {
        return Some(SanitizerCategory::Redaction);
    }

    if exact_or_method_match(name, PATH_SANITIZER_NAMES) {
        return Some(SanitizerCategory::Path);
    }

    if exact_or_method_match(name, NETWORK_SANITIZER_NAMES) {
        return Some(SanitizerCategory::Network);
    }

    if exact_or_method_match(name, TYPE_COERCION_SANITIZER_NAMES) {
        return Some(SanitizerCategory::TypeCoercion);
    }

    let lower = compact_lower(name);

    if (lower.starts_with("validate") || lower.starts_with("sanitize")) && lower.contains("path") {
        return Some(SanitizerCategory::Path);
    }

    if (lower.starts_with("validate")
        || lower.starts_with("allowlist")
        || lower.starts_with("ensureallowed")
        || lower.starts_with("assertallowed"))
        && (lower.contains("url")
            || lower.contains("uri")
            || lower.contains("host")
            || lower.contains("domain"))
    {
        return Some(SanitizerCategory::Network);
    }

    None
}

/// Check if a function name is a non-redaction input sanitizer. Kept for parser
/// compatibility; redaction helpers are intentionally excluded from this global
/// taint downgrade path.
#[allow(dead_code)]
pub fn is_sanitizer(name: &str) -> bool {
    matches!(
        sanitizer_category(name),
        Some(
            SanitizerCategory::Path | SanitizerCategory::Network | SanitizerCategory::TypeCoercion
        )
    )
}

#[allow(dead_code)]
pub fn is_redaction_sanitizer(name: &str) -> bool {
    matches!(sanitizer_category(name), Some(SanitizerCategory::Redaction))
}

/// Whether `name` canonicalizes a path without confining it to a root.
pub fn is_unconfined_canonicalizer(name: &str) -> bool {
    exact_or_method_match(name, UNCONFINED_CANONICALIZER_NAMES)
}

/// Sanitizer label for `var = name(...)`, or `None` when the assignment does
/// not sanitize `var`.
///
/// Named sanitizers (`validatePath`, `realpath`, ...) sanitize on their own.
/// Unconfined canonicalizers (`path.resolve`, `os.path.abspath`) sanitize only
/// when `scope_text` -- the enclosing function, or the file at module level --
/// also contains a containment check on `var` (`var.startsWith(root)`,
/// `var.is_relative_to(root)`, `commonpath`, `path.relative`).
pub fn assignment_sanitizer_label(name: &str, var: &str, scope_text: &str) -> Option<String> {
    match sanitizer_category(name) {
        Some(SanitizerCategory::Redaction) => return None,
        Some(_) => return sanitizer_label(name),
        None => {}
    }
    (is_unconfined_canonicalizer(name) && has_containment_check(var, scope_text))
        .then(|| format!("{}:{name}", SanitizerCategory::Path.as_str()))
}

/// Whether `scope_text` checks that `var` stays inside a root directory.
fn has_containment_check(var: &str, scope_text: &str) -> bool {
    let var = regex::escape(var);
    let patterns = [
        format!(r"\b{var}\s*\.\s*(?:startsWith|startswith|is_relative_to|relative_to)\s*\("),
        format!(r"(?:commonpath|commonprefix)\s*\([^)]*\b{var}\b"),
        format!(r"\brelative\s*\([^)]*\b{var}\b"),
    ];
    patterns
        .iter()
        .any(|pattern| regex::Regex::new(pattern).is_ok_and(|re| re.is_match(scope_text)))
}

pub fn sanitizer_label(name: &str) -> Option<String> {
    sanitizer_category(name).map(|category| format!("{}:{name}", category.as_str()))
}
