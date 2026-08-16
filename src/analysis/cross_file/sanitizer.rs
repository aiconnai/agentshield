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
    "path.resolve",
    "path.normalize",
    "resolve",
    "normalize",
    "os.path.realpath",
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

pub fn sanitizer_label(name: &str) -> Option<String> {
    sanitizer_category(name).map(|category| format!("{}:{name}", category.as_str()))
}
