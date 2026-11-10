use serde::{Deserialize, Serialize};

use super::host::normalize_host;

/// Domain-level allow/deny policy using glob-style patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPolicy {
    /// Allowed domain patterns (glob-style: `"*.example.com"`, `"api.github.com"`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicitly denied domain patterns (takes precedence over allow).
    #[serde(default)]
    pub deny: Vec<String>,
}

impl DomainPolicy {
    /// Check if a domain is allowed by this policy.
    ///
    /// Deny rules take precedence over allow rules. If the allow list is
    /// empty, all domains not explicitly denied are allowed.
    ///
    /// Fails closed: a host that has no canonical form (see
    /// [`normalize_host`]) is never allowed, and neither is anything when a
    /// rule cannot be parsed, so a broken rule can never widen access.
    pub(super) fn is_domain_allowed(&self, domain: &str) -> bool {
        let Some(host) = normalize_host(domain) else {
            return false;
        };
        let (Some(deny), Some(allow)) = (parse_all(&self.deny), parse_all(&self.allow)) else {
            return false;
        };
        // Deny takes precedence
        if deny.iter().any(|pattern| pattern.matches(&host)) {
            return false;
        }
        // If allow list is empty, allow all (that aren't denied)
        allow.is_empty() || allow.iter().any(|pattern| pattern.matches(&host))
    }
}

fn parse_all(patterns: &[String]) -> Option<Vec<Pattern>> {
    patterns
        .iter()
        .map(|pattern| Pattern::parse(pattern).ok())
        .collect()
}

/// Why a domain pattern was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PatternError {
    /// Nothing, or only whitespace.
    Empty,
    /// An empty label, such as `*.`, `.`, `a..b` or `*..x`.
    EmptyLabel,
    /// Not a valid host name (for example a malformed `xn--` label).
    InvalidHost,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the pattern is empty",
            Self::EmptyLabel => {
                "it contains an empty label (a wildcard needs a domain after `*.`, \
                 and a bare `*` is the only way to match every host)"
            }
            Self::InvalidHost => "it is not a valid host name or IP literal",
        })
    }
}

/// A parsed domain pattern, in canonical form (see [`normalize_host`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pattern {
    /// `*`: every host.
    Any,
    /// `*.example.com` matches `example.com` and every subdomain. The legacy
    /// spelling `*example.com` (no dot) is kept for existing policy files and
    /// matches any host ending in that text.
    Wildcard { suffix: String, dotted: bool },
    /// A single host name or IP literal.
    Exact(String),
}

impl Pattern {
    /// Parse a pattern, normalizing Unicode and punycode spellings to one form.
    pub(super) fn parse(raw: &str) -> Result<Self, PatternError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(PatternError::Empty);
        }
        if raw == "*" {
            return Ok(Self::Any);
        }
        match raw.strip_prefix('*') {
            Some(rest) => {
                let dotted = rest.starts_with('.');
                let body = rest.strip_prefix('.').unwrap_or(rest);
                let body = normalize_part(body)?;
                let suffix = if dotted { format!(".{body}") } else { body };
                Ok(Self::Wildcard { suffix, dotted })
            }
            None => normalize_part(raw).map(Self::Exact),
        }
    }

    /// Whether the canonical host `host` matches this pattern.
    pub(super) fn matches(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Wildcard { suffix, dotted } => {
                host.ends_with(suffix.as_str()) || (*dotted && host == &suffix[1..])
            }
            Self::Exact(name) => host == name,
        }
    }
}

/// Normalize the host part of a pattern, telling an empty label apart from
/// other invalid input so the error message can name the real problem.
fn normalize_part(part: &str) -> Result<String, PatternError> {
    normalize_host(part).ok_or_else(|| {
        let name = part.strip_suffix('.').unwrap_or(part);
        if name.is_empty() || name.split('.').any(str::is_empty) {
            PatternError::EmptyLabel
        } else {
            PatternError::InvalidHost
        }
    })
}

/// Glob matching for domain patterns.
///
/// Supports `*.example.com` (matches `sub.example.com` and `example.com`),
/// exact matches like `api.github.com`, and a bare `*` (matches every host).
/// Both sides are normalized first: ASCII case, a trailing root dot, and
/// Unicode versus punycode spelling do not matter. Anything that cannot be
/// normalized does not match.
pub(super) fn domain_matches(domain: &str, pattern: &str) -> bool {
    match (normalize_host(domain), Pattern::parse(pattern)) {
        (Some(host), Ok(pattern)) => pattern.matches(&host),
        _ => false,
    }
}

/// Extract the hostname from a URL string or bare domain.
///
/// Handles `http://`, `https://` URLs (strips scheme, path, port) and bare
/// domain names (e.g., `"api.example.com"`). Returns `None` for strings that
/// cannot be mapped to a useful hostname (e.g., paths, IP-like without dot).
/// The hostname is returned in canonical form (see [`normalize_host`]).
pub(super) fn extract_domain(url_or_domain: &str) -> Option<String> {
    // Try stripping http:// or https://
    let rest = if let Some(r) = url_or_domain.strip_prefix("https://") {
        r
    } else if let Some(r) = url_or_domain.strip_prefix("http://") {
        r
    } else {
        // Bare domain: must contain a dot and no slashes
        if url_or_domain.contains('.') && !url_or_domain.contains('/') {
            return normalize_host(url_or_domain);
        }
        return None;
    };

    // Take the host portion (before first '/')
    let host = rest.split('/').next()?;
    // Strip port if present
    let host = host.split(':').next()?;

    if host.is_empty() {
        return None;
    }
    normalize_host(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_label_patterns_are_rejected_with_a_specific_reason() {
        for raw in ["*.", ".", "*..x", "a..b", ".example.com", "*.example.com.."] {
            assert_eq!(
                Pattern::parse(raw),
                Err(PatternError::EmptyLabel),
                "pattern {raw:?}"
            );
        }
        assert_eq!(Pattern::parse(""), Err(PatternError::Empty));
        assert_eq!(Pattern::parse("  "), Err(PatternError::Empty));
        assert_eq!(
            Pattern::parse("xn--.example"),
            Err(PatternError::InvalidHost)
        );
    }

    #[test]
    fn valid_patterns_parse_to_their_canonical_form() {
        assert_eq!(Pattern::parse("*"), Ok(Pattern::Any));
        assert_eq!(
            Pattern::parse("*.Bücher.Example."),
            Ok(Pattern::Wildcard {
                suffix: ".xn--bcher-kva.example".into(),
                dotted: true
            })
        );
        assert_eq!(
            Pattern::parse("[::ffff:8.8.8.8]"),
            Ok(Pattern::Exact("8.8.8.8".into()))
        );
    }

    #[test]
    fn legacy_undotted_wildcard_keeps_suffix_semantics() {
        let pattern = Pattern::parse("*example.com").unwrap();
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("evilexample.com"));
        assert!(!pattern.matches("example.org"));
    }
}
