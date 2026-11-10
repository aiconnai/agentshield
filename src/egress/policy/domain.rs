use serde::{Deserialize, Serialize};

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
    pub(super) fn is_domain_allowed(&self, domain: &str) -> bool {
        // Deny takes precedence
        if self
            .deny
            .iter()
            .any(|pattern| domain_matches(domain, pattern))
        {
            return false;
        }
        // If allow list is empty, allow all (that aren't denied)
        if self.allow.is_empty() {
            return true;
        }
        self.allow
            .iter()
            .any(|pattern| domain_matches(domain, pattern))
    }
}

/// Canonical form of a host or pattern for matching: DNS names are
/// case-insensitive and a trailing root dot names the same host.
pub(super) fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Simple glob matching for domain patterns.
///
/// Supports `*.example.com` (matches `sub.example.com` and `example.com`),
/// exact matches like `api.github.com`, and a bare `*` (matches every host).
/// Matching ignores ASCII case and a trailing root dot.
pub(super) fn domain_matches(domain: &str, pattern: &str) -> bool {
    let domain = normalize_domain(domain);
    let pattern = normalize_domain(pattern);
    match pattern.strip_prefix('*') {
        Some("") => true,
        // "*.example.com" matches "sub.example.com" and "example.com"
        Some(suffix) => {
            domain.ends_with(suffix) || suffix.strip_prefix('.').is_some_and(|bare| domain == bare)
        }
        None => domain == pattern,
    }
}

/// Extract the hostname from a URL string or bare domain.
///
/// Handles `http://`, `https://` URLs (strips scheme, path, port) and bare
/// domain names (e.g., `"api.example.com"`). Returns `None` for strings that
/// cannot be mapped to a useful hostname (e.g., paths, IP-like without dot).
pub(super) fn extract_domain(url_or_domain: &str) -> Option<String> {
    // Try stripping http:// or https://
    let rest = if let Some(r) = url_or_domain.strip_prefix("https://") {
        r
    } else if let Some(r) = url_or_domain.strip_prefix("http://") {
        r
    } else {
        // Bare domain: must contain a dot and no slashes
        if url_or_domain.contains('.') && !url_or_domain.contains('/') {
            return Some(url_or_domain.to_string());
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
    Some(host.to_string())
}
