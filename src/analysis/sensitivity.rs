//! Shared heuristic for classifying variable/header names as credential-shaped.
//!
//! Used by adapters and parsers that need to flag `is_sensitive` on env
//! accesses and headers. A single implementation avoids the same secret name
//! being flagged by one adapter and missed by another.

/// Heuristic: does this variable/header name look like it holds a credential?
pub(crate) fn looks_sensitive_name(name: &str) -> bool {
    let matches_pattern = |needle: &str| -> bool {
        name.as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
    };

    let starts_with_ci = |prefix: &str| -> bool {
        name.len() >= prefix.len()
            && name.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    };

    let ends_with_ci = |suffix: &str| -> bool {
        name.len() >= suffix.len()
            && name.as_bytes()[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
    };

    matches_pattern("SECRET")
        || matches_pattern("TOKEN")
        || matches_pattern("PASSWORD")
        || matches_pattern("CREDENTIAL")
        || matches_pattern("AUTHORIZATION")
        || matches_pattern("AUTHENTICAT")
        || starts_with_ci("AUTH_")
        || ends_with_ci("_AUTH")
        || name.eq_ignore_ascii_case("AUTH")
        || matches_pattern("PRIVATE_KEY")
        || matches_pattern("API_KEY")
        || ends_with_ci("_KEY")
        || starts_with_ci("AWS_")
        || starts_with_ci("GH_")
        || starts_with_ci("GITHUB_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_known_sensitive_names() {
        for name in [
            "API_KEY",
            "PRIVATE_KEY",
            "ENCRYPTION_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AUTHORIZATION",
            "CREDENTIAL",
            "CREDENTIALS",
        ] {
            assert!(looks_sensitive_name(name), "{name} should be sensitive");
        }
    }

    #[test]
    fn does_not_flag_benign_names() {
        for name in [
            "USERNAME",
            "HOST",
            "PORT",
            "MODEL",
            "TIMEOUT",
            "AUTHOR",
            "AUTHORS",
            "AUTHOR_EMAIL",
            "AUTHORITY",
        ] {
            assert!(
                !looks_sensitive_name(name),
                "{name} should not be sensitive"
            );
        }
    }
}
