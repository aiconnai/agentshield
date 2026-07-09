//! Shared heuristic for classifying variable/header names as credential-shaped.
//!
//! Used by adapters and parsers that need to flag `is_sensitive` on env
//! accesses and headers. A single implementation avoids the same secret name
//! being flagged by one adapter and missed by another.

/// Heuristic: does this variable/header name look like it holds a credential?
pub(crate) fn looks_sensitive_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("PASSWORD")
        || upper.contains("CREDENTIAL")
        || upper.contains("AUTH")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("API_KEY")
        || upper.ends_with("_KEY")
        || upper.starts_with("AWS_")
        || upper.starts_with("GH_")
        || upper.starts_with("GITHUB_")
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
        for name in ["USERNAME", "HOST", "PORT", "MODEL", "TIMEOUT"] {
            assert!(
                !looks_sensitive_name(name),
                "{name} should not be sensitive"
            );
        }
    }
}
