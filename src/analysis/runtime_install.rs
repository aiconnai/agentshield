use once_cell::sync::Lazy;
use regex::Regex;

static INSTALL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:pip3?|uv\s+pip)\s+install|npm\s+(?:install|i\b)|(?:yarn|pnpm)\s+add")
        .expect("static regex pattern is valid")
});

pub(crate) fn is_runtime_install_command(command: &str) -> bool {
    INSTALL_PATTERN.is_match(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_runtime_install_commands() {
        assert!(is_runtime_install_command("npm install lodash"));
        assert!(is_runtime_install_command("uv pip install requests"));
        assert!(!is_runtime_install_command("npm run build"));
    }
}
