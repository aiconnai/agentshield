use once_cell::sync::Lazy;
use regex::Regex;

static INSTALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"pip\s+install").expect("static regex pattern is valid"),
        Regex::new(r"pip3\s+install").expect("static regex pattern is valid"),
        Regex::new(r"npm\s+install").expect("static regex pattern is valid"),
        Regex::new(r"npm\s+i\b").expect("static regex pattern is valid"),
        Regex::new(r"uv\s+pip\s+install").expect("static regex pattern is valid"),
        Regex::new(r"yarn\s+add").expect("static regex pattern is valid"),
        Regex::new(r"pnpm\s+add").expect("static regex pattern is valid"),
    ]
});

pub(crate) fn is_runtime_install_command(command: &str) -> bool {
    INSTALL_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(command))
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
