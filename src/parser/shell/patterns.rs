use once_cell::sync::Lazy;
use regex::Regex;

pub(crate) static CURL_WGET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)\b(curl|wget|aria2c|http|https)\s+").expect("static regex pattern is valid")
});

pub(crate) static EVAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)\beval\s+").expect("static regex pattern is valid"));

pub(crate) static INSTALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)\b(pip3?\s+install|npm\s+install|npm\s+i\b|yarn\s+add|pnpm\s+add|cargo\s+install|gem\s+install|go\s+install)")
        .expect("static regex pattern is valid")
});

pub(crate) static BACKTICK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"`[^`]+`").expect("static regex pattern is valid"));

pub(crate) static SENSITIVE_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\$\{?(AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)")
        .expect("static regex pattern is valid")
});

// Shell positional arguments represent values supplied to a function or script
// invocation. Named variables can come from the caller environment.
pub(crate) static SHELL_VARIABLE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*)|([0-9]+|[@*#?]))")
        .expect("static regex pattern is valid")
});

// Recognize only canonicalization helpers that map to the existing path
// sanitizer contract. Quoting by itself is not a sanitizer.
pub(crate) static PATH_SANITIZER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)^\s*(?:local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?\$\(\s*(realpath|readlink\s+-f)\b"#,
    )
    .expect("static regex pattern is valid")
});
