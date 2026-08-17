use once_cell::sync::Lazy;
use regex::Regex;

pub(crate) static OPENAI_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9_-]{20,}").expect("valid OpenAI API key regex"));

pub(crate) static GITHUB_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:gh[opusr]_|github_pat_)[A-Za-z0-9_]{20,}").expect("valid GitHub token regex")
});

pub(crate) static AWS_ACCESS_KEY_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid AWS access key id regex"));

pub(crate) static AWS_SECRET_ACCESS_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(["']?\b(?:aws_secret_access_key|secret_access_key)\b["']?\s*[:=]\s*)(?:"([^"]*)"|'([^']*)'|([^\s"',}\];]+))"#,
    )
    .expect("valid AWS secret access key regex")
});

pub(crate) static AWS_SECRET_ACCESS_KEY_VALUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9/+=]{40}").expect("valid AWS secret access key value regex")
});

pub(crate) static BEARER_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Bearer [A-Za-z0-9._~+/=-]{20,}").expect("valid bearer token regex"));

pub(crate) static JWT_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    // Anchor the first segment to the JWT header prefix `eyJ` (base64url of the
    // JSON `{"...`) so arbitrary three-part dotted strings (S3 keys, module
    // paths, hostnames) are not redacted as JWTs.
    Regex::new(r"\beyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        .expect("valid JWT token regex")
});

pub(crate) static PEM_PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("valid PEM private key regex")
});

pub(crate) static BASIC_AUTH_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(https?://)[^/@\s:]+:[^/@\s]+@([^\s"'<>()]+)"#)
        .expect("valid basic auth URL regex")
});

pub(crate) static SLACK_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xox[abprs]-[A-Za-z0-9-]{10,}").expect("valid Slack token regex"));

pub(crate) static GOOGLE_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AIza[A-Za-z0-9_-]{20,}").expect("valid Google API key regex"));

pub(crate) static STRIPE_SECRET_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{16,}").expect("valid Stripe secret key regex")
});

pub(crate) static GENERIC_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(["']?\b(?:api_key|apikey|token|secret|password|passwd|pwd|access_key|private_key|credential|auth)\b["']?\s*[:=]\s*)(?:"([^"]*)"|'([^']*)'|([^\s"',}\];]+))"#,
    )
    .expect("valid generic secret regex")
});
