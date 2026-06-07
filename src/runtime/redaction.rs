use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    OpenAiApiKey,
    GitHubToken,
    AwsAccessKeyId,
    AwsSecretAccessKey,
    BearerToken,
    JwtToken,
    PemPrivateKey,
    BasicAuthUrl,
    SlackToken,
    GoogleApiKey,
    StripeSecretKey,
    GenericSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    pub kind: RedactionKind,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionReport {
    pub redacted_text: String,
    pub redactions: Vec<Redaction>,
}

#[derive(Debug, Clone)]
struct Match {
    kind: RedactionKind,
    start: usize,
    end: usize,
    replacement: String,
}

static OPENAI_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9_-]{20,}").expect("valid OpenAI API key regex"));
static GITHUB_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:gh[opusr]_|github_pat_)[A-Za-z0-9_]{20,}").expect("valid GitHub token regex")
});
static AWS_ACCESS_KEY_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid AWS access key id regex"));
static AWS_SECRET_ACCESS_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(["']?\b(?:aws_secret_access_key|secret_access_key)\b["']?\s*[:=]\s*)(?:"([^"]*)"|'([^']*)'|([^\s"',}\];]+))"#,
    )
        .expect("valid AWS secret access key regex")
});
static AWS_SECRET_ACCESS_KEY_VALUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9/+=]{40}").expect("valid AWS secret access key value regex")
});
static BEARER_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Bearer [A-Za-z0-9._~+/=-]{20,}").expect("valid bearer token regex"));
static JWT_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    // Anchor the first segment to the JWT header prefix `eyJ` (base64url of the
    // JSON `{"...`) so arbitrary three-part dotted strings (S3 keys, module
    // paths, hostnames) are not redacted as JWTs.
    Regex::new(r"\beyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        .expect("valid JWT token regex")
});
static PEM_PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("valid PEM private key regex")
});
static BASIC_AUTH_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(https?://)[^/@\s:]+:[^/@\s]+@([^\s"'<>()]+)"#)
        .expect("valid basic auth URL regex")
});
static SLACK_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xox[abprs]-[A-Za-z0-9-]{10,}").expect("valid Slack token regex"));
static GOOGLE_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AIza[A-Za-z0-9_-]{20,}").expect("valid Google API key regex"));
static STRIPE_SECRET_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{16,}").expect("valid Stripe secret key regex")
});
static GENERIC_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(["']?\b(?:api_key|apikey|token|secret|password|passwd|pwd|access_key|private_key|credential|auth)\b["']?\s*[:=]\s*)(?:"([^"]*)"|'([^']*)'|([^\s"',}\];]+))"#,
    )
        .expect("valid generic secret regex")
});

pub fn redact_text(input: &str) -> RedactionReport {
    let mut matches = Vec::new();

    collect_simple_matches(
        input,
        &OPENAI_API_KEY_RE,
        RedactionKind::OpenAiApiKey,
        "[REDACTED:openai_api_key]",
        &mut matches,
    );
    collect_simple_matches(
        input,
        &GITHUB_TOKEN_RE,
        RedactionKind::GitHubToken,
        "[REDACTED:github_token]",
        &mut matches,
    );
    collect_simple_matches(
        input,
        &AWS_ACCESS_KEY_ID_RE,
        RedactionKind::AwsAccessKeyId,
        "[REDACTED:aws_access_key_id]",
        &mut matches,
    );
    collect_key_value_matches(
        input,
        &AWS_SECRET_ACCESS_KEY_RE,
        RedactionKind::AwsSecretAccessKey,
        "[REDACTED:aws_secret_access_key]",
        &mut matches,
    );
    collect_aws_secret_access_key_value_matches(input, &mut matches);
    collect_simple_matches(
        input,
        &BEARER_TOKEN_RE,
        RedactionKind::BearerToken,
        "Bearer [REDACTED:bearer_token]",
        &mut matches,
    );
    collect_simple_matches(
        input,
        &JWT_TOKEN_RE,
        RedactionKind::JwtToken,
        "[REDACTED:jwt_token]",
        &mut matches,
    );
    collect_simple_matches(
        input,
        &PEM_PRIVATE_KEY_RE,
        RedactionKind::PemPrivateKey,
        "[REDACTED:pem_private_key]",
        &mut matches,
    );
    collect_basic_auth_url_matches(input, &mut matches);
    collect_simple_matches(
        input,
        &SLACK_TOKEN_RE,
        RedactionKind::SlackToken,
        "[REDACTED:slack_token]",
        &mut matches,
    );
    collect_simple_matches(
        input,
        &GOOGLE_API_KEY_RE,
        RedactionKind::GoogleApiKey,
        "[REDACTED:google_api_key]",
        &mut matches,
    );
    collect_simple_matches(
        input,
        &STRIPE_SECRET_KEY_RE,
        RedactionKind::StripeSecretKey,
        "[REDACTED:stripe_secret_key]",
        &mut matches,
    );
    collect_key_value_matches(
        input,
        &GENERIC_SECRET_RE,
        RedactionKind::GenericSecret,
        "[REDACTED:generic_secret]",
        &mut matches,
    );

    matches.sort_by_key(|candidate| {
        (
            redaction_match_priority(candidate.kind),
            candidate.start,
            candidate.end,
        )
    });

    let mut selected: Vec<Match> = Vec::new();
    for candidate in matches {
        if !selected.iter().any(|existing| {
            ranges_overlap(candidate.start, candidate.end, existing.start, existing.end)
        }) {
            selected.push(candidate);
        }
    }

    selected.sort_by_key(|redaction| redaction.start);

    let mut redacted_text = String::with_capacity(input.len());
    let mut cursor = 0;
    let mut redactions = Vec::with_capacity(selected.len());

    for selected_match in selected {
        redacted_text.push_str(&input[cursor..selected_match.start]);
        redacted_text.push_str(&selected_match.replacement);
        cursor = selected_match.end;
        redactions.push(Redaction {
            kind: selected_match.kind,
            start: selected_match.start,
            end: selected_match.end,
        });
    }

    redacted_text.push_str(&input[cursor..]);

    RedactionReport {
        redacted_text,
        redactions,
    }
}

pub fn redact_runtime_event(
    event: crate::runtime::RuntimeEvent,
) -> (crate::runtime::RuntimeEvent, Vec<Redaction>) {
    // Destructure exhaustively so a newly-added field is a compile error here
    // rather than a silent redaction bypass (deny-by-default). Non-secret
    // fields are listed explicitly to acknowledge they carry no secrets.
    let crate::runtime::RuntimeEvent {
        schema_version,
        source,
        action,
        mut tool_name,
        mut command,
        mut url,
        mut path,
        mut arguments,
        redacted: _, // never trust the caller-supplied flag; recomputed below.
    } = event;

    let mut redactions = Vec::new();
    redact_optional_string(&mut tool_name, &mut redactions);
    redact_optional_string(&mut command, &mut redactions);
    redact_optional_string(&mut url, &mut redactions);
    redact_optional_string(&mut path, &mut redactions);
    redact_json_strings(&mut arguments, &mut redactions);

    let event = crate::runtime::RuntimeEvent {
        schema_version,
        source,
        action,
        tool_name,
        command,
        url,
        path,
        arguments,
        // Authoritative: reflects what redaction actually did, ignoring any
        // attacker-set input value.
        redacted: !redactions.is_empty(),
    };

    (event, redactions)
}

fn collect_simple_matches(
    input: &str,
    regex: &Regex,
    kind: RedactionKind,
    replacement: &str,
    matches: &mut Vec<Match>,
) {
    for regex_match in regex.find_iter(input) {
        matches.push(Match {
            kind,
            start: regex_match.start(),
            end: regex_match.end(),
            replacement: replacement.to_string(),
        });
    }
}

fn redaction_match_priority(kind: RedactionKind) -> u8 {
    match kind {
        RedactionKind::GenericSecret => 1,
        _ => 0,
    }
}

fn collect_key_value_matches(
    input: &str,
    regex: &Regex,
    kind: RedactionKind,
    value_replacement: &str,
    matches: &mut Vec<Match>,
) {
    for captures in regex.captures_iter(input) {
        if let (Some(full_match), Some(prefix_match)) = (captures.get(0), captures.get(1)) {
            let replacement = if captures.get(2).is_some() {
                format!("{}\"{}\"", prefix_match.as_str(), value_replacement)
            } else if captures.get(3).is_some() {
                format!("{}'{}'", prefix_match.as_str(), value_replacement)
            } else {
                format!("{}{}", prefix_match.as_str(), value_replacement)
            };

            matches.push(Match {
                kind,
                start: full_match.start(),
                end: full_match.end(),
                replacement,
            });
        }
    }
}

fn collect_aws_secret_access_key_value_matches(input: &str, matches: &mut Vec<Match>) {
    for regex_match in AWS_SECRET_ACCESS_KEY_VALUE_RE.find_iter(input) {
        let candidate = regex_match.as_str();
        if has_secret_value_boundary(input, regex_match.start(), regex_match.end())
            && looks_like_aws_secret_access_key_value(candidate)
        {
            matches.push(Match {
                kind: RedactionKind::AwsSecretAccessKey,
                start: regex_match.start(),
                end: regex_match.end(),
                replacement: "[REDACTED:aws_secret_access_key]".to_string(),
            });
        }
    }
}

fn has_secret_value_boundary(input: &str, start: usize, end: usize) -> bool {
    let before_is_boundary = input[..start]
        .chars()
        .next_back()
        .is_none_or(|character| !is_aws_secret_access_key_character(character));
    let after_is_boundary = input[end..]
        .chars()
        .next()
        .is_none_or(|character| !is_aws_secret_access_key_character(character));

    before_is_boundary && after_is_boundary
}

fn looks_like_aws_secret_access_key_value(candidate: &str) -> bool {
    if candidate.len() != 40 {
        return false;
    }

    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut seen = [false; 256];
    let mut unique_count = 0;

    for byte in candidate.bytes() {
        if !is_aws_secret_access_key_byte(byte) {
            return false;
        }

        let index = usize::from(byte);
        if !seen[index] {
            seen[index] = true;
            unique_count += 1;
        }

        match byte {
            b'a'..=b'z' => has_lowercase = true,
            b'A'..=b'Z' => has_uppercase = true,
            b'0'..=b'9' => has_digit = true,
            b'/' | b'+' | b'=' => has_symbol = true,
            _ => {}
        }
    }

    has_lowercase && has_uppercase && (has_digit || has_symbol) && unique_count >= 16
}

fn is_aws_secret_access_key_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'+' | b'=')
}

fn is_aws_secret_access_key_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '/' | '+' | '=')
}

fn collect_basic_auth_url_matches(input: &str, matches: &mut Vec<Match>) {
    for captures in BASIC_AUTH_URL_RE.captures_iter(input) {
        if let (Some(full_match), Some(scheme_match), Some(host_and_path_match)) =
            (captures.get(0), captures.get(1), captures.get(2))
        {
            matches.push(Match {
                kind: RedactionKind::BasicAuthUrl,
                start: full_match.start(),
                end: full_match.end(),
                replacement: format!(
                    "{}[REDACTED:basic_auth]@{}",
                    scheme_match.as_str(),
                    host_and_path_match.as_str()
                ),
            });
        }
    }
}

fn redact_optional_string(value: &mut Option<String>, redactions: &mut Vec<Redaction>) {
    if let Some(text) = value {
        let report = redact_text(text);
        if !report.redactions.is_empty() {
            *text = report.redacted_text;
            redactions.extend(report.redactions);
        }
    }
}

/// Maximum JSON nesting depth `redact_json_value` will descend.
///
/// Bounds the recursion so an attacker-controlled, deeply nested `arguments`
/// payload cannot stack-overflow the process. A guard-page overflow is an
/// uncatchable abort, which for the runtime guard is a fail-open (the guard
/// dies instead of redacting), so this limit fails *closed*: at the cap we
/// stop descending and scrub the remaining subtree wholesale via
/// [`redact_overflowed_subtree`] rather than recursing further.
const MAX_JSON_REDACTION_DEPTH: usize = 256;

fn redact_json_strings(value: &mut Value, redactions: &mut Vec<Redaction>) {
    redact_json_value(value, None, 0, redactions);
}

fn redact_json_value(
    value: &mut Value,
    inherited_secret_kind: Option<RedactionKind>,
    depth: usize,
    redactions: &mut Vec<Redaction>,
) {
    if depth >= MAX_JSON_REDACTION_DEPTH {
        // Fail closed: do not recurse past the bound. Scrub any string values
        // in the remaining subtree so nothing leaks, then stop descending.
        redact_overflowed_subtree(value, inherited_secret_kind, redactions);
        return;
    }
    match value {
        Value::String(text) => {
            if let Some(kind) = inherited_secret_kind {
                if !text.is_empty() {
                    let original_len = text.len();
                    *text = replacement_for_key_redacted_value(kind).to_string();
                    redactions.push(Redaction {
                        kind,
                        start: 0,
                        end: original_len,
                    });
                }
            } else {
                let report = redact_text(text);
                if !report.redactions.is_empty() {
                    *text = report.redacted_text;
                    redactions.extend(report.redactions);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, inherited_secret_kind, depth + 1, redactions);
            }
        }
        Value::Object(entries) => {
            for (key, entry) in entries.iter_mut() {
                let secret_kind = secret_kind_for_json_key(key).or(inherited_secret_kind);
                redact_json_value(entry, secret_kind, depth + 1, redactions);
            }
        }
        // A numeric value under a secret-like key (e.g. {"pin": 1234}) is still
        // a secret — replace it with a redacted string so it does not leak.
        Value::Number(_) => redact_secret_scalar(value, inherited_secret_kind, redactions),
        Value::Null | Value::Bool(_) => {}
    }
}

/// Replace a non-string scalar that sits under a secret-like key with a redacted
/// string placeholder. No-op when there is no inherited secret context.
fn redact_secret_scalar(
    value: &mut Value,
    inherited_secret_kind: Option<RedactionKind>,
    redactions: &mut Vec<Redaction>,
) {
    if let Some(kind) = inherited_secret_kind {
        let original_len = value.to_string().len();
        *value = Value::String(replacement_for_key_redacted_value(kind).to_string());
        redactions.push(Redaction {
            kind,
            start: 0,
            end: original_len,
        });
    }
}

/// Scrub every string in `value`'s subtree without recursing, used when the
/// recursion depth bound is hit. Walks the subtree with an explicit stack so a
/// pathologically deep payload cannot overflow the native stack here either.
/// Fails closed: keys with no secret context still get the generic
/// [`redact_text`] pass, and any secret context inherited from above is
/// applied wholesale to descendant strings.
fn redact_overflowed_subtree(
    value: &mut Value,
    inherited_secret_kind: Option<RedactionKind>,
    redactions: &mut Vec<Redaction>,
) {
    let mut stack: Vec<(&mut Value, Option<RedactionKind>)> = vec![(value, inherited_secret_kind)];
    while let Some((node, secret_kind)) = stack.pop() {
        match node {
            Value::String(text) => {
                if let Some(kind) = secret_kind {
                    if !text.is_empty() {
                        let original_len = text.len();
                        *text = replacement_for_key_redacted_value(kind).to_string();
                        redactions.push(Redaction {
                            kind,
                            start: 0,
                            end: original_len,
                        });
                    }
                } else {
                    let report = redact_text(text);
                    if !report.redactions.is_empty() {
                        *text = report.redacted_text;
                        redactions.extend(report.redactions);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    stack.push((item, secret_kind));
                }
            }
            Value::Object(entries) => {
                for (key, entry) in entries.iter_mut() {
                    let kind = secret_kind_for_json_key(key).or(secret_kind);
                    stack.push((entry, kind));
                }
            }
            Value::Number(_) => redact_secret_scalar(node, secret_kind, redactions),
            Value::Null | Value::Bool(_) => {}
        }
    }
}

fn replacement_for_key_redacted_value(kind: RedactionKind) -> &'static str {
    match kind {
        RedactionKind::AwsSecretAccessKey => "[REDACTED:aws_secret_access_key]",
        RedactionKind::OpenAiApiKey => "[REDACTED:openai_api_key]",
        RedactionKind::GitHubToken => "[REDACTED:github_token]",
        RedactionKind::AwsAccessKeyId => "[REDACTED:aws_access_key_id]",
        RedactionKind::BearerToken => "[REDACTED:bearer_token]",
        RedactionKind::JwtToken => "[REDACTED:jwt_token]",
        RedactionKind::PemPrivateKey => "[REDACTED:pem_private_key]",
        RedactionKind::BasicAuthUrl => "[REDACTED:basic_auth]",
        RedactionKind::SlackToken => "[REDACTED:slack_token]",
        RedactionKind::GoogleApiKey => "[REDACTED:google_api_key]",
        RedactionKind::StripeSecretKey => "[REDACTED:stripe_secret_key]",
        RedactionKind::GenericSecret => "[REDACTED:generic_secret]",
    }
}

fn secret_kind_for_json_key(key: &str) -> Option<RedactionKind> {
    let normalized = normalized_json_key(key);
    let tokens: Vec<&str> = normalized
        .split('_')
        .filter(|token| !token.is_empty())
        .collect();
    let compact = tokens.join("");

    if compact == "awssecretaccesskey" || compact == "secretaccesskey" {
        return Some(RedactionKind::AwsSecretAccessKey);
    }

    if matches!(compact.as_str(), "apikey" | "accesskey" | "privatekey") {
        return Some(RedactionKind::GenericSecret);
    }

    if contains_token_sequence(&tokens, &["aws", "secret", "access", "key"])
        || contains_token_sequence(&tokens, &["secret", "access", "key"])
    {
        return Some(RedactionKind::AwsSecretAccessKey);
    }

    if contains_token_sequence(&tokens, &["api", "key"])
        || contains_token_sequence(&tokens, &["access", "key"])
        || contains_token_sequence(&tokens, &["private", "key"])
    {
        return Some(RedactionKind::GenericSecret);
    }

    if tokens.iter().any(|token| {
        matches!(
            *token,
            "secret"
                | "password"
                | "passwd"
                | "pwd"
                | "token"
                | "credential"
                | "credentials"
                | "auth"
                | "authorization"
                | "bearer"
                | "cookie"
                | "session"
                | "sessionid"
        )
    }) {
        return Some(RedactionKind::GenericSecret);
    }

    None
}

fn normalized_json_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    let mut previous_was_separator = false;

    for character in key.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            normalized.push('_');
            previous_was_separator = true;
        }
    }

    normalized.trim_matches('_').to_string()
}

fn contains_token_sequence(tokens: &[&str], sequence: &[&str]) -> bool {
    !sequence.is_empty()
        && tokens.len() >= sequence.len()
        && tokens
            .windows(sequence.len())
            .any(|window| window == sequence)
}

fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}
