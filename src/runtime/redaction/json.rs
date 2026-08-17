use serde_json::Value;

use super::engine::redact_text;
use super::types::{Redaction, RedactionKind, replacement_for_key_redacted_value};

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

pub(crate) fn redact_optional_string(value: &mut Option<String>, redactions: &mut Vec<Redaction>) {
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
pub(crate) const MAX_JSON_REDACTION_DEPTH: usize = 256;

pub(crate) fn redact_json_strings(value: &mut Value, redactions: &mut Vec<Redaction>) {
    redact_json_value(value, None, 0, redactions);
}

pub(crate) fn redact_json_value(
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
pub(crate) fn redact_secret_scalar(
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
pub(crate) fn redact_overflowed_subtree(
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

pub(crate) fn secret_kind_for_json_key(key: &str) -> Option<RedactionKind> {
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

pub(crate) fn normalized_json_key(key: &str) -> String {
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

pub(crate) fn contains_token_sequence(tokens: &[&str], sequence: &[&str]) -> bool {
    !sequence.is_empty()
        && tokens.len() >= sequence.len()
        && tokens
            .windows(sequence.len())
            .any(|window| window == sequence)
}
