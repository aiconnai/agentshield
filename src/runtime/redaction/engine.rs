use regex::Regex;

use super::patterns::*;
use super::types::*;

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

pub(crate) fn collect_simple_matches(
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

pub(crate) fn redaction_match_priority(kind: RedactionKind) -> u8 {
    match kind {
        RedactionKind::GenericSecret => 1,
        _ => 0,
    }
}

pub(crate) fn collect_key_value_matches(
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

pub(crate) fn collect_aws_secret_access_key_value_matches(input: &str, matches: &mut Vec<Match>) {
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

pub(crate) fn has_secret_value_boundary(input: &str, start: usize, end: usize) -> bool {
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

pub(crate) fn looks_like_aws_secret_access_key_value(candidate: &str) -> bool {
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

pub(crate) fn is_aws_secret_access_key_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'+' | b'=')
}

pub(crate) fn is_aws_secret_access_key_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '/' | '+' | '=')
}

pub(crate) fn collect_basic_auth_url_matches(input: &str, matches: &mut Vec<Match>) {
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

pub(crate) fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}
