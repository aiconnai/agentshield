use serde::{Deserialize, Serialize};

/// Category of secret matched by the redaction engine.
///
/// Each variant covers a specific token family:
///
/// - `OpenAiApiKey`: OpenAI API keys (`sk-...`, `sk-proj-...`).
/// - `GitHubToken`: GitHub personal access / OAuth tokens (`ghp_...`, `gho_...`, etc.).
/// - `AwsAccessKeyId` / `AwsSecretAccessKey`: AWS access key ID and secret access key pair.
/// - `BearerToken`: generic `Authorization: Bearer ...` credentials. This is also
///   the fallback family for API tokens from other AI providers (e.g. Anthropic
///   `sk-ant-...`) that carry no provider-specific prefix pattern.
/// - `JwtToken`: JSON Web Tokens (header.payload.signature).
/// - `PemPrivateKey`: PEM-encoded private key blocks.
/// - `BasicAuthUrl`: credentials embedded in a URL (`https://user:pass@host`).
/// - `SlackToken`: Slack tokens (`xox[baprs]-...`).
/// - `GoogleApiKey`: Google API keys (`AIza...`).
/// - `StripeSecretKey`: Stripe secret keys (`sk_live_...`, `sk_test_...`).
/// - `GenericSecret`: last-resort `key = value`-shaped secrets with no
///   provider-specific pattern. Together with `BearerToken`, this catches
///   unclassified third-party tokens.
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
pub(crate) struct Match {
    pub(crate) kind: RedactionKind,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) replacement: String,
}

pub(crate) fn replacement_for_key_redacted_value(kind: RedactionKind) -> &'static str {
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
