use agentshield::runtime::{
    redact_runtime_event, redact_text, RedactionKind, RuntimeAction, RuntimeEvent,
    RuntimeEventSource, RuntimeSchemaVersion,
};
use serde_json::json;

#[test]
fn openai_api_key_redaction_removes_original_key() {
    let key = "sk-EXAMPLEEXAMPLEEXAMPLEEXAMPLE00";
    let report = redact_text(&format!("OPENAI_API_KEY={key}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::OpenAiApiKey);
    assert!(report.redacted_text.contains("[REDACTED:openai_api_key]"));
    assert!(!report.redacted_text.contains(key));
}

#[test]
fn github_token_redaction_removes_original_token() {
    let token = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE00";
    let report = redact_text(&format!("token: {token}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::GitHubToken);
    assert!(report.redacted_text.contains("[REDACTED:github_token]"));
    assert!(!report.redacted_text.contains(token));
}

#[test]
fn github_token_redaction_covers_all_supported_prefixes() {
    for prefix in ["ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_"] {
        let token = format!("{prefix}EXAMPLEEXAMPLEEXAMPLEEXAMPLE00");
        let report = redact_text(&format!("observed {token}"));

        assert_eq!(report.redactions[0].kind, RedactionKind::GitHubToken);
        assert!(report.redacted_text.contains("[REDACTED:github_token]"));
        assert!(!report.redacted_text.contains(&token));
    }
}

#[test]
fn bearer_token_redaction_preserves_bearer_but_removes_token_value() {
    let token = "abcdefghijklmnopqrstuvwxyz.1234567890";
    let report = redact_text(&format!("Authorization: Bearer {token}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::BearerToken);
    assert!(report
        .redacted_text
        .contains("Bearer [REDACTED:bearer_token]"));
    assert!(!report.redacted_text.contains(token));
}

#[test]
fn jwt_like_token_redaction_removes_original_token() {
    // Synthetic JWT (jwt.io example payload) fed to the redactor under test — not a live credential.
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"; // gitleaks:allow
    let report = redact_text(&format!("jwt={token}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::JwtToken);
    assert!(report.redacted_text.contains("[REDACTED:jwt_token]"));
    assert!(!report.redacted_text.contains(token));
}

#[test]
fn pem_private_key_redaction_removes_multiline_block() {
    // Truncated, non-functional PEM block fed to the redactor under test — not a live key.
    let key = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC\nAQ8AMIIBCgKCAQEAu\n-----END PRIVATE KEY-----"; // gitleaks:allow
    let report = redact_text(&format!("loaded\n{key}\ndone"));

    assert_eq!(report.redactions[0].kind, RedactionKind::PemPrivateKey);
    assert!(report.redacted_text.contains("[REDACTED:pem_private_key]"));
    assert!(!report.redacted_text.contains("MIIEvAIBADAN"));
    assert!(!report.redacted_text.contains(key));
}

#[test]
fn basic_auth_url_redaction_removes_userinfo_but_keeps_url_shape() {
    let url = "https://user:pass@example.com/path?x=1";
    let report = redact_text(&format!("fetch {url}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::BasicAuthUrl);
    assert!(report
        .redacted_text
        .contains("https://[REDACTED:basic_auth]@example.com/path?x=1"));
    assert!(!report.redacted_text.contains("user:pass"));
    assert!(!report.redacted_text.contains("pass"));
}

#[test]
fn aws_secret_access_key_redaction_removes_key_value_secret() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let report = redact_text(&format!("AWS_SECRET_ACCESS_KEY={secret}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::AwsSecretAccessKey);
    assert_eq!(
        report.redacted_text,
        "AWS_SECRET_ACCESS_KEY=[REDACTED:aws_secret_access_key]"
    );
    assert!(!report.redacted_text.contains(secret));
}

#[test]
fn aws_secret_access_key_value_only_redaction_removes_standalone_secret() {
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let report = redact_text(&format!("observed {secret}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::AwsSecretAccessKey);
    assert!(report
        .redacted_text
        .contains("[REDACTED:aws_secret_access_key]"));
    assert!(!report.redacted_text.contains(secret));
}

#[test]
fn slack_token_redaction_covers_supported_prefixes() {
    for prefix in ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"] {
        let token = format!("{prefix}1234567890-abcdefghij-klmnopqrst");
        let report = redact_text(&format!("slack {token}"));

        assert_eq!(report.redactions[0].kind, RedactionKind::SlackToken);
        assert!(report.redacted_text.contains("[REDACTED:slack_token]"));
        assert!(!report.redacted_text.contains(&token));
    }
}

#[test]
fn google_api_key_redaction_removes_original_key() {
    // Placeholder key (literal "EXAMPLE" in the value) fed to the redactor under test — not a live key.
    let key = "AIzaSyEXAMPLE_EXAMPLE_EXAMPLE_EXAMPLE00"; // gitleaks:allow
    let report = redact_text(&format!("google_api_key={key}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::GoogleApiKey);
    assert!(report.redacted_text.contains("[REDACTED:google_api_key]"));
    assert!(!report.redacted_text.contains(key));
}

#[test]
fn stripe_secret_key_redaction_removes_live_and_test_keys() {
    // Assemble the key at runtime so the literal `sk_live_...`/`sk_test_...`
    // form never appears contiguously in source. GitHub secret-scanning flags
    // the Stripe prefix + 16+ alphanumerics regardless of the (synthetic) body,
    // so a contiguous literal blocks the push. The redactor keys off the
    // prefix, so detection coverage is unchanged.
    let body = "EXAMPLEEXAMPLEEXAMPLEEXAMPLE00";
    for env in ["live", "test"] {
        let key = format!("sk_{env}_{body}");
        let report = redact_text(&format!("stripe {key}"));

        assert_eq!(report.redactions[0].kind, RedactionKind::StripeSecretKey);
        assert!(report
            .redacted_text
            .contains("[REDACTED:stripe_secret_key]"));
        assert!(!report.redacted_text.contains(&key));
    }
}

#[test]
fn generic_api_key_redaction_removes_value() {
    let value = "supersecretvalue";
    let report = redact_text(&format!("api_key={value}"));

    assert_eq!(report.redactions[0].kind, RedactionKind::GenericSecret);
    assert_eq!(report.redacted_text, "api_key=[REDACTED:generic_secret]");
    assert!(!report.redacted_text.contains(value));
}

#[test]
fn generic_password_redaction_keeps_ampersands_inside_value() {
    let value = "p@ss&word!";
    let report = redact_text(&format!("password={value} next=visible"));

    assert_eq!(report.redactions[0].kind, RedactionKind::GenericSecret);
    assert_eq!(
        report.redacted_text,
        "password=[REDACTED:generic_secret] next=visible"
    );
    assert!(!report.redacted_text.contains(value));
    assert!(!report.redacted_text.contains("word!"));
}

#[test]
fn generic_secret_redaction_stops_at_allowed_delimiters() {
    for (input, expected) in [
        (
            "password=secret, keep",
            "password=[REDACTED:generic_secret], keep",
        ),
        (
            "password=secret} keep",
            "password=[REDACTED:generic_secret]} keep",
        ),
        (
            "password=secret] keep",
            "password=[REDACTED:generic_secret]] keep",
        ),
        (
            "password=secret; keep",
            "password=[REDACTED:generic_secret]; keep",
        ),
    ] {
        let report = redact_text(input);

        assert_eq!(report.redacted_text, expected);
    }
}

#[test]
fn json_style_key_value_text_redaction_removes_values() {
    let password_report = redact_text(r#""password":"hunter2""#);
    let aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let aws_report = redact_text(&format!("aws_secret_access_key: {aws_secret}"));

    assert_eq!(
        password_report.redacted_text,
        r#""password":"[REDACTED:generic_secret]""#
    );
    assert!(!password_report.redacted_text.contains("hunter2"));
    assert_eq!(
        aws_report.redactions[0].kind,
        RedactionKind::AwsSecretAccessKey
    );
    assert_eq!(
        aws_report.redacted_text,
        "aws_secret_access_key: [REDACTED:aws_secret_access_key]"
    );
    assert!(!aws_report.redacted_text.contains(aws_secret));
}

#[test]
fn negative_redaction_inputs_remain_unchanged() {
    for input in [
        "ordinary text without credentials",
        "https://example.com/path?query=value",
        "tokenize this paragraph for the secretary",
    ] {
        let report = redact_text(input);

        assert!(report.redactions.is_empty());
        assert_eq!(report.redacted_text, input);
    }
}

#[test]
fn runtime_event_argument_redaction_marks_event_redacted() {
    let secret = "sk-EXAMPLEEXAMPLEEXAMPLEEXAMPLE00";
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("fetch_secret".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({
            "nested": {
                "key": secret,
                "safe": "visible"
            }
        }),
        redacted: false,
    };

    let (redacted_event, redactions) = redact_runtime_event(event);

    assert!(redacted_event.redacted);
    assert_eq!(redactions.len(), 1);
    assert!(!redacted_event.arguments.to_string().contains(secret));
    assert!(redacted_event
        .arguments
        .to_string()
        .contains("[REDACTED:openai_api_key]"));
}

#[test]
fn runtime_event_arguments_redact_aws_secret_access_key_by_json_key() {
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("safe_tool".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({
            "aws_secret_access_key": secret,
            "safe": "visible"
        }),
        redacted: false,
    };

    let (redacted_event, redactions) = redact_runtime_event(event);
    let serialized_event = serde_json::to_string(&redacted_event).unwrap();
    let serialized_redactions = serde_json::to_string(&redactions).unwrap();

    assert!(redacted_event.redacted);
    assert!(redactions
        .iter()
        .any(|redaction| redaction.kind == RedactionKind::AwsSecretAccessKey));
    assert!(!serialized_event.contains(secret));
    assert!(!serialized_redactions.contains(secret));
    assert!(serialized_event.contains("[REDACTED:aws_secret_access_key]"));
    assert!(redacted_event.arguments.to_string().contains("visible"));
}

#[test]
fn runtime_event_arguments_redact_password_by_json_key() {
    let password = "hunter2supersecretvalue";
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("safe_tool".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({
            "password": password,
            "safe": "visible"
        }),
        redacted: false,
    };

    let (redacted_event, redactions) = redact_runtime_event(event);
    let serialized_event = serde_json::to_string(&redacted_event).unwrap();
    let serialized_redactions = serde_json::to_string(&redactions).unwrap();

    assert!(redacted_event.redacted);
    assert!(redactions
        .iter()
        .any(|redaction| redaction.kind == RedactionKind::GenericSecret));
    assert!(!serialized_event.contains(password));
    assert!(!serialized_redactions.contains(password));
    assert!(serialized_event.contains("[REDACTED:generic_secret]"));
    assert!(redacted_event.arguments.to_string().contains("visible"));
}

#[test]
fn runtime_event_arguments_redact_nested_values_under_secret_like_keys() {
    let direct = "hunter2supersecretvalue";
    let array_value = "nested-array-secret";
    let object_value = "nested-object-secret";
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("safe_tool".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({
            "credentials": {
                "direct": direct,
                "list": [
                    array_value,
                    {
                        "inside": object_value
                    }
                ]
            },
            "safe": "visible"
        }),
        redacted: false,
    };

    let (redacted_event, redactions) = redact_runtime_event(event);
    let serialized_event = serde_json::to_string(&redacted_event).unwrap();

    assert!(redacted_event.redacted);
    assert_eq!(redactions.len(), 3);
    assert!(!serialized_event.contains(direct));
    assert!(!serialized_event.contains(array_value));
    assert!(!serialized_event.contains(object_value));
    assert!(serialized_event.contains("[REDACTED:generic_secret]"));
    assert!(redacted_event.arguments.to_string().contains("visible"));
}

#[test]
fn runtime_event_arguments_do_not_redact_benign_secret_like_substrings_in_keys() {
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("safe_tool".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({
            "secretary": "schedule meeting",
            "tokenize": "split ordinary prose",
            "keynote": "conference talk",
            "monkey": "banana"
        }),
        redacted: false,
    };

    let (redacted_event, redactions) = redact_runtime_event(event);

    assert!(!redacted_event.redacted);
    assert!(redactions.is_empty());
    assert_eq!(redacted_event.arguments["secretary"], "schedule meeting");
    assert_eq!(redacted_event.arguments["tokenize"], "split ordinary prose");
    assert_eq!(redacted_event.arguments["keynote"], "conference talk");
    assert_eq!(redacted_event.arguments["monkey"], "banana");
}

#[test]
fn runtime_event_arguments_redact_value_only_aws_secret_in_json_string() {
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("safe_tool".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: json!({
            "ordinary": secret
        }),
        redacted: false,
    };

    let (redacted_event, redactions) = redact_runtime_event(event);
    let serialized_event = serde_json::to_string(&redacted_event).unwrap();
    let serialized_redactions = serde_json::to_string(&redactions).unwrap();

    assert!(redacted_event.redacted);
    assert_eq!(redactions[0].kind, RedactionKind::AwsSecretAccessKey);
    assert!(!serialized_event.contains(secret));
    assert!(!serialized_redactions.contains(secret));
    assert!(serialized_event.contains("[REDACTED:aws_secret_access_key]"));
}

#[test]
fn runtime_event_arguments_redact_does_not_overflow_on_deeply_nested_json() {
    // Build a deeply nested arguments payload programmatically. This bypasses
    // serde_json::from_str's 128-level recursion cap (an attacker can reach
    // redact_runtime_event via from_reader/custom Deserializer/programmatic
    // construction), so the redactor must bound its own recursion or a
    // guard-page stack overflow aborts the process — a fail-open for the guard.
    // 512 levels exceeds MAX_JSON_REDACTION_DEPTH (256) so the depth-cap path
    // (redact_overflowed_subtree) is exercised, while staying shallow enough
    // that building/dropping the serde_json::Value tree — both of which recurse
    // in serde itself — does not stack-overflow and confound the test.
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let mut nested = json!({ "aws_secret_access_key": secret });
    for _ in 0..512 {
        nested = json!({ "nested": nested });
    }

    let event = RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some("safe_tool".to_string()),
        command: None,
        url: None,
        path: None,
        arguments: nested,
        redacted: false,
    };

    // Must not stack-overflow, and the secret at the bottom must be redacted
    // (fail closed) rather than leaked or crashing. Walk the tree iteratively
    // to inspect the leaf without recursively serializing 50k levels (which
    // would itself confound the test by recursing in serde).
    let (redacted_event, _redactions) = redact_runtime_event(event);
    assert!(redacted_event.redacted);

    let mut node = &redacted_event.arguments;
    while let Some(inner) = node.get("nested") {
        node = inner;
    }
    let leaf = node
        .get("aws_secret_access_key")
        .and_then(|v| v.as_str())
        .expect("leaf secret value present");
    assert_ne!(leaf, secret, "deeply nested secret must be redacted");
    assert_eq!(leaf, "[REDACTED:aws_secret_access_key]");
}

#[test]
fn redaction_ranges_do_not_include_raw_secret_text() {
    let key = "sk-EXAMPLEEXAMPLEEXAMPLEEXAMPLE00";
    let report = redact_text(&format!("observed {key}"));
    let serialized_redactions = serde_json::to_string(&report.redactions).unwrap();

    assert!(!serialized_redactions.contains(key));
    assert!(serialized_redactions.contains("open_ai_api_key"));
    assert!(report.redactions[0].start < report.redactions[0].end);
}

fn event_with_arguments(arguments: serde_json::Value) -> RuntimeEvent {
    RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Stdin,
        action: RuntimeAction::ToolCall,
        tool_name: None,
        command: None,
        url: None,
        path: None,
        arguments,
        redacted: false,
    }
}

#[test]
fn secret_bearing_keys_authorization_cookie_bearer_session_are_redacted() {
    for key in ["authorization", "cookie", "bearer", "session", "sessionId"] {
        let event = event_with_arguments(json!({ key: "abc123rawvalue_no_vendor_match" }));
        let (redacted, redactions) = redact_runtime_event(event);
        let serialized = serde_json::to_string(&redacted.arguments).unwrap();

        assert!(
            !serialized.contains("abc123rawvalue_no_vendor_match"),
            "key {key} should be redacted, got {serialized}"
        );
        assert!(!redactions.is_empty(), "key {key} produced no redaction");
    }
}

#[test]
fn numeric_value_under_secret_key_is_redacted() {
    let event = event_with_arguments(json!({ "password": 1234567890123456_i64 }));
    let (redacted, redactions) = redact_runtime_event(event);
    let serialized = serde_json::to_string(&redacted.arguments).unwrap();

    assert!(
        !serialized.contains("1234567890123456"),
        "numeric secret leaked: {serialized}"
    );
    assert!(!redactions.is_empty());
    assert!(redacted.redacted);
}

#[test]
fn attacker_set_redacted_flag_is_recomputed_not_trusted() {
    // Caller claims redacted:true but the value is a real secret the redactor
    // catches: the flag stays true AND the secret is scrubbed.
    let mut event = event_with_arguments(json!({ "data": "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE00" }));
    event.redacted = true;
    let (redacted, _redactions) = redact_runtime_event(event);
    assert!(redacted.redacted);
    assert!(!serde_json::to_string(&redacted.arguments)
        .unwrap()
        .contains("ghp_EXAMPLE"));

    // Caller claims redacted:true but there is nothing to redact: the flag is
    // reset to false rather than laundered.
    let mut benign = event_with_arguments(json!({ "note": "just a normal value" }));
    benign.redacted = true;
    let (redacted_benign, redactions) = redact_runtime_event(benign);
    assert!(redactions.is_empty());
    assert!(
        !redacted_benign.redacted,
        "redacted flag must be reset to false"
    );
}

#[test]
fn benign_dotted_strings_are_not_redacted_as_jwt() {
    for benign in [
        "longsegmentaaaa.longsegmentbbbb.longsegmentcccc",
        "com.example.module.something-else-here.final",
    ] {
        let report = redact_text(benign);
        assert_eq!(
            report.redacted_text, benign,
            "benign dotted string was wrongly redacted: {benign}"
        );
    }
}

#[test]
fn real_jwt_is_still_redacted() {
    // Synthetic JWT (jwt.io example payload) fed to the redactor under test — not a live credential.
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"; // gitleaks:allow
    let report = redact_text(&format!("token {jwt}"));
    assert_eq!(report.redactions[0].kind, RedactionKind::JwtToken);
    assert!(!report.redacted_text.contains(jwt));
}
