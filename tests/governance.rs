use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::NaiveDate;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ExceptionsManifest {
    #[serde(default)]
    exception: Vec<ExceptionEntry>,
}

#[derive(Debug, Deserialize)]
struct ExceptionEntry {
    id: String,
    rule: String,
    owner: String,
    rationale: String,
    scope: String,
    compensating_control: String,
    record: String,
    expires: String,
}

fn validate_exceptions_toml(content: &str, today: NaiveDate) -> Result<Vec<String>, String> {
    let manifest: ExceptionsManifest =
        toml::from_str(content).map_err(|e| format!("Failed to parse TOML: {e}"))?;

    let mut seen_ids = HashSet::new();
    let mut verified = Vec::new();

    for entry in manifest.exception {
        if !entry.id.starts_with("EXC-") || entry.id.len() < 5 {
            return Err(format!(
                "Exception id '{}' is invalid: must match EXC-XXXX",
                entry.id
            ));
        }

        if !seen_ids.insert(entry.id.clone()) {
            return Err(format!("Duplicate exception id: '{}'", entry.id));
        }

        if !(entry.rule.starts_with("R-") || entry.rule.starts_with("P-")) {
            return Err(format!(
                "Exception '{}' has invalid rule '{}': must start with 'R-' or 'P-'",
                entry.id, entry.rule
            ));
        }

        if entry.owner.trim().is_empty() {
            return Err(format!("Exception '{}' owner must not be empty", entry.id));
        }
        if entry.rationale.trim().is_empty() {
            return Err(format!(
                "Exception '{}' rationale must not be empty",
                entry.id
            ));
        }
        if entry.scope.trim().is_empty() {
            return Err(format!("Exception '{}' scope must not be empty", entry.id));
        }
        if entry.compensating_control.trim().is_empty() {
            return Err(format!(
                "Exception '{}' compensating_control must not be empty",
                entry.id
            ));
        }
        if entry.record.trim().is_empty() {
            return Err(format!("Exception '{}' record must not be empty", entry.id));
        }

        let expiry = NaiveDate::parse_from_str(entry.expires.trim(), "%Y-%m-%d").map_err(|e| {
            format!(
                "Exception '{}' has invalid expires date '{}': {e}",
                entry.id, entry.expires
            )
        })?;

        if expiry < today {
            return Err(format!(
                "Exception '{}' has expired on {} (current date: {}). Waivers must fail closed.",
                entry.id, expiry, today
            ));
        }

        verified.push(entry.id);
    }

    Ok(verified)
}

#[test]
fn repository_exceptions_manifest_is_valid_and_unexpired() {
    let manifest_path = Path::new("governance/exceptions.toml");
    assert!(
        manifest_path.exists(),
        "governance/exceptions.toml must exist per standard [R-0.6]"
    );

    let content = fs::read_to_string(manifest_path).expect("read governance/exceptions.toml");
    let today = chrono::Utc::now().date_naive();
    let verified = validate_exceptions_toml(&content, today).expect("valid manifest");

    println!("Verified {} active governance exceptions", verified.len());
}

#[test]
fn validator_rejects_expired_exceptions() {
    let toml = r#"
[[exception]]
id = "EXC-0001"
rule = "R-2.1.3"
owner = "core-team"
rationale = "testing"
scope = "test-scope"
compensating_control = "testing"
record = "ISSUE-1"
expires = "2020-01-01"
"#;
    let today = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let err = validate_exceptions_toml(toml, today).unwrap_err();
    assert!(err.contains("expired"));
}

#[test]
fn validator_rejects_duplicate_exception_ids() {
    let toml = r#"
[[exception]]
id = "EXC-0001"
rule = "R-2.1.3"
owner = "core-team"
rationale = "testing 1"
scope = "test-scope"
compensating_control = "testing"
record = "ISSUE-1"
expires = "2028-01-01"

[[exception]]
id = "EXC-0001"
rule = "R-3.3.1"
owner = "core-team"
rationale = "testing 2"
scope = "test-scope"
compensating_control = "testing"
record = "ISSUE-2"
expires = "2028-01-01"
"#;
    let today = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let err = validate_exceptions_toml(toml, today).unwrap_err();
    assert!(err.contains("Duplicate exception id"));
}

#[test]
fn validator_rejects_missing_required_fields() {
    let toml = r#"
[[exception]]
id = "EXC-0001"
rule = "R-2.1.3"
owner = ""
rationale = "testing"
scope = "test-scope"
compensating_control = "testing"
record = "ISSUE-1"
expires = "2028-01-01"
"#;
    let today = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let err = validate_exceptions_toml(toml, today).unwrap_err();
    assert!(err.contains("owner must not be empty"));
}
