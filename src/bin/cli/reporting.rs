use std::path::{Path, PathBuf};

use agentshield::ScanOptions;
use agentshield::config::Config;
use agentshield::output::OutputFormat;

pub(super) fn cmd_suppress(
    fingerprint: String,
    reason: String,
    expires: Option<String>,
    config: Option<PathBuf>,
) -> Result<i32, agentshield::error::ShieldError> {
    if reason.trim().is_empty() {
        eprintln!("Error: --reason must be a non-empty string");
        return Ok(2);
    }

    if let Some(ref date_str) = expires {
        if chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d").is_err() {
            eprintln!(
                "Error: --expires '{}' is not a valid date (expected YYYY-MM-DD)",
                date_str
            );
            return Ok(2);
        }
    }

    let config_path = config.unwrap_or_else(|| PathBuf::from(".agentshield.toml"));
    let cfg = Config::load(&config_path)?;
    if cfg
        .policy
        .suppressions
        .iter()
        .any(|s| s.fingerprint == fingerprint)
    {
        println!("Fingerprint {fingerprint} already exists in suppressions; no update needed.");
        return Ok(0);
    }

    let workspace = config_workspace(&config_path);
    let options = ScanOptions {
        config_path: Some(config_path.clone()),
        format: OutputFormat::Console,
        fail_on_override: None,
        ignore_tests: false,
        custom_rules_dir: None,
    };
    let report = agentshield::scan(&workspace, &options)?;
    let matches = report
        .findings
        .into_iter()
        .any(|finding| finding.fingerprint(&report.scan_root) == fingerprint);
    if !matches {
        eprintln!("Error: fingerprint '{fingerprint}' was not found in scan results.");
        return Ok(2);
    }

    let toml_content = if config_path.exists() {
        std::fs::read_to_string(&config_path).map_err(|e| {
            agentshield::error::ShieldError::Config(format!("Failed to read config file: {}", e))
        })?
    } else {
        "".to_string()
    };

    let mut doc = toml_content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| {
            agentshield::error::ShieldError::Config(format!("Failed to parse config file: {}", e))
        })?;

    // Ensure "policy" table exists
    if !doc.contains_key("policy") {
        doc["policy"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    let policy = doc["policy"].as_table_mut().ok_or_else(|| {
        agentshield::error::ShieldError::Config("Expected 'policy' to be a table".into())
    })?;

    // Ensure "suppressions" array of tables exists under "policy"
    if !policy.contains_key("suppressions") {
        policy["suppressions"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let suppressions = policy["suppressions"]
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            agentshield::error::ShieldError::Config(
                "Expected 'policy.suppressions' to be an array of tables".into(),
            )
        })?;

    let mut new_entry = toml_edit::Table::new();
    new_entry.insert("fingerprint", toml_edit::value(fingerprint.clone()));
    new_entry.insert("reason", toml_edit::value(reason.clone()));
    if let Some(ref exp) = expires {
        new_entry.insert("expires", toml_edit::value(exp.clone()));
    }
    let created_at = chrono::Utc::now().format("%Y-%m-%d").to_string();
    new_entry.insert("created_at", toml_edit::value(created_at));

    suppressions.push(new_entry);

    let new_toml = doc.to_string();
    std::fs::write(&config_path, new_toml)?;

    let expires_display = expires
        .as_deref()
        .map(|d| format!(" (expires: {})", d))
        .unwrap_or_default();
    println!(
        "Suppressed finding {} : {}{}",
        &fingerprint[..fingerprint.len().min(12)],
        reason,
        expires_display
    );

    Ok(0)
}

fn config_workspace(config_path: &std::path::Path) -> PathBuf {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(super) fn cmd_list_suppressions(
    config: Option<PathBuf>,
) -> Result<i32, agentshield::error::ShieldError> {
    let config_path = config.unwrap_or_else(|| PathBuf::from(".agentshield.toml"));
    let cfg = Config::load(&config_path)?;
    let suppressions = &cfg.policy.suppressions;

    if suppressions.is_empty() {
        println!("No suppressions configured.");
        return Ok(0);
    }

    println!(
        "{:<16}  {:<40}  {:<10}  STATUS",
        "FINGERPRINT", "REASON", "EXPIRES"
    );
    println!("{}", "-".repeat(80));

    for s in suppressions {
        let fp_short = &s.fingerprint[..s.fingerprint.len().min(16)];
        let reason_truncated = if s.reason.len() > 40 {
            format!("{}...", &s.reason[..37])
        } else {
            s.reason.clone()
        };
        let expires_display = s.expires.as_deref().unwrap_or("-");
        let status = if s.is_expired() { "expired" } else { "active" };

        println!(
            "{:<16}  {:<40}  {:<10}  {}",
            fp_short, reason_truncated, expires_display, status
        );
    }

    Ok(0)
}

pub(super) fn cmd_certify(
    path: PathBuf,
    sign_key: Option<PathBuf>,
    output: Option<PathBuf>,
    config: Option<PathBuf>,
    ignore_tests: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    use agentshield::certify::envelope::{DsseEnvelope, build_attestation};

    let options = ScanOptions {
        config_path: config.clone(),
        format: OutputFormat::Console,
        fail_on_override: None,
        ignore_tests,
        custom_rules_dir: None,
    };

    let report = agentshield::scan(&path, &options)?;
    let config_path = config.unwrap_or_else(|| path.join(".agentshield.toml"));
    let cfg = Config::load(&config_path)?;
    let suppressions = &cfg.policy.suppressions;

    let payload = build_attestation(
        &report.scan_root,
        &report.findings,
        suppressions,
        &report.targets,
        None,
    );

    let mut envelope = DsseEnvelope::new(&payload)?;

    if let Some(key_path) = sign_key {
        let key_bytes = read_and_parse_signing_key(&key_path)?;
        envelope.sign(&key_bytes)?;
        let display_name = if key_path.as_os_str() == "-" {
            "stdin".to_string()
        } else {
            key_path.display().to_string()
        };
        eprintln!("Signed attestation with key: {}", display_name);
    }

    let json = serde_json::to_string_pretty(&envelope)?;

    match output {
        Some(out) => {
            std::fs::write(&out, &json)?;
            eprintln!(
                "Wrote attestation to: {} ({} findings)",
                out.display(),
                report.findings.len()
            );
        }
        None => print!("{}", json),
    }

    Ok(0)
}

/// Parse raw key bytes into an Ed25519 32-byte signing key.
///
/// Implements defensive transport normalization (Standard v5 R-5.1.2):
/// - Accepts exact 32-byte raw binary keys as-is (never trimmed).
/// - Safely strips single terminal `\n` or `\r\n` delimiters appended by CLI secret providers (Infisical, Vault).
/// - Decodes 64-character hexadecimal strings into 32-byte keys.
/// - Fails closed on malformed hex, invalid lengths, or unexpected control characters.
fn parse_signing_key(bytes: &[u8]) -> Result<[u8; 32], agentshield::error::ShieldError> {
    // Exact 32-byte raw binary key: accept as-is (never trim even if byte 31 is 0x0A)
    if let Ok(key) = bytes.try_into() {
        return Ok(key);
    }

    // Raw binary key with single trailing terminal newline (e.g. 33 bytes ending in \n)
    if bytes.len() == 33 && bytes.ends_with(b"\n") {
        if let Ok(key) = bytes[..32].try_into() {
            return Ok(key);
        }
    }
    // Raw binary key with single trailing CRLF (34 bytes ending in \r\n)
    if bytes.len() == 34 && bytes.ends_with(b"\r\n") {
        if let Ok(key) = bytes[..32].try_into() {
            return Ok(key);
        }
    }

    // Hexadecimal string representation (64 hex characters, optionally ending with single terminal delimiter)
    let mut trimmed = bytes;
    if trimmed.ends_with(b"\r\n") {
        trimmed = &trimmed[..trimmed.len() - 2];
    } else if trimmed.ends_with(b"\n") {
        trimmed = &trimmed[..trimmed.len() - 1];
    }

    if trimmed.len() == 64 {
        let s = std::str::from_utf8(trimmed).map_err(|_| {
            agentshield::error::ShieldError::Internal(
                "Invalid Ed25519 signing key: 64-byte sequence is not valid UTF-8 hex".into(),
            )
        })?;
        let decoded = hex::decode(s).map_err(|e| {
            agentshield::error::ShieldError::Internal(format!(
                "Invalid Ed25519 signing key hex encoding: {e}"
            ))
        })?;
        return decoded.as_slice().try_into().map_err(|_| {
            agentshield::error::ShieldError::Internal(
                "Invalid decoded Ed25519 key length; expected 32 bytes".into(),
            )
        });
    }

    Err(agentshield::error::ShieldError::Internal(format!(
        "Invalid Ed25519 signing key length ({} bytes); expected 32 bytes raw binary or 64 hex characters",
        bytes.len()
    )))
}

/// Read and parse an Ed25519 signing key from standard input (`-`) or a file path.
///
/// If reading from a file path on Unix, warns if file permissions allow group or others access.
fn read_and_parse_signing_key(
    key_path: &Path,
) -> Result<[u8; 32], agentshield::error::ShieldError> {
    let (key_bytes, source_desc) = if key_path.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).map_err(|e| {
            agentshield::error::ShieldError::Internal(format!(
                "Failed to read signing key from stdin: {e}"
            ))
        })?;
        (buf, "stdin".to_string())
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(key_path) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    eprintln!(
                        "Warning: signing key file '{}' is accessible by others (mode {:04o}). Permissions should be restricted (0600 or 0400).",
                        key_path.display(),
                        mode & 0o7777
                    );
                }
            }
        }
        let bytes = std::fs::read(key_path).map_err(|e| {
            agentshield::error::ShieldError::Internal(format!(
                "Failed to read signing key '{}': {}",
                key_path.display(),
                e
            ))
        })?;
        (bytes, format!("'{}'", key_path.display()))
    };

    parse_signing_key(&key_bytes).map_err(|e| {
        agentshield::error::ShieldError::Internal(format!(
            "Failed to load signing key from {source_desc}: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::config_workspace;
    use std::path::{Path, PathBuf};

    #[test]
    fn default_config_path_scans_current_workspace() {
        assert_eq!(
            config_workspace(Path::new(".agentshield.toml")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn explicit_config_path_scans_its_parent_workspace() {
        assert_eq!(
            config_workspace(Path::new("project/.agentshield.toml")),
            PathBuf::from("project")
        );
    }

    #[test]
    fn test_parse_signing_key_raw_32_bytes() {
        let raw = [42u8; 32];
        let parsed = super::parse_signing_key(&raw).expect("valid raw key");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn test_parse_signing_key_raw_with_newline() {
        let mut with_nl = vec![42u8; 32];
        with_nl.push(b'\n');
        let parsed = super::parse_signing_key(&with_nl).expect("valid raw key with newline");
        assert_eq!(parsed, [42u8; 32]);
    }

    #[test]
    fn test_parse_signing_key_raw_with_crlf() {
        let mut with_crlf = vec![42u8; 32];
        with_crlf.extend_from_slice(b"\r\n");
        let parsed = super::parse_signing_key(&with_crlf).expect("valid raw key with crlf");
        assert_eq!(parsed, [42u8; 32]);
    }

    #[test]
    fn test_parse_signing_key_raw_ending_in_0x0a_not_trimmed() {
        let mut raw = [42u8; 32];
        raw[31] = b'\n'; // Byte 31 happens to be 0x0A
        let parsed = super::parse_signing_key(&raw).expect("valid raw key ending in newline byte");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn test_parse_signing_key_hex_64_chars() {
        let raw = [7u8; 32];
        let hex_str = hex::encode(raw);
        let parsed = super::parse_signing_key(hex_str.as_bytes()).expect("valid hex key");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn test_parse_signing_key_hex_with_terminal_newline() {
        let raw = [7u8; 32];
        let hex_str = format!("{}\n", hex::encode(raw));
        let parsed =
            super::parse_signing_key(hex_str.as_bytes()).expect("valid hex key with newline");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn test_parse_signing_key_rejects_invalid_inputs() {
        assert!(super::parse_signing_key(b"too-short").is_err());
        assert!(super::parse_signing_key(&[1u8; 35]).is_err());
        let invalid_hex = "g".repeat(64);
        assert!(super::parse_signing_key(invalid_hex.as_bytes()).is_err());
    }
}
