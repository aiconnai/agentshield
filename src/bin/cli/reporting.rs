use std::path::PathBuf;

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
        let key_bytes = std::fs::read(&key_path).map_err(|e| {
            agentshield::error::ShieldError::Internal(format!(
                "Failed to read signing key '{}': {}",
                key_path.display(),
                e
            ))
        })?;
        envelope.sign(&key_bytes)?;
        eprintln!("Signed attestation with key: {}", key_path.display());
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
}
