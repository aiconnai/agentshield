use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShieldError};
use crate::rules::policy::Policy;

/// Top-level configuration from `.agentshield.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

/// `[scan]` section of the config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Skip test files when true.
    #[serde(default)]
    pub ignore_tests: bool,
}

/// `[runtime]` section of the config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub proxy: RuntimeProxyConfig,
}

/// Blocking threshold for the MCP proxy guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyFailOn {
    /// Block only `block` verdicts (default).
    #[default]
    Block,
    /// Block `warn` and `block` verdicts.
    Warn,
    /// Never block; still evaluated and audited.
    Never,
}

/// Per-tool proxy policy override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyToolOverride {
    pub name: String,
    #[serde(default)]
    pub fail_on: ProxyFailOn,
}

/// `[runtime.proxy]` section: MCP proxy guard policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeProxyConfig {
    #[serde(default)]
    pub fail_on: ProxyFailOn,
    #[serde(default, rename = "tool")]
    pub tool_overrides: Vec<ProxyToolOverride>,
}

impl Config {
    /// Load config from a TOML file. Returns default if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the loaded configuration.
    ///
    /// Called automatically by `load()`. Exposed for testing via
    /// `validate_for_test()`.
    fn validate(&self) -> Result<()> {
        for s in &self.policy.suppressions {
            if s.reason.trim().is_empty() {
                return Err(ShieldError::Config(format!(
                    "Suppression for fingerprint '{}' must have a non-empty reason",
                    s.fingerprint,
                )));
            }
        }
        Ok(())
    }

    /// Validate without loading from file. Used by tests.
    #[cfg(test)]
    pub fn validate_for_test(&self) -> Result<()> {
        self.validate()
    }

    /// Generate a starter config file.
    pub fn starter_toml() -> &'static str {
        r#"# AgentShield configuration
# See https://github.com/limaronaldo/agentshield for documentation.

[policy]
# Minimum severity to fail the scan (info, low, medium, high, critical).
fail_on = "high"

# Rule IDs to ignore entirely.
# ignore_rules = ["SHIELD-008"]

# Per-rule severity overrides.
# [policy.overrides]
# "SHIELD-012" = "info"

# Suppress specific findings by fingerprint.
# Run `agentshield scan . --format json` to see fingerprints.
# [[policy.suppressions]]
# fingerprint = "abc123..."
# reason = "False positive: input is validated by middleware"
# expires = "2026-06-01"

# [scan]
# Skip test files (test/, tests/, __tests__/, *.test.ts, *.spec.ts, etc.).
# ignore_tests = false
"#
    }
}
