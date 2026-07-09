use std::path::{Component, Path};

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
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanPathFilterSummary {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScanPathFilter {
    ignore_tests: bool,
    include: Vec<CompiledPathPattern>,
    exclude: Vec<CompiledPathPattern>,
}

#[derive(Debug, Clone)]
struct CompiledPathPattern {
    raw: String,
    patterns: Vec<glob::Pattern>,
}

const PATH_PATTERN_MATCH_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

impl ScanPathFilter {
    pub fn for_ignore_tests(ignore_tests: bool) -> Self {
        Self {
            ignore_tests,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }

    pub fn from_scan_config(config: &ScanConfig, ignore_tests: bool) -> Result<Self> {
        Ok(Self {
            ignore_tests,
            include: compile_path_patterns("scan.include", &config.include)?,
            exclude: compile_path_patterns("scan.exclude", &config.exclude)?,
        })
    }

    pub const fn ignore_tests(&self) -> bool {
        self.ignore_tests
    }

    pub fn allows_path(&self, root: &Path, path: &Path) -> bool {
        let relative = relative_path(root, path);
        let included = self.include.is_empty()
            || self
                .include
                .iter()
                .any(|pattern| pattern.matches(&relative));
        let excluded = self
            .exclude
            .iter()
            .any(|pattern| pattern.matches(&relative));

        included && !excluded
    }

    pub fn summary(&self) -> ScanPathFilterSummary {
        ScanPathFilterSummary {
            include: self
                .include
                .iter()
                .map(|pattern| pattern.raw.clone())
                .collect(),
            exclude: self
                .exclude
                .iter()
                .map(|pattern| pattern.raw.clone())
                .collect(),
        }
    }
}

impl CompiledPathPattern {
    fn new(section: &str, raw: &str) -> Result<Self> {
        let normalized = normalize_config_pattern(raw);
        if normalized.is_empty() {
            return Err(ShieldError::Config(format!(
                "{section} pattern must not be empty"
            )));
        }
        let patterns = expand_config_pattern(&normalized)
            .into_iter()
            .map(|pattern| {
                glob::Pattern::new(&pattern).map_err(|err| {
                    ShieldError::Config(format!("invalid {section} pattern '{raw}': {err}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            raw: raw.to_string(),
            patterns,
        })
    }

    fn matches(&self, relative_path: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches_with(relative_path, PATH_PATTERN_MATCH_OPTIONS))
    }
}

fn compile_path_patterns(section: &str, patterns: &[String]) -> Result<Vec<CompiledPathPattern>> {
    patterns
        .iter()
        .map(|pattern| CompiledPathPattern::new(section, pattern))
        .collect()
}

fn normalize_config_pattern(pattern: &str) -> String {
    let mut normalized = pattern.trim().replace('\\', "/");
    normalized = normalized.trim_start_matches('/').to_string();
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped.to_string();
    }
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    if normalized.ends_with('/') {
        normalized.push_str("**");
    }
    normalized
}

fn expand_config_pattern(pattern: &str) -> Vec<String> {
    let mut patterns = vec![pattern.to_string()];
    if let Some(root_pattern) = pattern.strip_prefix("**/") {
        if !root_pattern.is_empty() {
            patterns.push(root_pattern.to_string());
        }
    }
    patterns
}

fn relative_path(root: &Path, path: &Path) -> String {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let relative = canonical_path
        .strip_prefix(&canonical_root)
        .or_else(|_| path.strip_prefix(root))
        .unwrap_or(path);
    let parts: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            Component::CurDir => None,
            Component::ParentDir => Some("..".to_string()),
            Component::RootDir | Component::Prefix(_) => None,
        })
        .collect();

    parts.join("/")
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
        let _ = ScanPathFilter::from_scan_config(&self.scan, self.scan.ignore_tests)?;
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
# See https://github.com/aiconnai/agentshield for documentation.

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
# Include only matching paths. Empty means include all scan-supported files.
# Use ** for recursive directories; * and ? stay within one path segment.
# include = ["src/**", "tools/**"]
# Exclude matching paths after include filtering.
# exclude = ["legacy/**", "**/generated/**", "vendor/**"]

# [runtime.proxy]
# Runtime MCP proxy guard blocking threshold: block, warn, or never.
# fail_on = "block"

# [[runtime.proxy.tool]]
# name = "calculator.add"
# fail_on = "never"
"#
    }
}
