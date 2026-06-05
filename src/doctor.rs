use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::adapter::all_adapters;
use crate::config::Config;
use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct EnabledFeatures {
    pub python: bool,
    pub typescript: bool,
    pub runtime: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub version: String,
    pub target: PathBuf,
    pub config_path: PathBuf,
    pub config_found: bool,
    pub fail_on: String,
    pub ignore_tests: bool,
    pub enabled_features: EnabledFeatures,
    pub detected_adapters: Vec<String>,
    pub available_adapters: Vec<String>,
    pub runtime_wrap_available: bool,
}

pub fn run_doctor(
    target: &Path,
    config_path: Option<PathBuf>,
    ignore_tests_override: bool,
) -> Result<DoctorReport> {
    let effective_config_path = config_path.unwrap_or_else(|| target.join(".agentshield.toml"));
    let config_found = effective_config_path.exists();
    let config = Config::load(&effective_config_path)?;
    let ignore_tests = ignore_tests_override || config.scan.ignore_tests;

    let adapters = all_adapters();
    let available_adapters = adapters
        .iter()
        .map(|adapter| adapter.framework().to_string())
        .collect();
    let detected_adapters = adapters
        .iter()
        .filter(|adapter| adapter.detect(target))
        .map(|adapter| adapter.framework().to_string())
        .collect();

    Ok(DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        target: target.to_path_buf(),
        config_path: effective_config_path,
        config_found,
        fail_on: config.policy.fail_on.to_string(),
        ignore_tests,
        enabled_features: EnabledFeatures {
            python: cfg!(feature = "python"),
            typescript: cfg!(feature = "typescript"),
            runtime: cfg!(feature = "runtime"),
        },
        detected_adapters,
        available_adapters,
        runtime_wrap_available: cfg!(feature = "runtime"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_missing_config_and_enabled_features() {
        let tmp = tempfile::TempDir::new().unwrap();

        let report = run_doctor(tmp.path(), None, false).unwrap();

        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(report.target, tmp.path());
        assert_eq!(report.config_path, tmp.path().join(".agentshield.toml"));
        assert!(!report.config_found);
        assert_eq!(report.fail_on, "high");
        assert!(!report.ignore_tests);
        assert_eq!(report.enabled_features.python, cfg!(feature = "python"));
        assert_eq!(
            report.enabled_features.typescript,
            cfg!(feature = "typescript")
        );
        assert_eq!(report.enabled_features.runtime, cfg!(feature = "runtime"));
        assert_eq!(report.runtime_wrap_available, cfg!(feature = "runtime"));
        assert!(!report.available_adapters.is_empty());
        assert!(report.detected_adapters.is_empty());
    }

    #[test]
    fn ignore_tests_cli_override_enables_effective_setting() {
        let tmp = tempfile::TempDir::new().unwrap();

        let report = run_doctor(tmp.path(), None, true).unwrap();

        assert!(report.ignore_tests);
    }
}
