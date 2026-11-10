//! Decide which policy files a scan may apply.
//!
//! A scanned directory can ship its own `.agentshield.toml` and
//! `.agentshield/rules`. When the directory is untrusted third-party code (a
//! downloaded MCP server, `node_modules/<pkg>`, ...) that policy could silence
//! every finding through suppressions, `ignore_rules`, `fail_on`, scan
//! excludes or `ignore_tests`. Target policy is therefore applied only when:
//!
//! - the canonicalized scan root equals the canonicalized current working
//!   directory (scanning your own repository from its root), or
//! - the caller opts in explicitly (`--trust-target-config`).
//!
//! Explicitly supplied config and rules paths are always honoured.

use std::path::{Path, PathBuf};

use super::Config;
use crate::error::Result;

/// File name of the per-project configuration.
pub const TARGET_CONFIG_FILE: &str = ".agentshield.toml";

/// CLI flag that opts in to applying the scan target's own policy files.
pub const TRUST_TARGET_CONFIG_FLAG: &str = "--trust-target-config";

/// Default config path inside a scan root.
pub fn target_config_path(scan_root: &Path) -> PathBuf {
    scan_root.join(TARGET_CONFIG_FILE)
}

/// Default custom-rules directory inside a scan root.
pub fn target_rules_dir(scan_root: &Path) -> PathBuf {
    scan_root.join(".agentshield").join("rules")
}

/// True when the canonicalized scan root is the canonicalized current working
/// directory. Any canonicalization failure is treated as "not the cwd".
pub fn scan_root_is_current_dir(scan_root: &Path) -> bool {
    let Ok(cwd) = std::env::current_dir().and_then(|dir| dir.canonicalize()) else {
        return false;
    };
    scan_root
        .canonicalize()
        .is_ok_and(|canonical_root| canonical_root == cwd)
}

/// Caller-supplied inputs that decide where scan policy comes from.
#[derive(Debug, Clone, Copy)]
pub struct PolicySources<'a> {
    /// Explicit config file (`--config`); always honoured.
    pub explicit_config: Option<&'a Path>,
    /// Explicit custom rules directory (`--rules-dir`); always honoured.
    pub explicit_rules_dir: Option<&'a Path>,
    /// Explicit opt-in to the scan target's own policy files.
    pub trust_target_config: bool,
}

/// The policy a scan will apply, plus any target policy files it ignored.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Effective configuration (built-in defaults when no config applies).
    pub config: Config,
    /// Config file that was loaded, if any.
    pub config_path: Option<PathBuf>,
    /// Custom rules directory to load, if any.
    pub rules_dir: Option<PathBuf>,
    /// Whether the target's own policy files were trusted.
    pub target_trusted: bool,
    /// Target policy files that exist on disk but were not applied.
    pub ignored_target_paths: Vec<PathBuf>,
}

impl ResolvedPolicy {
    /// Resolve the policy for scanning `scan_root`.
    pub fn resolve(scan_root: &Path, sources: PolicySources<'_>) -> Result<Self> {
        let target_trusted = sources.trust_target_config || scan_root_is_current_dir(scan_root);
        let mut ignored_target_paths = Vec::new();

        let config_path = match sources.explicit_config {
            Some(path) => Some(path.to_path_buf()),
            None => {
                let default_path = target_config_path(scan_root);
                if target_trusted {
                    Some(default_path)
                } else {
                    if default_path.exists() {
                        ignored_target_paths.push(default_path);
                    }
                    None
                }
            }
        };
        let config = match &config_path {
            Some(path) => Config::load(path)?,
            None => Config::default(),
        };

        let rules_dir = if let Some(dir) = sources.explicit_rules_dir {
            Some(dir.to_path_buf())
        } else if let Some(dir) = &config.rules.custom_dir {
            // Only reachable for an explicit config or a trusted target config.
            Some(if dir.is_absolute() {
                dir.clone()
            } else {
                scan_root.join(dir)
            })
        } else {
            let default_dir = target_rules_dir(scan_root);
            match (default_dir.is_dir(), target_trusted) {
                (true, true) => Some(default_dir),
                (true, false) => {
                    ignored_target_paths.push(default_dir);
                    None
                }
                (false, _) => None,
            }
        };

        Ok(Self {
            config,
            config_path,
            rules_dir,
            target_trusted,
            ignored_target_paths,
        })
    }

    /// One-line human notice describing ignored target policy, if any.
    ///
    /// Intended for stderr only; it must never be written into JSON, SARIF or
    /// HTML report output.
    pub fn ignored_notice(&self) -> Option<String> {
        if self.ignored_target_paths.is_empty() {
            return None;
        }
        let paths = self
            .ignored_target_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!(
            "Notice: ignoring policy shipped by the scan target ({paths}) because the scan \
             root is not the current directory; pass {TRUST_TARGET_CONFIG_FLAG} to apply it, \
             or choose policy explicitly with --config / --rules-dir."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn untrusted() -> PolicySources<'static> {
        PolicySources {
            explicit_config: None,
            explicit_rules_dir: None,
            trust_target_config: false,
        }
    }

    #[test]
    fn untrusted_target_without_policy_files_has_no_notice() {
        let tmp = TempDir::new().unwrap();
        let resolved = ResolvedPolicy::resolve(tmp.path(), untrusted()).unwrap();
        assert!(!resolved.target_trusted);
        assert!(resolved.config_path.is_none());
        assert!(resolved.rules_dir.is_none());
        assert!(resolved.ignored_notice().is_none());
    }

    #[test]
    fn untrusted_target_policy_files_are_ignored_and_named() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(TARGET_CONFIG_FILE), "[policy]\n").unwrap();
        std::fs::create_dir_all(target_rules_dir(tmp.path())).unwrap();

        let resolved = ResolvedPolicy::resolve(tmp.path(), untrusted()).unwrap();

        assert!(resolved.config_path.is_none());
        assert!(resolved.rules_dir.is_none());
        let notice = resolved.ignored_notice().expect("notice");
        assert!(notice.contains(TARGET_CONFIG_FILE));
        assert!(notice.contains("rules"));
        assert!(notice.contains(TRUST_TARGET_CONFIG_FLAG));
        assert!(!notice.contains('\n'));
    }

    #[test]
    fn trusted_target_policy_files_are_applied() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(TARGET_CONFIG_FILE), "[policy]\n").unwrap();
        std::fs::create_dir_all(target_rules_dir(tmp.path())).unwrap();

        let resolved = ResolvedPolicy::resolve(
            tmp.path(),
            PolicySources {
                trust_target_config: true,
                ..untrusted()
            },
        )
        .unwrap();

        assert_eq!(
            resolved.config_path,
            Some(tmp.path().join(TARGET_CONFIG_FILE))
        );
        assert_eq!(resolved.rules_dir, Some(target_rules_dir(tmp.path())));
        assert!(resolved.ignored_notice().is_none());
    }

    #[test]
    fn explicit_paths_win_without_trust() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("custom.toml");
        std::fs::write(&config, "[policy]\nfail_on = \"critical\"\n").unwrap();
        let rules = tmp.path().join("rules");

        let resolved = ResolvedPolicy::resolve(
            tmp.path(),
            PolicySources {
                explicit_config: Some(&config),
                explicit_rules_dir: Some(&rules),
                trust_target_config: false,
            },
        )
        .unwrap();

        assert_eq!(resolved.config_path.as_deref(), Some(config.as_path()));
        assert_eq!(resolved.rules_dir.as_deref(), Some(rules.as_path()));
        assert_eq!(
            resolved.config.policy.fail_on,
            crate::rules::Severity::Critical
        );
    }

    #[test]
    fn current_dir_counts_as_trusted() {
        let cwd = std::env::current_dir().unwrap();
        assert!(scan_root_is_current_dir(&cwd));
        assert!(scan_root_is_current_dir(Path::new(".")));
        assert!(!scan_root_is_current_dir(Path::new("tests")));
        assert!(!scan_root_is_current_dir(Path::new("does/not/exist")));
    }
}
