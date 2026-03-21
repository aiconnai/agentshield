use crate::ir::{ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-012: No Lockfile
///
/// Flags when dependencies are declared but no lockfile is present.
/// Without a lockfile, installs are non-reproducible and vulnerable
/// to dependency confusion attacks.
pub struct NoLockfileDetector;

impl Detector for NoLockfileDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-012".into(),
            name: "No Lockfile".into(),
            description: "Dependencies declared but no lockfile present".into(),
            default_severity: Severity::Low,
            attack_category: AttackCategory::SupplyChain,
            cwe_id: None,
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        if target.dependencies.dependencies.is_empty() {
            return findings; // No deps declared — nothing to lock
        }

        if target.dependencies.lockfile.is_none() {
            let dep_count = target.dependencies.dependencies.len();
            let registries: Vec<_> = target
                .dependencies
                .dependencies
                .iter()
                .map(|d| d.registry.as_str())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            // Use the first dependency's manifest file as the location for this
            // finding, so it appears in SARIF output and GitHub Code Scanning.
            let manifest_location = target
                .dependencies
                .dependencies
                .first()
                .and_then(|d| d.location.as_ref())
                .map(|loc| SourceLocation {
                    file: loc.file.clone(),
                    line: 1,
                    column: 0,
                    end_line: None,
                    end_column: None,
                });

            findings.push(Finding {
                rule_id: "SHIELD-012".into(),
                rule_name: "No Lockfile".into(),
                severity: Severity::Low,
                confidence: Confidence::High,
                attack_category: AttackCategory::SupplyChain,
                message: format!(
                    "{} dependencies declared ({}) but no lockfile found",
                    dep_count,
                    registries.join(", ")
                ),
                location: manifest_location.clone(),
                evidence: vec![Evidence {
                    description: "Expected lockfile (Pipfile.lock, poetry.lock, uv.lock, \
                         package-lock.json, yarn.lock, pnpm-lock.yaml) but none found"
                        .to_string(),
                    location: manifest_location,
                    snippet: None,
                }],
                taint_path: None,
                remediation: Some(
                    "Add a lockfile to pin exact dependency versions. \
                     Use `pip freeze > requirements.txt` with hashes, \
                     `poetry lock`, `uv lock`, or `npm install` to generate one."
                        .into(),
                ),
                cwe_id: None,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::dependency_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    #[test]
    fn flags_deps_without_lockfile() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: DependencySurface {
                dependencies: vec![Dependency {
                    name: "requests".into(),
                    version_constraint: Some("2.31.0".into()),
                    locked_version: None,
                    locked_hash: None,
                    registry: "pypi".into(),
                    is_dev: false,
                    location: None,
                }],
                lockfile: None,
                issues: vec![],
            },
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = NoLockfileDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-012");
    }

    #[test]
    fn passes_with_lockfile() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: DependencySurface {
                dependencies: vec![Dependency {
                    name: "requests".into(),
                    version_constraint: Some("2.31.0".into()),
                    locked_version: None,
                    locked_hash: None,
                    registry: "pypi".into(),
                    is_dev: false,
                    location: None,
                }],
                lockfile: Some(LockfileInfo {
                    path: PathBuf::from("poetry.lock"),
                    format: LockfileFormat::PoetryLock,
                    all_pinned: true,
                    all_hashed: false,
                }),
                issues: vec![],
            },
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = NoLockfileDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn passes_no_deps() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = NoLockfileDetector.run(&target);
        assert!(findings.is_empty());
    }
}
