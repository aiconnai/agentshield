use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-009: Unpinned Dependencies
///
/// Flags dependencies without exact version pinning (==). Using >=, ~=, ^,
/// or no version constraint allows untested code to be pulled in at install
/// time, enabling supply chain attacks.
pub struct UnpinnedDepsDetector;

impl Detector for UnpinnedDepsDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-009".into(),
            name: "Unpinned Dependencies".into(),
            description: "Dependencies without exact version pinning".into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::SupplyChain,
            cwe_id: Some("CWE-1104".into()),
            owasp_mcp: Some(OwaspMcp::SupplyChain),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for dep in &target.dependencies.dependencies {
            let is_pinned = dep
                .version_constraint
                .as_ref()
                .map(|v| {
                    // Consider pinned if: exact version (no operators) or uses ==
                    // Unpinned: >=, ~=, ^, *, no version
                    !v.starts_with(">=")
                        && !v.starts_with("~=")
                        && !v.starts_with("~>")
                        && !v.starts_with('^')
                        && !v.contains('*')
                        && !v.starts_with('>')
                        && !v.starts_with('<')
                })
                .unwrap_or(false); // No version at all = unpinned

            if !is_pinned {
                let version_info = dep
                    .version_constraint
                    .as_deref()
                    .unwrap_or("(no version specified)");

                findings.push(Finding {
                    rule_id: "SHIELD-009".into(),
                    rule_name: "Unpinned Dependencies".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::SupplyChain,
                    message: format!("Dependency '{}' is not pinned: {}", dep.name, version_info),
                    location: dep.location.clone(),
                    evidence: vec![Evidence {
                        description: format!("{} {} on {}", dep.name, version_info, dep.registry),
                        location: dep.location.clone(),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(format!(
                        "Pin '{}' to an exact version (e.g., {}==x.y.z) to prevent \
                         supply chain attacks via malicious updates.",
                        dep.name, dep.name
                    )),
                    cwe_id: Some("CWE-1104".into()),
                });
            }
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

    fn make_target(deps: Vec<Dependency>) -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: DependencySurface {
                dependencies: deps,
                ..Default::default()
            },
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    #[test]
    fn flags_unpinned_dep() {
        let target = make_target(vec![Dependency {
            name: "requests".into(),
            version_constraint: Some(">=2.28".into()),
            locked_version: None,
            locked_hash: None,
            registry: "pypi".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = UnpinnedDepsDetector.run(&target);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn passes_pinned_dep() {
        let target = make_target(vec![Dependency {
            name: "requests".into(),
            version_constraint: Some("2.31.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "pypi".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = UnpinnedDepsDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_no_version() {
        let target = make_target(vec![Dependency {
            name: "flask".into(),
            version_constraint: None,
            locked_version: None,
            locked_hash: None,
            registry: "pypi".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = UnpinnedDepsDetector.run(&target);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_caret_range() {
        let target = make_target(vec![Dependency {
            name: "express".into(),
            version_constraint: Some("^4.18.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "npm".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = UnpinnedDepsDetector.run(&target);
        assert_eq!(findings.len(), 1);
    }
}
