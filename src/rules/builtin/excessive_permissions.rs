use std::collections::HashSet;

use crate::ir::tool_surface::PermissionType;
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-008: Excessive Permissions
///
/// Flags when an extension declares permissions it never actually uses.
/// A calculator tool that requests network access is suspicious.
pub struct ExcessivePermissionsDetector;

impl Detector for ExcessivePermissionsDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-008".into(),
            name: "Excessive Permissions".into(),
            description: "Extension declares more capabilities than it uses".into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::ExcessivePermissions,
            cwe_id: Some("CWE-250".into()),
            owasp_mcp: Some(OwaspMcp::ExcessiveScope),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect declared permissions across all tools
        let declared: HashSet<PermissionType> = target
            .tools
            .iter()
            .flat_map(|t| t.declared_permissions.iter().map(|p| p.permission_type))
            .collect();

        if declared.is_empty() {
            return findings;
        }

        // Determine actually used capabilities from execution surface
        let mut used = HashSet::new();
        if !target.execution.file_operations.is_empty() {
            used.insert(PermissionType::FileRead);
            used.insert(PermissionType::FileWrite);
        }
        if !target.execution.network_operations.is_empty() {
            used.insert(PermissionType::NetworkAccess);
        }
        if !target.execution.commands.is_empty() {
            used.insert(PermissionType::ProcessExec);
        }
        if !target.execution.env_accesses.is_empty() {
            used.insert(PermissionType::EnvAccess);
        }

        // Find declared but unused permissions
        let unused: Vec<_> = declared.difference(&used).copied().collect();

        if !unused.is_empty() {
            let unused_names: Vec<String> = unused.iter().map(|p| format!("{:?}", p)).collect();

            findings.push(Finding {
                rule_id: "SHIELD-008".into(),
                rule_name: "Excessive Permissions".into(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                attack_category: AttackCategory::ExcessivePermissions,
                message: format!(
                    "Declares {} permission(s) not used in code: {}",
                    unused.len(),
                    unused_names.join(", ")
                ),
                location: None,
                evidence: unused
                    .iter()
                    .map(|p| Evidence {
                        description: format!("Declared {:?} but no matching code found", p),
                        location: None,
                        snippet: None,
                    })
                    .collect(),
                taint_path: None,
                remediation: Some(
                    "Remove unnecessary permission declarations. \
                     Only request capabilities the tool actually needs."
                        .into(),
                ),
                cwe_id: Some("CWE-250".into()),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::tool_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    #[test]
    fn flags_unused_network_permission() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![ToolSurface {
                name: "calculator".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                declared_permissions: vec![DeclaredPermission {
                    permission_type: PermissionType::NetworkAccess,
                    target: None,
                    description: None,
                }],
                defined_at: None,
            }],
            execution: Default::default(), // No actual execution
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = ExcessivePermissionsDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-008");
    }

    #[test]
    fn passes_when_no_declared_permissions() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![ToolSurface {
                name: "calculator".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                declared_permissions: vec![],
                defined_at: None,
            }],
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = ExcessivePermissionsDetector.run(&target);
        assert!(findings.is_empty());
    }
}
