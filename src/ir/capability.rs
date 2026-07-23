use std::collections::BTreeSet;

use crate::analysis::runtime_install::is_runtime_install_command;

use super::execution_surface::{ExecutionSurface, FileOpType};
use super::tool_surface::{
    Capability, CapabilityDeclaration, CapabilityDeclarationSource, CapabilityEvidence,
    PermissionType, ToolSurface,
};

pub(crate) fn project_declared_permissions(tool: &mut ToolSurface) {
    for permission in &tool.declared_permissions {
        let Some(capability) = capability_for_permission(permission.permission_type) else {
            continue;
        };
        tool.declared_capabilities.insert(capability);
        tool.capability_declarations.push(CapabilityDeclaration {
            capability,
            source: CapabilityDeclarationSource::Permission,
            phrase_or_field: permission_label(permission.permission_type).to_string(),
        });
    }
    tool.capability_declarations
        .sort_by_key(|declaration| declaration.capability);
    tool.capability_declarations.dedup();
}

pub(crate) fn project_observed_execution(tool: &mut ToolSurface, execution: &ExecutionSurface) {
    let mut capabilities = BTreeSet::new();
    let mut evidence = Vec::new();

    for operation in &execution.file_operations {
        let (capability, label) = match operation.operation {
            FileOpType::Read | FileOpType::List => (Capability::FsRead, "file read"),
            FileOpType::Write | FileOpType::Delete | FileOpType::Chmod => {
                (Capability::FsWrite, "file write")
            }
        };
        capabilities.insert(capability);
        evidence.push(CapabilityEvidence {
            capability,
            location: operation.location.clone(),
            description: label.to_string(),
        });
    }

    for operation in &execution.network_operations {
        capabilities.insert(Capability::NetworkEgress);
        evidence.push(CapabilityEvidence {
            capability: Capability::NetworkEgress,
            location: operation.location.clone(),
            description: format!("network egress via {}", operation.function),
        });
    }

    for operation in &execution.commands {
        capabilities.insert(Capability::ProcessExec);
        evidence.push(CapabilityEvidence {
            capability: Capability::ProcessExec,
            location: operation.location.clone(),
            description: format!("process execution via {}", operation.function),
        });
        if let super::ArgumentSource::Literal(command) = &operation.command_arg {
            if is_runtime_install_command(command) {
                capabilities.insert(Capability::PackageInstall);
                evidence.push(CapabilityEvidence {
                    capability: Capability::PackageInstall,
                    location: operation.location.clone(),
                    description: "runtime package installation".to_string(),
                });
            }
        }
    }

    for access in &execution.env_accesses {
        capabilities.insert(Capability::EnvRead);
        evidence.push(CapabilityEvidence {
            capability: Capability::EnvRead,
            location: access.location.clone(),
            description: "environment read".to_string(),
        });
        if access.is_sensitive {
            capabilities.insert(Capability::CredentialAccess);
            evidence.push(CapabilityEvidence {
                capability: Capability::CredentialAccess,
                location: access.location.clone(),
                description: "sensitive environment read".to_string(),
            });
        }
    }

    for operation in &execution.dynamic_exec {
        capabilities.insert(Capability::DynamicEval);
        evidence.push(CapabilityEvidence {
            capability: Capability::DynamicEval,
            location: operation.location.clone(),
            description: format!("dynamic evaluation via {}", operation.function),
        });
    }

    tool.observed_capabilities.extend(capabilities);
    tool.capability_evidence.extend(evidence);
    tool.capability_evidence.sort_by(|left, right| {
        (
            left.capability,
            &left.location.file,
            left.location.line,
            left.location.column,
            &left.description,
        )
            .cmp(&(
                right.capability,
                &right.location.file,
                right.location.line,
                right.location.column,
                &right.description,
            ))
    });
    tool.capability_evidence.dedup();
}

fn capability_for_permission(permission: PermissionType) -> Option<Capability> {
    match permission {
        PermissionType::FileRead => Some(Capability::FsRead),
        PermissionType::FileWrite => Some(Capability::FsWrite),
        PermissionType::NetworkAccess => Some(Capability::NetworkEgress),
        PermissionType::ProcessExec => Some(Capability::ProcessExec),
        PermissionType::EnvAccess => Some(Capability::EnvRead),
        PermissionType::DatabaseAccess => Some(Capability::DatabaseRead),
        PermissionType::Unknown => None,
    }
}

fn permission_label(permission: PermissionType) -> &'static str {
    match permission {
        PermissionType::FileRead => "file_read",
        PermissionType::FileWrite => "file_write",
        PermissionType::NetworkAccess => "network_access",
        PermissionType::ProcessExec => "process_exec",
        PermissionType::EnvAccess => "env_access",
        PermissionType::DatabaseAccess => "database_access",
        PermissionType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ir::execution_surface::{
        CommandInvocation, EnvAccess, FileOperation, NetworkOperation,
    };
    use crate::ir::{ArgumentSource, SourceLocation};

    fn location(line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("src/server.ts"),
            line,
            column: 2,
            end_line: Some(line),
            end_column: Some(8),
        }
    }

    fn tool() -> ToolSurface {
        ToolSurface {
            name: "tool".into(),
            description: None,
            input_schema: None,
            output_schema: None,
            declared_permissions: Vec::new(),
            defined_at: None,
            declared_capabilities: BTreeSet::new(),
            capability_declarations: Vec::new(),
            observed_capabilities: BTreeSet::new(),
            capability_observation_complete: false,
            capability_evidence: Vec::new(),
        }
    }

    #[test]
    fn permissions_project_without_input_schema_inference() {
        let mut tool = tool();
        tool.input_schema = Some(serde_json::json!({
            "properties": {"url": {"type": "string"}}
        }));
        tool.declared_permissions = vec![
            super::super::tool_surface::DeclaredPermission {
                permission_type: PermissionType::NetworkAccess,
                target: None,
                description: None,
            },
            super::super::tool_surface::DeclaredPermission {
                permission_type: PermissionType::DatabaseAccess,
                target: None,
                description: None,
            },
        ];

        project_declared_permissions(&mut tool);

        assert_eq!(
            tool.declared_capabilities,
            BTreeSet::from([Capability::NetworkEgress, Capability::DatabaseRead])
        );
        assert!(tool
            .capability_declarations
            .iter()
            .all(|declaration| { declaration.source == CapabilityDeclarationSource::Permission }));
    }

    #[test]
    fn execution_projects_capabilities_and_sorted_evidence() {
        let mut tool = tool();
        let execution = ExecutionSurface {
            commands: vec![CommandInvocation {
                function: "exec".into(),
                command_arg: ArgumentSource::Literal("npm install lodash".into()),
                location: location(5),
            }],
            file_operations: vec![FileOperation {
                operation: FileOpType::Read,
                path_arg: ArgumentSource::Unknown,
                location: location(3),
            }],
            network_operations: vec![NetworkOperation {
                function: "fetch".into(),
                url_arg: ArgumentSource::Unknown,
                method: None,
                sends_data: false,
                location: location(4),
            }],
            env_accesses: vec![EnvAccess {
                var_name: ArgumentSource::Literal("API_KEY".into()),
                is_sensitive: true,
                location: location(2),
            }],
            dynamic_exec: Vec::new(),
        };

        project_observed_execution(&mut tool, &execution);

        assert_eq!(
            tool.observed_capabilities,
            BTreeSet::from([
                Capability::FsRead,
                Capability::NetworkEgress,
                Capability::ProcessExec,
                Capability::EnvRead,
                Capability::CredentialAccess,
                Capability::PackageInstall,
            ])
        );
        assert!(tool
            .capability_evidence
            .windows(2)
            .all(|pair| pair[0].capability <= pair[1].capability));
    }
}
