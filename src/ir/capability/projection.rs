use std::collections::BTreeSet;

use crate::analysis::runtime_install::is_runtime_install_command;
use crate::ir::execution_surface::{ExecutionSurface, FileOpType};
use crate::ir::tool_surface::{
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
    sort_and_dedup_declarations(&mut tool.capability_declarations);
}

pub(crate) fn sort_and_dedup_declarations(declarations: &mut Vec<CapabilityDeclaration>) {
    declarations.sort_by(|left, right| {
        (
            left.capability,
            declaration_source_order(left.source),
            &left.phrase_or_field,
        )
            .cmp(&(
                right.capability,
                declaration_source_order(right.source),
                &right.phrase_or_field,
            ))
    });
    declarations.dedup();
}

pub(crate) fn declaration_source_order(source: CapabilityDeclarationSource) -> u8 {
    match source {
        CapabilityDeclarationSource::Description => 0,
        CapabilityDeclarationSource::InputSchema => 1,
        CapabilityDeclarationSource::Permission => 2,
    }
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

        if let crate::ir::ArgumentSource::Literal(command) = &operation.command_arg {
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
