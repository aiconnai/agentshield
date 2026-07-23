use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::SourceLocation;

/// A declared tool/function exposed by the extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSurface {
    pub name: String,
    pub description: Option<String>,
    /// JSON Schema of the tool's input parameters.
    pub input_schema: Option<serde_json::Value>,
    /// JSON Schema of the tool's output.
    pub output_schema: Option<serde_json::Value>,
    /// Permissions declared by the tool (if any).
    pub declared_permissions: Vec<DeclaredPermission>,
    /// Source location where the tool is defined.
    pub defined_at: Option<SourceLocation>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub declared_capabilities: BTreeSet<Capability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_declarations: Vec<CapabilityDeclaration>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub observed_capabilities: BTreeSet<Capability>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub capability_observation_complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_evidence: Vec<CapabilityEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    NetworkEgress,
    ProcessExec,
    EnvRead,
    CredentialAccess,
    DynamicEval,
    PackageInstall,
    DatabaseRead,
    DatabaseWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEvidence {
    pub capability: Capability,
    pub location: SourceLocation,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    pub capability: Capability,
    pub source: CapabilityDeclarationSource,
    pub phrase_or_field: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDeclarationSource {
    Description,
    InputSchema,
    Permission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclaredPermission {
    pub permission_type: PermissionType,
    /// e.g., "filesystem:/tmp/*"
    pub target: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionType {
    FileRead,
    FileWrite,
    NetworkAccess,
    ProcessExec,
    EnvAccess,
    DatabaseAccess,
    Unknown,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> ToolSurface {
        ToolSurface {
            name: "read_file".into(),
            description: Some("Read a file".into()),
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
    fn empty_capability_fields_are_omitted_from_json() {
        let value = serde_json::to_value(tool()).unwrap();

        assert!(value.get("declared_capabilities").is_none());
        assert!(value.get("capability_declarations").is_none());
        assert!(value.get("observed_capabilities").is_none());
        assert!(value.get("capability_observation_complete").is_none());
        assert!(value.get("capability_evidence").is_none());
    }

    #[test]
    fn legacy_tool_json_deserializes_with_capability_defaults() {
        let value = serde_json::json!({
            "name": "read_file",
            "description": "Read a file",
            "input_schema": null,
            "output_schema": null,
            "declared_permissions": [],
            "defined_at": null
        });

        let tool: ToolSurface = serde_json::from_value(value).unwrap();

        assert!(tool.declared_capabilities.is_empty());
        assert!(tool.capability_declarations.is_empty());
        assert!(tool.observed_capabilities.is_empty());
        assert!(!tool.capability_observation_complete);
        assert!(tool.capability_evidence.is_empty());
    }

    #[test]
    fn capabilities_serialize_in_stable_enum_order() {
        let mut tool = tool();
        tool.observed_capabilities.extend([
            Capability::NetworkEgress,
            Capability::FsRead,
            Capability::CredentialAccess,
        ]);

        let value = serde_json::to_value(tool).unwrap();

        assert_eq!(
            value["observed_capabilities"],
            serde_json::json!(["fs_read", "network_egress", "credential_access"])
        );
    }

    #[test]
    fn populated_capability_state_round_trips() {
        let mut tool = tool();
        tool.declared_capabilities.insert(Capability::FsRead);
        tool.capability_declarations.push(CapabilityDeclaration {
            capability: Capability::FsRead,
            source: CapabilityDeclarationSource::Description,
            phrase_or_field: "read files".into(),
        });
        tool.observed_capabilities.insert(Capability::FsRead);
        tool.capability_observation_complete = true;
        tool.capability_evidence.push(CapabilityEvidence {
            capability: Capability::FsRead,
            location: SourceLocation {
                file: "src/server.ts".into(),
                line: 4,
                column: 2,
                end_line: Some(4),
                end_column: Some(12),
            },
            description: "file read".into(),
        });

        let value = serde_json::to_value(&tool).unwrap();
        let decoded: ToolSurface = serde_json::from_value(value).unwrap();

        assert_eq!(decoded.declared_capabilities, tool.declared_capabilities);
        assert_eq!(
            decoded.capability_declarations,
            tool.capability_declarations
        );
        assert_eq!(decoded.observed_capabilities, tool.observed_capabilities);
        assert!(decoded.capability_observation_complete);
        assert_eq!(decoded.capability_evidence, tool.capability_evidence);
    }
}
