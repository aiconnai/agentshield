pub(crate) mod inference;
pub(crate) mod projection;
pub(crate) mod types;

pub(crate) use inference::project_declared_description;
pub(crate) use projection::{project_declared_permissions, project_observed_execution};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::projection::declaration_source_order;
    use super::*;
    use crate::ir::execution_surface::{
        CommandInvocation, EnvAccess, ExecutionSurface, FileOpType, FileOperation, NetworkOperation,
    };
    use crate::ir::tool_surface::{
        Capability, CapabilityDeclarationSource, PermissionType, ToolSurface,
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
            crate::ir::tool_surface::DeclaredPermission {
                permission_type: PermissionType::NetworkAccess,
                target: None,
                description: None,
            },
            crate::ir::tool_surface::DeclaredPermission {
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
        assert!(
            tool.capability_declarations.iter().all(|declaration| {
                declaration.source == CapabilityDeclarationSource::Permission
            })
        );
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
        assert!(
            tool.capability_evidence
                .windows(2)
                .all(|pair| pair[0].capability <= pair[1].capability)
        );
    }

    #[test]
    fn description_projection_recognizes_curated_phrases_with_boundaries() {
        let mut tool = tool();
        tool.description = Some(
            "Read files, fetch URLs, run commands, inspect environment, \
             load secrets, evaluate arbitrary code, install packages, \
             query database, and update records."
                .into(),
        );

        project_declared_description(&mut tool);

        assert_eq!(
            tool.declared_capabilities,
            BTreeSet::from([
                Capability::FsRead,
                Capability::NetworkEgress,
                Capability::ProcessExec,
                Capability::EnvRead,
                Capability::CredentialAccess,
                Capability::DynamicEval,
                Capability::PackageInstall,
                Capability::DatabaseRead,
                Capability::DatabaseWrite,
            ])
        );
        assert!(
            tool.capability_declarations.iter().all(|declaration| {
                declaration.source == CapabilityDeclarationSource::Description
            })
        );
    }

    #[test]
    fn description_projection_is_fp_averse() {
        for description in [
            "A utility to manage data and search",
            "Accepts an API key",
            "Download the report to disk",
            "Execute code review and execute code paths",
            "Does not access the network",
        ] {
            let mut tool = tool();
            tool.description = Some(description.into());

            project_declared_description(&mut tool);

            assert!(
                tool.declared_capabilities.is_empty(),
                "unexpected capability for {description}"
            );
        }

        let mut api_key_and_file = tool();
        api_key_and_file.description = Some("Accepts an API key and read files".into());
        project_declared_description(&mut api_key_and_file);
        assert_eq!(
            api_key_and_file.declared_capabilities,
            BTreeSet::from([Capability::FsRead])
        );
    }

    #[test]
    fn description_projection_handles_articles_inflections_and_url_disclosure() {
        for description in [
            "Reads a file and fetches a URL",
            "Read files from a URL",
            "Fetches the URL and reads the file",
        ] {
            let mut tool = tool();
            tool.description = Some(description.into());

            project_declared_description(&mut tool);

            assert_eq!(
                tool.declared_capabilities,
                BTreeSet::from([Capability::FsRead, Capability::NetworkEgress]),
                "{description}"
            );
        }
    }

    #[test]
    fn negation_within_four_tokens_suppresses_a_phrase() {
        for description in [
            "Never fetch URLs",
            "Does not ever directly fetch URLs",
            "Works without making HTTP requests",
            "Doesn't run commands",
        ] {
            let mut tool = tool();
            tool.description = Some(description.into());
            project_declared_description(&mut tool);
            assert!(
                tool.declared_capabilities.is_empty(),
                "unexpected capability for {description}"
            );
        }
    }

    #[test]
    fn negation_stops_at_sentence_and_adversative_boundaries() {
        for description in [
            "Does not write files. Fetch URLs and read files.",
            "Does not write files; fetches a URL and reads a file.",
            "Does not write files, but fetches a URL and reads a file.",
        ] {
            let mut tool = tool();
            tool.description = Some(description.into());

            project_declared_description(&mut tool);

            assert_eq!(
                tool.declared_capabilities,
                BTreeSet::from([Capability::FsRead, Capability::NetworkEgress]),
                "{description}"
            );
        }
    }

    #[test]
    fn download_from_local_sources_does_not_declare_network() {
        for description in [
            "Download from disk and read files",
            "Downloads from cache and reads a file",
            "Download from local storage and read files",
        ] {
            let mut tool = tool();
            tool.description = Some(description.into());

            project_declared_description(&mut tool);

            assert_eq!(
                tool.declared_capabilities,
                BTreeSet::from([Capability::FsRead]),
                "{description}"
            );
        }

        let mut remote = tool();
        remote.description = Some("Download from a URL and read files".into());
        project_declared_description(&mut remote);
        assert_eq!(
            remote.declared_capabilities,
            BTreeSet::from([Capability::FsRead, Capability::NetworkEgress])
        );
    }

    #[test]
    fn declaration_order_and_projection_are_idempotent() {
        let mut tool = tool();
        tool.description = Some("Fetch URLs and read files".into());
        tool.declared_permissions = vec![crate::ir::tool_surface::DeclaredPermission {
            permission_type: PermissionType::NetworkAccess,
            target: None,
            description: None,
        }];

        project_declared_permissions(&mut tool);
        project_declared_description(&mut tool);
        project_declared_description(&mut tool);

        assert_eq!(tool.capability_declarations.len(), 3);
        assert!(tool.capability_declarations.windows(2).all(|pair| {
            (
                pair[0].capability,
                declaration_source_order(pair[0].source),
                &pair[0].phrase_or_field,
            ) <= (
                pair[1].capability,
                declaration_source_order(pair[1].source),
                &pair[1].phrase_or_field,
            )
        }));
    }
}
