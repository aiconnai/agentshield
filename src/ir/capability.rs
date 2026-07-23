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
    sort_and_dedup_declarations(&mut tool.capability_declarations);
}

pub(crate) fn project_declared_description(tool: &mut ToolSurface) {
    let Some(description) = tool.description.as_deref() else {
        return;
    };

    for matched in description_capabilities(description) {
        tool.declared_capabilities.insert(matched.capability);
        tool.capability_declarations.push(CapabilityDeclaration {
            capability: matched.capability,
            source: CapabilityDeclarationSource::Description,
            phrase_or_field: matched.phrase,
        });
    }
    sort_and_dedup_declarations(&mut tool.capability_declarations);
}

fn sort_and_dedup_declarations(declarations: &mut Vec<CapabilityDeclaration>) {
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

fn declaration_source_order(source: CapabilityDeclarationSource) -> u8 {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DescriptionCapability {
    capability: Capability,
    phrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DescriptionToken {
    Word(String),
    Boundary,
}

struct PhrasePattern {
    capability: Capability,
    tokens: &'static [&'static str],
}

macro_rules! phrase {
    ($capability:ident, $($token:literal),+ $(,)?) => {
        PhrasePattern {
            capability: Capability::$capability,
            tokens: &[$($token),+],
        }
    };
}

const DESCRIPTION_PHRASES: &[PhrasePattern] = &[
    phrase!(FsRead, "read", "file"),
    phrase!(FsRead, "read", "files"),
    phrase!(FsRead, "list", "directory"),
    phrase!(FsRead, "list", "directories"),
    phrase!(FsRead, "inspect", "file"),
    phrase!(FsRead, "inspect", "files"),
    phrase!(FsWrite, "write", "file"),
    phrase!(FsWrite, "write", "files"),
    phrase!(FsWrite, "create", "file"),
    phrase!(FsWrite, "create", "files"),
    phrase!(FsWrite, "delete", "file"),
    phrase!(FsWrite, "delete", "files"),
    phrase!(FsWrite, "modify", "file"),
    phrase!(FsWrite, "modify", "files"),
    phrase!(NetworkEgress, "fetch", "url"),
    phrase!(NetworkEgress, "fetch", "urls"),
    phrase!(NetworkEgress, "http", "request"),
    phrase!(NetworkEgress, "http", "requests"),
    phrase!(NetworkEgress, "call", "api"),
    phrase!(NetworkEgress, "call", "apis"),
    phrase!(NetworkEgress, "from", "url"),
    phrase!(NetworkEgress, "from", "urls"),
    phrase!(NetworkEgress, "from", "http"),
    phrase!(NetworkEgress, "from", "https"),
    phrase!(NetworkEgress, "from", "web"),
    phrase!(NetworkEgress, "download", "url"),
    phrase!(NetworkEgress, "download", "urls"),
    phrase!(ProcessExec, "run", "command"),
    phrase!(ProcessExec, "run", "commands"),
    phrase!(ProcessExec, "execute", "command"),
    phrase!(ProcessExec, "execute", "commands"),
    phrase!(ProcessExec, "shell", "command"),
    phrase!(ProcessExec, "shell", "commands"),
    phrase!(ProcessExec, "subprocess"),
    phrase!(EnvRead, "read", "environment", "variable"),
    phrase!(EnvRead, "read", "environment", "variables"),
    phrase!(EnvRead, "inspect", "environment"),
    phrase!(CredentialAccess, "read", "secret"),
    phrase!(CredentialAccess, "read", "secrets"),
    phrase!(CredentialAccess, "load", "secret"),
    phrase!(CredentialAccess, "load", "secrets"),
    phrase!(CredentialAccess, "access", "credential"),
    phrase!(CredentialAccess, "access", "credentials"),
    phrase!(CredentialAccess, "read", "api", "key", "from", "store"),
    phrase!(CredentialAccess, "read", "api", "keys", "from", "store"),
    phrase!(CredentialAccess, "load", "api", "key", "from", "store"),
    phrase!(CredentialAccess, "load", "api", "keys", "from", "store"),
    phrase!(DynamicEval, "evaluate", "arbitrary", "code"),
    phrase!(DynamicEval, "execute", "arbitrary", "code"),
    phrase!(DynamicEval, "dynamic", "code", "evaluation"),
    phrase!(PackageInstall, "install", "package"),
    phrase!(PackageInstall, "install", "packages"),
    phrase!(PackageInstall, "add", "dependency"),
    phrase!(PackageInstall, "add", "dependencies"),
    phrase!(DatabaseRead, "query", "database"),
    phrase!(DatabaseRead, "read", "database"),
    phrase!(DatabaseRead, "search", "records"),
    phrase!(DatabaseWrite, "write", "database"),
    phrase!(DatabaseWrite, "update", "record"),
    phrase!(DatabaseWrite, "update", "records"),
    phrase!(DatabaseWrite, "delete", "record"),
    phrase!(DatabaseWrite, "delete", "records"),
];

fn description_capabilities(description: &str) -> Vec<DescriptionCapability> {
    let tokens = tokenize_description(description);
    let mut matches = Vec::new();

    for pattern in DESCRIPTION_PHRASES {
        for (start, candidate) in tokens.windows(pattern.tokens.len()).enumerate() {
            if pattern_matches(candidate, pattern.tokens) && !is_negated(&tokens, start) {
                matches.push(DescriptionCapability {
                    capability: pattern.capability,
                    phrase: pattern.tokens.join(" "),
                });
            }
        }
    }

    matches.sort_by(|left, right| {
        (left.capability, &left.phrase).cmp(&(right.capability, &right.phrase))
    });
    matches.dedup();
    matches
}

fn pattern_matches(candidate: &[DescriptionToken], pattern: &[&str]) -> bool {
    candidate
        .iter()
        .zip(pattern)
        .all(|(token, expected)| matches!(token, DescriptionToken::Word(word) if word == expected))
}

fn tokenize_description(description: &str) -> Vec<DescriptionToken> {
    let normalized = description.to_lowercase().replace('’', "'");
    let mut tokens = Vec::new();
    let mut word = String::new();

    for character in normalized.chars() {
        if character.is_alphanumeric() || character == '\'' {
            word.push(character);
            continue;
        }

        push_description_word(&mut tokens, &mut word);
        if matches!(character, '.' | ';' | ':' | '!' | '?')
            && !matches!(tokens.last(), Some(DescriptionToken::Boundary))
        {
            tokens.push(DescriptionToken::Boundary);
        }
    }
    push_description_word(&mut tokens, &mut word);
    tokens
}

fn push_description_word(tokens: &mut Vec<DescriptionToken>, word: &mut String) {
    if word.is_empty() {
        return;
    }

    let normalized = normalize_description_word(word);
    if !matches!(normalized, "a" | "an" | "the") {
        tokens.push(DescriptionToken::Word(normalized.to_string()));
    }
    word.clear();
}

fn normalize_description_word(word: &str) -> &str {
    match word {
        "reads" => "read",
        "writes" => "write",
        "creates" => "create",
        "deletes" => "delete",
        "modifies" => "modify",
        "lists" => "list",
        "inspects" => "inspect",
        "fetches" => "fetch",
        "calls" => "call",
        "downloads" => "download",
        "runs" => "run",
        "executes" => "execute",
        "loads" => "load",
        "accesses" => "access",
        "evaluates" => "evaluate",
        "installs" => "install",
        "adds" => "add",
        "queries" => "query",
        "searches" => "search",
        "updates" => "update",
        _ => word,
    }
}

fn is_negated(tokens: &[DescriptionToken], phrase_start: usize) -> bool {
    let mut preceding_words = 0;
    for token in tokens[..phrase_start].iter().rev() {
        let DescriptionToken::Word(word) = token else {
            break;
        };
        if matches!(word.as_str(), "but" | "however" | "yet") {
            break;
        }
        preceding_words += 1;
        if matches!(
            word.as_str(),
            "no" | "not" | "never" | "without" | "doesn't"
        ) {
            return true;
        }
        if preceding_words == 4 {
            break;
        }
    }
    false
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
        assert!(tool
            .capability_declarations
            .iter()
            .all(|declaration| { declaration.source == CapabilityDeclarationSource::Description }));
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
        tool.declared_permissions = vec![super::super::tool_surface::DeclaredPermission {
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
