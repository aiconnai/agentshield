//! Crate-private registry and structural parsers for local client discovery.
//!
//! D.0 intentionally has no CLI or public API consumer. The module-level
//! allowance is removed when D.1 wires the accepted types into `discover`.
#![allow(dead_code)]

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(crate) const REGISTRY_VERSION: u32 = 1;
pub(crate) const MAX_DEPTH_PER_ROOT: usize = 4;
pub(crate) const MAX_DIRECTORIES_PER_ROOT: usize = 256;
pub(crate) const MAX_DIRECTORIES_PER_INVOCATION: usize = 512;
pub(crate) const MAX_CANDIDATE_FILES_PER_ROOT: usize = 1_024;
pub(crate) const MAX_CANDIDATE_FILES_PER_INVOCATION: usize = 2_048;
pub(crate) const MAX_OPENED_CONFIGS_PER_ROOT: usize = 128;
pub(crate) const MAX_OPENED_CONFIGS_PER_INVOCATION: usize = 256;
pub(crate) const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_AGGREGATE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_ENTRIES_PER_INVOCATION: usize = 1_024;
const MAX_DECLARED_NAME_BYTES: usize = 256;
const MAX_PATH_REF_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClientId {
    ClaudeCode,
    Cursor,
    VsCode,
}

impl ClientId {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Cursor => "cursor",
            Self::VsCode => "vscode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiscoveryBase {
    EffectiveProfile,
    ExplicitRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiscoveryScope {
    User,
    Workspace,
}

impl DiscoveryScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Workspace => "workspace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigFormat {
    McpServersJson,
    VsCodeServersJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiscoveryDescriptor {
    pub id: &'static str,
    pub client_id: ClientId,
    pub base: DiscoveryBase,
    pub relative_path: &'static str,
    pub scope: DiscoveryScope,
    pub format: ConfigFormat,
    pub descriptor_version: u32,
    pub documentation_url: &'static str,
}

const REGISTRY: &[DiscoveryDescriptor] = &[
    DiscoveryDescriptor {
        id: "cursor.user.mcp_json",
        client_id: ClientId::Cursor,
        base: DiscoveryBase::EffectiveProfile,
        relative_path: ".cursor/mcp.json",
        scope: DiscoveryScope::User,
        format: ConfigFormat::McpServersJson,
        descriptor_version: 1,
        documentation_url: "https://docs.cursor.com/context/model-context-protocol",
    },
    DiscoveryDescriptor {
        id: "cursor.workspace.mcp_json",
        client_id: ClientId::Cursor,
        base: DiscoveryBase::ExplicitRoot,
        relative_path: ".cursor/mcp.json",
        scope: DiscoveryScope::Workspace,
        format: ConfigFormat::McpServersJson,
        descriptor_version: 1,
        documentation_url: "https://docs.cursor.com/context/model-context-protocol",
    },
    DiscoveryDescriptor {
        id: "claude_code.workspace.mcp_json",
        client_id: ClientId::ClaudeCode,
        base: DiscoveryBase::ExplicitRoot,
        relative_path: ".mcp.json",
        scope: DiscoveryScope::Workspace,
        format: ConfigFormat::McpServersJson,
        descriptor_version: 1,
        documentation_url: "https://docs.anthropic.com/en/docs/claude-code/mcp",
    },
    DiscoveryDescriptor {
        id: "vscode.workspace.mcp_json",
        client_id: ClientId::VsCode,
        base: DiscoveryBase::ExplicitRoot,
        relative_path: ".vscode/mcp.json",
        scope: DiscoveryScope::Workspace,
        format: ConfigFormat::VsCodeServersJson,
        descriptor_version: 1,
        documentation_url: "https://code.visualstudio.com/docs/agents/reference/mcp-configuration",
    },
];

pub(crate) fn registry() -> &'static [DiscoveryDescriptor] {
    REGISTRY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceStatus {
    Inspected,
    Unsupported,
    Malformed,
    PermissionDenied,
    LimitReached,
    UnsupportedFilesystemSafety,
    ChangeDetectedDuringRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntryState {
    Configured,
    Disabled,
    Unresolved,
    LocalReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SupportStatus {
    LocalStdio,
    Remote,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiagnosticCode {
    InvalidJson,
    MissingServerMap,
    ServerMapNotObject,
    EntryNotObject,
    EntryNameTooLong,
    EntryNameInvalid,
    EntryLimitReached,
    ConfigSizeLimitReached,
    PermissionDenied,
    UnsupportedFilesystemSafety,
    ChangeDetectedDuringRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiscoveryMethod {
    KnownPath,
    ExplicitRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProvenanceObservation {
    pub descriptor_id: &'static str,
    pub discovery_method: DiscoveryMethod,
    pub path_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedactedPathRef(String);

impl RedactedPathRef {
    pub(crate) fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PATH_REF_BYTES
            || value.contains('\\')
            || value.contains('\0')
            || value.split('/').any(|component| component == "..")
            || !valid_path_ref_prefix(&value)
        {
            return None;
        }
        Some(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DiscoverySource {
    pub source_id: String,
    pub client_id: ClientId,
    pub path_ref: String,
    pub scope: DiscoveryScope,
    pub status: SourceStatus,
    pub provenance: Vec<ProvenanceObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DiscoveryEntry {
    pub entry_id: String,
    pub source_id: String,
    pub declared_name: String,
    pub state: EntryState,
    pub support_status: SupportStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DiscoveryDiagnostic {
    pub code: DiagnosticCode,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ParsedDiscoverySource {
    pub source: DiscoverySource,
    pub entries: Vec<DiscoveryEntry>,
    pub diagnostics: Vec<DiscoveryDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DiscoverySummary {
    pub sources: usize,
    pub entries: usize,
    pub diagnostics: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DiscoveryEnvelope {
    pub schema: &'static str,
    pub registry_version: u32,
    pub sources: Vec<DiscoverySource>,
    pub entries: Vec<DiscoveryEntry>,
    pub diagnostics: Vec<DiscoveryDiagnostic>,
    pub summary: DiscoverySummary,
}

pub(crate) fn build_envelope(mut parsed_sources: Vec<ParsedDiscoverySource>) -> DiscoveryEnvelope {
    parsed_sources.sort_by(|left, right| {
        (
            left.source.client_id,
            left.source.path_ref.as_str(),
            left.source.scope,
            left.source.source_id.as_str(),
        )
            .cmp(&(
                right.source.client_id,
                right.source.path_ref.as_str(),
                right.source.scope,
                right.source.source_id.as_str(),
            ))
    });

    let mut sources = Vec::with_capacity(parsed_sources.len());
    let mut entries = Vec::new();
    let mut diagnostics = Vec::new();
    for mut parsed in parsed_sources {
        let remaining_entries = MAX_ENTRIES_PER_INVOCATION.saturating_sub(entries.len());
        if parsed.entries.len() > remaining_entries {
            parsed.entries.truncate(remaining_entries);
            parsed.source.status = SourceStatus::LimitReached;
            parsed.push_diagnostic(DiagnosticCode::EntryLimitReached);
        }
        sources.push(parsed.source);
        entries.extend(parsed.entries);
        diagnostics.extend(parsed.diagnostics);
    }
    entries.sort_by(|left, right| {
        (
            left.source_id.as_str(),
            left.declared_name.as_str(),
            left.entry_id.as_str(),
        )
            .cmp(&(
                right.source_id.as_str(),
                right.declared_name.as_str(),
                right.entry_id.as_str(),
            ))
    });
    diagnostics.sort_by(|left, right| {
        (left.source_id.as_str(), left.code).cmp(&(right.source_id.as_str(), right.code))
    });

    let summary = DiscoverySummary {
        sources: sources.len(),
        entries: entries.len(),
        diagnostics: diagnostics.len(),
    };
    DiscoveryEnvelope {
        schema: "agentshield.discovery/v1",
        registry_version: REGISTRY_VERSION,
        sources,
        entries,
        diagnostics,
        summary,
    }
}

pub(crate) fn parse_source(
    descriptor: &DiscoveryDescriptor,
    path_ref: &RedactedPathRef,
    bytes: &[u8],
) -> ParsedDiscoverySource {
    let path_ref = path_ref.as_str();
    let source_id = stable_id(&[
        descriptor.client_id.as_str(),
        path_ref,
        descriptor.scope.as_str(),
    ]);
    let mut parsed = ParsedDiscoverySource {
        source: DiscoverySource {
            source_id: source_id.clone(),
            client_id: descriptor.client_id,
            path_ref: path_ref.to_owned(),
            scope: descriptor.scope,
            status: SourceStatus::Inspected,
            provenance: vec![ProvenanceObservation {
                descriptor_id: descriptor.id,
                discovery_method: match descriptor.base {
                    DiscoveryBase::EffectiveProfile => DiscoveryMethod::KnownPath,
                    DiscoveryBase::ExplicitRoot => DiscoveryMethod::ExplicitRoot,
                },
                path_ref: path_ref.to_owned(),
            }],
        },
        entries: Vec::new(),
        diagnostics: Vec::new(),
    };

    if bytes.len() > MAX_CONFIG_BYTES {
        parsed.source.status = SourceStatus::LimitReached;
        parsed.push_diagnostic(DiagnosticCode::ConfigSizeLimitReached);
        return parsed;
    }

    let root: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => {
            parsed.source.status = SourceStatus::Malformed;
            parsed.push_diagnostic(DiagnosticCode::InvalidJson);
            return parsed;
        }
    };

    let Some(root_object) = root.as_object() else {
        parsed.source.status = SourceStatus::Malformed;
        parsed.push_diagnostic(DiagnosticCode::MissingServerMap);
        return parsed;
    };
    let map_key = match descriptor.format {
        ConfigFormat::McpServersJson => "mcpServers",
        ConfigFormat::VsCodeServersJson => "servers",
    };
    let Some(server_map_value) = root_object.get(map_key) else {
        parsed.source.status = SourceStatus::Malformed;
        parsed.push_diagnostic(DiagnosticCode::MissingServerMap);
        return parsed;
    };
    let Some(server_map) = server_map_value.as_object() else {
        parsed.source.status = SourceStatus::Malformed;
        parsed.push_diagnostic(DiagnosticCode::ServerMapNotObject);
        return parsed;
    };

    parse_entries(server_map, &source_id, &mut parsed);
    parsed
}

fn parse_entries(
    server_map: &Map<String, Value>,
    source_id: &str,
    parsed: &mut ParsedDiscoverySource,
) {
    let mut entries = server_map.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(name, _)| *name);

    for (declared_name, value) in entries {
        if parsed.entries.len() == MAX_ENTRIES_PER_INVOCATION {
            parsed.source.status = SourceStatus::LimitReached;
            parsed.push_diagnostic(DiagnosticCode::EntryLimitReached);
            break;
        }
        if declared_name.len() > MAX_DECLARED_NAME_BYTES {
            parsed.push_diagnostic(DiagnosticCode::EntryNameTooLong);
            continue;
        }
        if declared_name.chars().any(char::is_control) {
            parsed.push_diagnostic(DiagnosticCode::EntryNameInvalid);
            continue;
        }
        let Some(object) = value.as_object() else {
            parsed.push_diagnostic(DiagnosticCode::EntryNotObject);
            continue;
        };

        let support_status = classify_support(object);
        let state = if support_status == SupportStatus::Unsupported {
            EntryState::Unresolved
        } else {
            EntryState::Configured
        };
        parsed.entries.push(DiscoveryEntry {
            entry_id: stable_id(&[source_id, declared_name]),
            source_id: source_id.to_owned(),
            declared_name: declared_name.to_owned(),
            state,
            support_status,
            local_reference: None,
        });
    }
}

fn classify_support(object: &Map<String, Value>) -> SupportStatus {
    if object.get("command").is_some_and(Value::is_string) {
        SupportStatus::LocalStdio
    } else if object.get("url").is_some_and(Value::is_string) {
        SupportStatus::Remote
    } else {
        SupportStatus::Unsupported
    }
}

fn stable_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

fn valid_path_ref_prefix(value: &str) -> bool {
    if value.starts_with("~/") || value.starts_with("@SOURCE/") {
        return true;
    }
    let Some(root_suffix) = value.strip_prefix("$ROOT[") else {
        return false;
    };
    let Some((index, relative)) = root_suffix.split_once(']') else {
        return false;
    };
    !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit())
        && relative.starts_with('/')
}

impl ParsedDiscoverySource {
    fn push_diagnostic(&mut self, code: DiagnosticCode) {
        self.diagnostics.push(DiscoveryDiagnostic {
            code,
            source_id: self.source.source_id.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn descriptor(id: &str) -> &'static DiscoveryDescriptor {
        registry()
            .iter()
            .find(|descriptor| descriptor.id == id)
            .expect("fixture descriptor must exist")
    }

    fn path_ref(value: &str) -> RedactedPathRef {
        RedactedPathRef::new(value).expect("fixture path ref must be redacted")
    }

    #[test]
    fn registry_is_unique_and_documented() {
        let mut ids = BTreeSet::new();
        let mut locations = BTreeSet::new();
        for descriptor in registry() {
            assert!(ids.insert(descriptor.id), "duplicate descriptor id");
            assert!(
                locations.insert((
                    descriptor.client_id,
                    descriptor.base,
                    descriptor.relative_path,
                    descriptor.scope,
                )),
                "duplicate registry location"
            );
            assert!(descriptor.documentation_url.starts_with("https://"));
            assert_eq!(descriptor.descriptor_version, 1);
            assert!(!descriptor.relative_path.starts_with('/'));
            assert!(!descriptor.relative_path.contains(".."));
        }
    }

    #[test]
    fn cursor_fixture_is_sorted_and_secret_safe() {
        let parsed = parse_source(
            descriptor("cursor.user.mcp_json"),
            &path_ref("~/.cursor/mcp.json"),
            include_bytes!("../../tests/fixtures/discovery/cursor/mcp.json"),
        );

        assert_eq!(parsed.source.status, SourceStatus::Inspected);
        assert_eq!(
            parsed
                .entries
                .iter()
                .map(|entry| entry.declared_name.as_str())
                .collect::<Vec<_>>(),
            vec!["local-tools", "remote-docs"]
        );
        assert_eq!(parsed.entries[0].support_status, SupportStatus::LocalStdio);
        assert_eq!(parsed.entries[1].support_status, SupportStatus::Remote);

        let serialized = serde_json::to_string(&parsed).expect("result serializes");
        for forbidden in [
            "super-secret-token",
            "Authorization",
            "node",
            "--api-key",
            "https://private.example.test",
            "\"command\"",
            "\"args\"",
            "\"env\"",
            "\"url\"",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "serialized result leaked {forbidden}"
            );
        }
    }

    #[test]
    fn supported_formats_use_their_documented_map_key() {
        let claude = parse_source(
            descriptor("claude_code.workspace.mcp_json"),
            &path_ref("$ROOT[0]/.mcp.json"),
            include_bytes!("../../tests/fixtures/discovery/claude_code/.mcp.json"),
        );
        let vscode = parse_source(
            descriptor("vscode.workspace.mcp_json"),
            &path_ref("$ROOT[0]/.vscode/mcp.json"),
            include_bytes!("../../tests/fixtures/discovery/vscode/mcp.json"),
        );

        assert_eq!(claude.entries.len(), 1);
        assert_eq!(claude.entries[0].declared_name, "workspace-tools");
        assert_eq!(vscode.entries.len(), 1);
        assert_eq!(vscode.entries[0].declared_name, "workspace-docs");
    }

    #[test]
    fn malformed_input_returns_bounded_diagnostic_without_input() {
        let secret = b"{\"mcpServers\":{\"token\":\"super-secret";
        let parsed = parse_source(
            descriptor("cursor.workspace.mcp_json"),
            &path_ref("$ROOT[0]/.cursor/mcp.json"),
            secret,
        );

        assert_eq!(parsed.source.status, SourceStatus::Malformed);
        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.diagnostics[0].code, DiagnosticCode::InvalidJson);
        let serialized = serde_json::to_string(&parsed).expect("result serializes");
        assert!(!serialized.contains("super-secret"));
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let bytes = vec![b' '; MAX_CONFIG_BYTES + 1];
        let parsed = parse_source(
            descriptor("cursor.workspace.mcp_json"),
            &path_ref("$ROOT[0]/.cursor/mcp.json"),
            &bytes,
        );

        assert_eq!(parsed.source.status, SourceStatus::LimitReached);
        assert_eq!(
            parsed.diagnostics[0].code,
            DiagnosticCode::ConfigSizeLimitReached
        );
    }

    #[test]
    fn ids_are_stable_and_path_ref_sensitive() {
        let config = br#"{"mcpServers":{"tools":{"command":"node"}}}"#;
        let descriptor = descriptor("cursor.workspace.mcp_json");
        let left = parse_source(descriptor, &path_ref("$ROOT[0]/.cursor/mcp.json"), config);
        let repeated = parse_source(descriptor, &path_ref("$ROOT[0]/.cursor/mcp.json"), config);
        let other_root = parse_source(descriptor, &path_ref("$ROOT[1]/.cursor/mcp.json"), config);

        assert_eq!(left.source.source_id, repeated.source.source_id);
        assert_eq!(left.entries[0].entry_id, repeated.entries[0].entry_id);
        assert_ne!(left.source.source_id, other_root.source.source_id);
    }

    #[test]
    fn envelope_is_versioned_and_deterministic() {
        let cursor = parse_source(
            descriptor("cursor.user.mcp_json"),
            &path_ref("~/.cursor/mcp.json"),
            include_bytes!("../../tests/fixtures/discovery/cursor/mcp.json"),
        );
        let claude = parse_source(
            descriptor("claude_code.workspace.mcp_json"),
            &path_ref("$ROOT[0]/.mcp.json"),
            include_bytes!("../../tests/fixtures/discovery/claude_code/.mcp.json"),
        );

        let left = build_envelope(vec![cursor.clone(), claude.clone()]);
        let right = build_envelope(vec![claude, cursor]);
        assert_eq!(left, right);
        assert_eq!(left.schema, "agentshield.discovery/v1");
        assert_eq!(left.registry_version, 1);
        assert_eq!(left.summary.sources, 2);
        assert_eq!(left.summary.entries, 3);
    }

    #[test]
    fn envelope_enforces_aggregate_entry_budget() {
        fn config(prefix: &str, count: usize) -> Vec<u8> {
            let servers = (0..count)
                .map(|index| {
                    (
                        format!("{prefix}-{index:04}"),
                        serde_json::json!({"command": "node"}),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            serde_json::to_vec(&serde_json::json!({"mcpServers": servers}))
                .expect("fixture config serializes")
        }

        let descriptor = descriptor("cursor.workspace.mcp_json");
        let first = parse_source(
            descriptor,
            &path_ref("$ROOT[0]/.cursor/mcp.json"),
            &config("first", 600),
        );
        let second = parse_source(
            descriptor,
            &path_ref("$ROOT[1]/.cursor/mcp.json"),
            &config("second", 600),
        );
        let envelope = build_envelope(vec![second, first]);

        assert_eq!(envelope.summary.entries, MAX_ENTRIES_PER_INVOCATION);
        assert_eq!(
            envelope
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == DiagnosticCode::EntryLimitReached)
                .count(),
            1
        );
        assert!(envelope
            .sources
            .iter()
            .any(|source| source.status == SourceStatus::LimitReached));
    }

    #[test]
    fn path_refs_reject_absolute_and_traversal_paths() {
        for invalid in [
            "/Users/alice/.cursor/mcp.json",
            "C:/Users/alice/.cursor/mcp.json",
            "~/../alice/.cursor/mcp.json",
            "$ROOT[x]/.cursor/mcp.json",
            "$ROOT[0]\\mcp.json",
            "relative/mcp.json",
        ] {
            assert!(
                RedactedPathRef::new(invalid).is_none(),
                "accepted unsafe path ref {invalid}"
            );
        }
        assert!(RedactedPathRef::new("@SOURCE/server").is_some());
    }
}
