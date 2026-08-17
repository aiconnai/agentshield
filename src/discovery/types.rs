use serde::Serialize;

use super::registry::valid_path_ref_prefix;

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
pub(crate) const MAX_DECLARED_NAME_BYTES: usize = 256;
pub(crate) const MAX_PATH_REF_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClientId {
    ClaudeCode,
    Cursor,
    VsCode,
}

impl ClientId {
    pub(crate) fn as_str(self) -> &'static str {
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
    pub(crate) fn as_str(self) -> &'static str {
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

pub(crate) const SOURCE_STATUSES: &[SourceStatus] = &[
    SourceStatus::Inspected,
    SourceStatus::Unsupported,
    SourceStatus::Malformed,
    SourceStatus::PermissionDenied,
    SourceStatus::LimitReached,
    SourceStatus::UnsupportedFilesystemSafety,
    SourceStatus::ChangeDetectedDuringRead,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntryState {
    Configured,
    Disabled,
    Unresolved,
    LocalReference,
}

impl EntryState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Disabled => "disabled",
            Self::Unresolved => "unresolved",
            Self::LocalReference => "local_reference",
        }
    }
}

pub(crate) const ENTRY_STATES: &[EntryState] = &[
    EntryState::Configured,
    EntryState::Disabled,
    EntryState::Unresolved,
    EntryState::LocalReference,
];

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
    LimitReached,
    ConfigSizeLimitReached,
    PermissionDenied,
    UnsupportedFilesystemSafety,
    ChangeDetectedDuringRead,
}

pub(crate) const DIAGNOSTIC_CODES: &[DiagnosticCode] = &[
    DiagnosticCode::InvalidJson,
    DiagnosticCode::MissingServerMap,
    DiagnosticCode::ServerMapNotObject,
    DiagnosticCode::EntryNotObject,
    DiagnosticCode::EntryNameTooLong,
    DiagnosticCode::EntryNameInvalid,
    DiagnosticCode::EntryLimitReached,
    DiagnosticCode::LimitReached,
    DiagnosticCode::ConfigSizeLimitReached,
    DiagnosticCode::PermissionDenied,
    DiagnosticCode::UnsupportedFilesystemSafety,
    DiagnosticCode::ChangeDetectedDuringRead,
];

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

    pub(crate) fn as_str(&self) -> &str {
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

impl ParsedDiscoverySource {
    pub(crate) fn push_diagnostic(&mut self, code: DiagnosticCode) {
        self.diagnostics.push(DiscoveryDiagnostic {
            code,
            source_id: self.source.source_id.clone(),
        });
    }
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
