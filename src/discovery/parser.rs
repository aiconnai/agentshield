use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::types::{
    ConfigFormat, DiagnosticCode, DiscoveryBase, DiscoveryDescriptor, DiscoveryEntry,
    DiscoveryMethod, DiscoverySource, EntryState, ParsedDiscoverySource, ProvenanceObservation,
    RedactedPathRef, SourceStatus, SupportStatus, MAX_CONFIG_BYTES, MAX_DECLARED_NAME_BYTES,
    MAX_ENTRIES_PER_INVOCATION,
};

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

pub(crate) fn stable_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}
