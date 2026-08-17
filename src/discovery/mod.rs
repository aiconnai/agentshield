//! Binary-private registry, filesystem boundary, and structural parsers for
//! local client discovery.

pub(crate) mod envelope;
#[path = "filesystem/mod.rs"]
pub(crate) mod filesystem;
pub(crate) mod parser;
pub(crate) mod registry;
pub(crate) mod types;

pub(crate) use envelope::build_envelope;
pub(crate) use filesystem::{discover, DiscoveryRequest};
pub(crate) use parser::parse_source;
pub(crate) use registry::registry;
pub(crate) use types::*;

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
        assert!(
            envelope
                .sources
                .iter()
                .any(|source| source.status == SourceStatus::LimitReached)
        );
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
