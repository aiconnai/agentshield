use super::types::{
    DiagnosticCode, DiscoveryEnvelope, DiscoverySummary, ParsedDiscoverySource, SourceStatus,
    MAX_ENTRIES_PER_INVOCATION, REGISTRY_VERSION,
};

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
