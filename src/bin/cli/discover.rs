use std::path::PathBuf;

use agentshield::error::{Result, ShieldError};

use crate::discovery::{
    discover, registry, DiscoveryBase, DiscoveryEnvelope, DiscoveryRequest, ENTRY_STATES,
    MAX_AGGREGATE_BYTES, MAX_CANDIDATE_FILES_PER_INVOCATION, MAX_CANDIDATE_FILES_PER_ROOT,
    MAX_CONFIG_BYTES, MAX_DEPTH_PER_ROOT, MAX_DIRECTORIES_PER_INVOCATION, MAX_DIRECTORIES_PER_ROOT,
    MAX_ENTRIES_PER_INVOCATION, MAX_OPENED_CONFIGS_PER_INVOCATION, MAX_OPENED_CONFIGS_PER_ROOT,
};

pub(crate) fn cmd_discover(
    include_default_paths: bool,
    roots: Vec<PathBuf>,
    format: String,
    explain: bool,
) -> Result<i32> {
    let format = DiscoveryOutputFormat::parse(&format)?;
    let request = DiscoveryRequest {
        include_default_paths,
        effective_profile: effective_profile(),
        roots,
    };

    if explain {
        eprint!("{}", render_explanation(&request));
    }

    let envelope = discover(&request).map_err(ShieldError::Config)?;
    match format {
        DiscoveryOutputFormat::Console => print!("{}", render_console(&envelope)),
        DiscoveryOutputFormat::Json => println!("{}", serde_json::to_string_pretty(&envelope)?),
    }
    Ok(0)
}

fn effective_profile() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryOutputFormat {
    Console,
    Json,
}

impl DiscoveryOutputFormat {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "console" => Ok(Self::Console),
            "json" => Ok(Self::Json),
            _ => Err(ShieldError::Config(format!(
                "unsupported discovery format '{value}'; expected console or json"
            ))),
        }
    }
}

fn render_explanation(request: &DiscoveryRequest) -> String {
    let default_descriptors = registry()
        .iter()
        .filter(|descriptor| descriptor.base == DiscoveryBase::EffectiveProfile)
        .map(|descriptor| format!("  - ~/{}\n", descriptor.relative_path))
        .collect::<String>();
    let roots = request
        .roots
        .iter()
        .enumerate()
        .map(|(index, _)| format!("  - $ROOT[{index}]\n"))
        .collect::<String>();
    let entry_states = ENTRY_STATES
        .iter()
        .map(|state| state.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "Discovery plan (read-only; no scan or execution)\n\
         Default paths: {}\n{}\
         Explicit roots:\n{}\
         Limits: depth={MAX_DEPTH_PER_ROOT}, directories={MAX_DIRECTORIES_PER_ROOT}/root \
         and {MAX_DIRECTORIES_PER_INVOCATION}/invocation, candidates={MAX_CANDIDATE_FILES_PER_ROOT}/root \
         and {MAX_CANDIDATE_FILES_PER_INVOCATION}/invocation, opened={MAX_OPENED_CONFIGS_PER_ROOT}/root \
         and {MAX_OPENED_CONFIGS_PER_INVOCATION}/invocation, file_bytes={MAX_CONFIG_BYTES}, \
         aggregate_bytes={MAX_AGGREGATE_BYTES}, entries={MAX_ENTRIES_PER_INVOCATION}\n\
         Symlinks and special files are never followed or read. Platforms without an atomic \
         no-follow primitive fail closed.\n\
         Entry states: {entry_states}.\n",
        if request.include_default_paths {
            "enabled"
        } else {
            "disabled"
        },
        if request.include_default_paths {
            default_descriptors
        } else {
            String::new()
        },
        if roots.is_empty() {
            "  (none)\n".to_owned()
        } else {
            roots
        },
    )
}

fn render_console(envelope: &DiscoveryEnvelope) -> String {
    let mut output = format!(
        "AgentShield discovery: {} source(s), {} entry/entries, {} diagnostic(s)\n",
        envelope.summary.sources, envelope.summary.entries, envelope.summary.diagnostics
    );

    for source in &envelope.sources {
        output.push_str(&format!(
            "\n{} [{}] ({})\n",
            source.path_ref,
            source.client_id.as_str(),
            json_label(&source.status)
        ));
        for entry in envelope
            .entries
            .iter()
            .filter(|entry| entry.source_id == source.source_id)
        {
            output.push_str(&format!(
                "  - {}: {} ({})\n",
                entry.declared_name,
                json_label(&entry.state),
                json_label(&entry.support_status)
            ));
        }
        for diagnostic in envelope
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.source_id == source.source_id)
        {
            output.push_str(&format!("  ! {}\n", json_label(&diagnostic.code)));
        }
    }
    output
}

fn json_label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_format_is_an_invocation_error() {
        let error = DiscoveryOutputFormat::parse("sarif").expect_err("sarif is unsupported");
        assert!(error.to_string().contains("console or json"));
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn explanation_redacts_explicit_roots() {
        let request = DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![PathBuf::from("/Users/alice/private")],
        };
        let explanation = render_explanation(&request);
        assert!(explanation.contains("$ROOT[0]"));
        assert!(!explanation.contains("alice"));
        assert!(!explanation.contains("/Users"));
    }
}
