mod budget;
mod candidate;
mod safe_open;

use std::path::PathBuf;

use super::{
    DiagnosticCode, DiscoveryDescriptor, DiscoveryDiagnostic, DiscoveryEnvelope,
    ParsedDiscoverySource, RedactedPathRef, SourceStatus, build_envelope, parse_source, registry,
};

#[derive(Debug)]
pub(crate) struct DiscoveryRequest {
    pub include_default_paths: bool,
    pub effective_profile: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
}

pub(crate) fn discover(request: &DiscoveryRequest) -> Result<DiscoveryEnvelope, String> {
    platform::discover(request)
}

fn failed_source(
    descriptor: &DiscoveryDescriptor,
    path_ref: &RedactedPathRef,
    status: SourceStatus,
    code: Option<DiagnosticCode>,
) -> ParsedDiscoverySource {
    let mut parsed = parse_source(descriptor, path_ref, br#"{"mcpServers":{}}"#);
    parsed.source.status = status;
    parsed.entries.clear();
    parsed.diagnostics.clear();
    if let Some(code) = code {
        parsed.diagnostics.push(DiscoveryDiagnostic {
            code,
            source_id: parsed.source.source_id.clone(),
        });
    }
    parsed
}

#[cfg(unix)]
mod platform {
    use super::budget::DiscoveryBudget;
    use super::candidate::merge_opened;
    use super::safe_open::{
        inspect_descriptors, is_filesystem_root, open_root, validate_user_root_syntax,
    };
    use super::*;
    use crate::discovery::DiscoveryBase;

    pub(super) fn discover(request: &DiscoveryRequest) -> Result<DiscoveryEnvelope, String> {
        let mut parsed = Vec::new();
        let mut opened = Vec::new();
        let mut invocation_budget = DiscoveryBudget::default();
        let mut continue_discovery = true;

        if request.include_default_paths {
            if let Some(profile) = &request.effective_profile {
                match open_root(profile, "effective profile") {
                    Ok(root) => {
                        let mut profile_budget = DiscoveryBudget::default();
                        continue_discovery = inspect_descriptors(
                            &root,
                            DiscoveryBase::EffectiveProfile,
                            None,
                            &mut invocation_budget,
                            &mut profile_budget,
                            &mut opened,
                            &mut parsed,
                        )?;
                    }
                    Err(_) => {
                        for descriptor in registry()
                            .iter()
                            .filter(|descriptor| descriptor.base == DiscoveryBase::EffectiveProfile)
                        {
                            let path_ref = candidate::candidate_path_ref(descriptor, None);
                            parsed.push(failed_source(
                                descriptor,
                                &path_ref,
                                SourceStatus::UnsupportedFilesystemSafety,
                                Some(DiagnosticCode::UnsupportedFilesystemSafety),
                            ));
                        }
                    }
                }
            }
        }

        if continue_discovery {
            for (index, root_path) in request.roots.iter().enumerate() {
                validate_user_root_syntax(root_path, index)?;
                let root = open_root(root_path, &format!("root[{index}]"))
                    .map_err(|reason| format!("invalid root[{index}]: {reason}"))?;
                if is_filesystem_root(&root)? {
                    return Err(format!(
                        "invalid root[{index}]: filesystem root is not allowed"
                    ));
                }
                let mut root_budget = DiscoveryBudget::default();
                if !inspect_descriptors(
                    &root,
                    DiscoveryBase::ExplicitRoot,
                    Some(index),
                    &mut invocation_budget,
                    &mut root_budget,
                    &mut opened,
                    &mut parsed,
                )? {
                    break;
                }
            }
        }

        parsed.extend(merge_opened(opened));
        Ok(build_envelope(parsed))
    }

    #[cfg(test)]
    pub(super) fn open_candidate_with_hook_for_test(
        root_path: &std::path::Path,
        relative_path: &str,
        after_open: impl FnOnce(),
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let root = open_root(root_path, "test root").map_err(|_| "root")?;
        let mut aggregate_bytes = 0;
        match super::candidate::open_candidate_with_hook(
            &root,
            relative_path,
            &mut aggregate_bytes,
            after_open,
        ) {
            Ok(result) => Ok(result.map(|(_, bytes)| bytes)),
            Err(super::candidate::OpenFailure::Changed) => Err("changed"),
            Err(_) => Err("other"),
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use super::candidate::candidate_path_ref;
    use super::*;
    use std::path::Component;

    pub(super) fn discover(request: &DiscoveryRequest) -> Result<DiscoveryEnvelope, String> {
        for (index, root) in request.roots.iter().enumerate() {
            if root.as_os_str().is_empty()
                || root
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
            {
                return Err(format!("invalid root[{index}]: path is not allowed"));
            }
            let metadata = std::fs::symlink_metadata(root)
                .map_err(|_| format!("invalid root[{index}]: path is unavailable"))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "invalid root[{index}]: path is not a regular directory"
                ));
            }
            if root.parent().is_none() {
                return Err(format!(
                    "invalid root[{index}]: filesystem root is not allowed"
                ));
            }
        }

        let mut parsed = Vec::new();
        for descriptor in registry() {
            let root_indices: Vec<Option<usize>> = match descriptor.base {
                DiscoveryBase::EffectiveProfile
                    if request.include_default_paths && request.effective_profile.is_some() =>
                {
                    vec![None]
                }
                DiscoveryBase::ExplicitRoot => (0..request.roots.len()).map(Some).collect(),
                _ => Vec::new(),
            };
            for root_index in root_indices {
                let path_ref = candidate_path_ref(descriptor, root_index);
                parsed.push(failed_source(
                    descriptor,
                    &path_ref,
                    SourceStatus::UnsupportedFilesystemSafety,
                    Some(DiagnosticCode::UnsupportedFilesystemSafety),
                ));
            }
        }
        Ok(build_envelope(parsed))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryMethod;

    #[cfg(unix)]
    #[test]
    fn registry_paths_are_strict_relative_paths() {
        for descriptor in registry() {
            assert!(
                super::candidate::validate_relative_registry_path(descriptor.relative_path).is_ok()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_root_reads_only_allowlisted_regular_files() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(directory.path().join(".cursor")).expect("cursor dir");
        std::fs::write(
            directory.path().join(".cursor/mcp.json"),
            br#"{"mcpServers":{"tools":{"command":"node","env":{"TOKEN":"secret"}}}}"#,
        )
        .expect("fixture");
        std::fs::write(directory.path().join("not-allowlisted.json"), b"secret").expect("decoy");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![directory.path().canonicalize().expect("canonical tempdir")],
        })
        .expect("discovery");

        assert_eq!(envelope.summary.sources, 1);
        assert_eq!(envelope.summary.entries, 1);
        let serialized = serde_json::to_string(&envelope).expect("serialize");
        assert!(!serialized.contains("TOKEN"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains(directory.path().to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_root_rejects_symlink_component() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(
            outside.path().join("mcp.json"),
            br#"{"mcpServers":{"tools":{"command":"node"}}}"#,
        )
        .expect("fixture");
        symlink(outside.path(), directory.path().join(".cursor")).expect("symlink");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![directory.path().canonicalize().expect("canonical tempdir")],
        })
        .expect("discovery");

        assert!(envelope.entries.is_empty());
        assert!(envelope.sources.iter().any(|source| {
            source.status == SourceStatus::UnsupportedFilesystemSafety
                && source.path_ref == "$ROOT[0]/.cursor/mcp.json"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_config_is_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(
            outside.path().join("config.json"),
            br#"{"mcpServers":{"secret":{"command":"do-not-read"}}}"#,
        )
        .expect("outside config");
        symlink(
            outside.path().join("config.json"),
            directory.path().join(".mcp.json"),
        )
        .expect("symlink");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![directory.path().canonicalize().expect("canonical tempdir")],
        })
        .expect("discovery");
        let serialized = serde_json::to_string(&envelope).expect("serialize");

        assert!(envelope.entries.is_empty());
        assert!(envelope.sources.iter().any(|source| {
            source.status == SourceStatus::UnsupportedFilesystemSafety
                && source.path_ref == "$ROOT[0]/.mcp.json"
        }));
        assert!(!serialized.contains("do-not-read"));
        assert!(!serialized.contains("secret"));
    }

    #[cfg(unix)]
    #[test]
    fn special_file_at_config_path_is_not_read() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(directory.path().join(".mcp.json")).expect("directory decoy");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![directory.path().canonicalize().expect("canonical tempdir")],
        })
        .expect("discovery");

        assert!(envelope.entries.is_empty());
        assert!(envelope.sources.iter().any(|source| {
            source.status == SourceStatus::Unsupported && source.path_ref == "$ROOT[0]/.mcp.json"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn write_during_read_is_reported_as_changed() {
        use std::io::Write;

        let directory = tempfile::tempdir().expect("tempdir");
        let config = directory.path().join(".mcp.json");
        std::fs::write(&config, br#"{"mcpServers":{"tools":{"command":"node"}}}"#).expect("config");
        let root = directory.path().canonicalize().expect("canonical root");

        let result = platform::open_candidate_with_hook_for_test(&root, ".mcp.json", || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&config)
                .expect("open config for concurrent write");
            file.write_all(b" ").expect("concurrent write");
        });

        assert_eq!(result.expect_err("change must be detected"), "changed");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_swap_after_open_never_changes_the_opened_content() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        let config = directory.path().join(".mcp.json");
        let moved = directory.path().join("opened.json");
        let benign = br#"{"mcpServers":{"benign":{"command":"node"}}}"#;
        std::fs::write(&config, benign).expect("config");
        std::fs::write(
            outside.path().join("target.json"),
            br#"{"mcpServers":{"secret":{"command":"do-not-read"}}}"#,
        )
        .expect("outside config");
        let root = directory.path().canonicalize().expect("canonical root");

        let result = platform::open_candidate_with_hook_for_test(&root, ".mcp.json", || {
            std::fs::rename(&config, &moved).expect("rename opened file");
            symlink(outside.path().join("target.json"), &config).expect("replacement symlink");
        });

        match result {
            Ok(Some(bytes)) => assert_eq!(bytes, benign),
            Err("changed") => {}
            other => panic!("unexpected swap result: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_root_itself_cannot_be_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let link_parent = tempfile::tempdir().expect("link parent");
        let link = link_parent
            .path()
            .canonicalize()
            .expect("canonical link parent")
            .join("root");
        symlink(directory.path(), &link).expect("symlink");

        let error = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![link],
        })
        .expect_err("symlink root must fail");
        assert!(error.contains("root[0]"));
        assert!(!error.contains(directory.path().to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn no_default_paths_does_not_read_home() {
        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: Vec::new(),
        })
        .expect("discovery");
        assert!(envelope.sources.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn known_and_explicit_observations_of_same_file_are_deduplicated() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(directory.path().join(".cursor")).expect("cursor dir");
        std::fs::write(
            directory.path().join(".cursor/mcp.json"),
            br#"{"mcpServers":{"tools":{"command":"node"}}}"#,
        )
        .expect("fixture");
        let root = directory.path().canonicalize().expect("canonical root");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: true,
            effective_profile: Some(root.clone()),
            roots: vec![root],
        })
        .expect("discovery");

        assert_eq!(envelope.summary.sources, 1);
        assert_eq!(envelope.sources[0].path_ref, "~/.cursor/mcp.json");
        assert_eq!(envelope.sources[0].provenance.len(), 2);
        assert_eq!(
            envelope.sources[0].provenance[0].discovery_method,
            DiscoveryMethod::KnownPath
        );
        assert_eq!(
            envelope.sources[0].provenance[1].discovery_method,
            DiscoveryMethod::ExplicitRoot
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_source_does_not_remove_valid_source() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(directory.path().join(".cursor")).expect("cursor dir");
        std::fs::create_dir(directory.path().join(".vscode")).expect("vscode dir");
        std::fs::write(directory.path().join(".cursor/mcp.json"), b"{secret")
            .expect("malformed fixture");
        std::fs::write(
            directory.path().join(".vscode/mcp.json"),
            br#"{"servers":{"docs":{"url":"https://example.test"}}}"#,
        )
        .expect("valid fixture");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![directory.path().canonicalize().expect("canonical root")],
        })
        .expect("discovery");

        assert_eq!(envelope.summary.sources, 2);
        assert_eq!(envelope.summary.entries, 1);
        assert!(
            envelope
                .sources
                .iter()
                .any(|source| source.status == SourceStatus::Malformed)
        );
        let serialized = serde_json::to_string(&envelope).expect("serialize");
        assert!(!serialized.contains("secret"));
    }

    #[cfg(unix)]
    #[test]
    fn repeated_roots_stop_with_one_bounded_limit_diagnostic() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical root");

        let envelope = discover(&DiscoveryRequest {
            include_default_paths: false,
            effective_profile: None,
            roots: vec![root; 300],
        })
        .expect("discovery");

        assert_eq!(envelope.summary.sources, 1);
        assert_eq!(envelope.summary.diagnostics, 1);
        assert_eq!(envelope.sources[0].status, SourceStatus::LimitReached);
        assert_eq!(envelope.diagnostics[0].code, DiagnosticCode::LimitReached);
        assert_eq!(
            envelope.sources[0].path_ref,
            format!(
                "$ROOT[{}]/.cursor/mcp.json",
                crate::discovery::MAX_DIRECTORIES_PER_INVOCATION / 2
            )
        );
    }
}
