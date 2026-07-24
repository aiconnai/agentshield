#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::Path;
use std::path::{Component, PathBuf};

use super::{
    build_envelope, parse_source, registry, DiagnosticCode, DiscoveryBase, DiscoveryDescriptor,
    DiscoveryDiagnostic, DiscoveryEnvelope, ParsedDiscoverySource, RedactedPathRef, SourceStatus,
};
#[cfg(unix)]
use super::{
    DiscoveryMethod, ProvenanceObservation, MAX_AGGREGATE_BYTES,
    MAX_CANDIDATE_FILES_PER_INVOCATION, MAX_CANDIDATE_FILES_PER_ROOT,
    MAX_OPENED_CONFIGS_PER_INVOCATION, MAX_OPENED_CONFIGS_PER_ROOT,
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

#[cfg(unix)]
#[derive(Debug)]
struct Candidate<'a> {
    descriptor: &'a DiscoveryDescriptor,
    path_ref: RedactedPathRef,
    method: DiscoveryMethod,
    root_index: Option<usize>,
}

#[cfg(unix)]
#[derive(Debug)]
struct OpenedCandidate<'a> {
    candidate: Candidate<'a>,
    identity: FileIdentity,
    bytes: Vec<u8>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct DiscoveryBudget {
    directories: usize,
    candidate_files: usize,
    opened_configs: usize,
    bytes: usize,
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
fn merge_opened(opened: Vec<OpenedCandidate<'_>>) -> Vec<ParsedDiscoverySource> {
    let mut by_identity: BTreeMap<FileIdentity, Vec<OpenedCandidate<'_>>> = BTreeMap::new();
    for candidate in opened {
        by_identity
            .entry(candidate.identity)
            .or_default()
            .push(candidate);
    }

    by_identity
        .into_values()
        .map(|mut observations| {
            observations.sort_by_key(|opened| {
                (
                    opened.candidate.method,
                    opened.candidate.root_index,
                    opened.candidate.descriptor.id,
                )
            });
            let primary = &observations[0];
            if observations
                .iter()
                .skip(1)
                .any(|observation| observation.bytes != primary.bytes)
            {
                let mut changed = failed_source(
                    primary.candidate.descriptor,
                    &primary.candidate.path_ref,
                    SourceStatus::ChangeDetectedDuringRead,
                    Some(DiagnosticCode::ChangeDetectedDuringRead),
                );
                changed.source.provenance = observations
                    .iter()
                    .map(|opened| ProvenanceObservation {
                        descriptor_id: opened.candidate.descriptor.id,
                        discovery_method: opened.candidate.method,
                        path_ref: opened.candidate.path_ref.as_str().to_owned(),
                    })
                    .collect();
                return changed;
            }
            let mut parsed = parse_source(
                primary.candidate.descriptor,
                &primary.candidate.path_ref,
                &primary.bytes,
            );
            parsed.source.provenance = observations
                .iter()
                .map(|opened| ProvenanceObservation {
                    descriptor_id: opened.candidate.descriptor.id,
                    discovery_method: opened.candidate.method,
                    path_ref: opened.candidate.path_ref.as_str().to_owned(),
                })
                .collect();
            parsed
        })
        .collect()
}

fn candidate_path_ref(
    descriptor: &DiscoveryDescriptor,
    root_index: Option<usize>,
) -> RedactedPathRef {
    let value = match root_index {
        Some(index) => format!("$ROOT[{index}]/{}", descriptor.relative_path),
        None => format!("~/{}", descriptor.relative_path),
    };
    RedactedPathRef::new(value).expect("registry paths always produce redacted references")
}

#[cfg(unix)]
fn validate_relative_registry_path(path: &str) -> Result<Vec<&str>, String> {
    let components = Path::new(path)
        .components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .ok_or_else(|| "registry path is not valid UTF-8".to_owned()),
            _ => Err("registry path is not a strict relative path".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err("registry path is empty".to_owned());
    }
    Ok(components)
}

#[cfg(unix)]
mod platform {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::OwnedFd;

    use rustix::fs::{open, openat, Mode, OFlags};
    use rustix::io::Errno;

    use super::*;

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK);

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
                            let path_ref = candidate_path_ref(descriptor, None);
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

    fn inspect_descriptors<'a>(
        root: &OwnedFd,
        base: DiscoveryBase,
        root_index: Option<usize>,
        invocation_budget: &mut DiscoveryBudget,
        root_budget: &mut DiscoveryBudget,
        opened: &mut Vec<OpenedCandidate<'a>>,
        parsed: &mut Vec<ParsedDiscoverySource>,
    ) -> Result<bool, String> {
        for descriptor in registry()
            .iter()
            .filter(|descriptor| descriptor.base == base)
        {
            let directory_count = validate_relative_registry_path(descriptor.relative_path)?
                .len()
                .saturating_sub(1);
            let limit_reached = invocation_budget.candidate_files
                >= MAX_CANDIDATE_FILES_PER_INVOCATION
                || root_budget.candidate_files >= MAX_CANDIDATE_FILES_PER_ROOT
                || invocation_budget.opened_configs >= MAX_OPENED_CONFIGS_PER_INVOCATION
                || root_budget.opened_configs >= MAX_OPENED_CONFIGS_PER_ROOT
                || invocation_budget
                    .directories
                    .saturating_add(directory_count)
                    > super::super::MAX_DIRECTORIES_PER_INVOCATION
                || root_budget.directories.saturating_add(directory_count)
                    > super::super::MAX_DIRECTORIES_PER_ROOT;
            if limit_reached {
                let path_ref = candidate_path_ref(descriptor, root_index);
                parsed.push(failed_source(
                    descriptor,
                    &path_ref,
                    SourceStatus::LimitReached,
                    Some(DiagnosticCode::LimitReached),
                ));
                return Ok(false);
            }
            invocation_budget.candidate_files += 1;
            root_budget.candidate_files += 1;
            invocation_budget.directories += directory_count;
            root_budget.directories += directory_count;

            let path_ref = candidate_path_ref(descriptor, root_index);
            let candidate = Candidate {
                descriptor,
                path_ref,
                method: if root_index.is_some() {
                    DiscoveryMethod::ExplicitRoot
                } else {
                    DiscoveryMethod::KnownPath
                },
                root_index,
            };
            match open_candidate(root, descriptor.relative_path, &mut invocation_budget.bytes) {
                Ok(Some((identity, bytes))) => {
                    invocation_budget.opened_configs += 1;
                    root_budget.opened_configs += 1;
                    opened.push(OpenedCandidate {
                        candidate,
                        identity,
                        bytes,
                    });
                }
                Ok(None) => {}
                Err(OpenFailure::PermissionDenied) => parsed.push(failed_source(
                    descriptor,
                    &candidate.path_ref,
                    SourceStatus::PermissionDenied,
                    Some(DiagnosticCode::PermissionDenied),
                )),
                Err(OpenFailure::Unsupported) => parsed.push(failed_source(
                    descriptor,
                    &candidate.path_ref,
                    SourceStatus::Unsupported,
                    None,
                )),
                Err(OpenFailure::UnsafeFilesystem) => parsed.push(failed_source(
                    descriptor,
                    &candidate.path_ref,
                    SourceStatus::UnsupportedFilesystemSafety,
                    Some(DiagnosticCode::UnsupportedFilesystemSafety),
                )),
                Err(OpenFailure::Changed) => parsed.push(failed_source(
                    descriptor,
                    &candidate.path_ref,
                    SourceStatus::ChangeDetectedDuringRead,
                    Some(DiagnosticCode::ChangeDetectedDuringRead),
                )),
                Err(OpenFailure::ConfigLimitReached) => parsed.push(failed_source(
                    descriptor,
                    &candidate.path_ref,
                    SourceStatus::LimitReached,
                    Some(DiagnosticCode::ConfigSizeLimitReached),
                )),
                Err(OpenFailure::InvocationLimitReached) => {
                    parsed.push(failed_source(
                        descriptor,
                        &candidate.path_ref,
                        SourceStatus::LimitReached,
                        Some(DiagnosticCode::LimitReached),
                    ));
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn validate_user_root_syntax(path: &Path, index: usize) -> Result<(), String> {
        if path.as_os_str().is_empty() {
            return Err(format!("invalid root[{index}]: path is empty"));
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(format!(
                "invalid root[{index}]: parent components are not allowed"
            ));
        }
        Ok(())
    }

    fn open_root(path: &Path, label: &str) -> Result<OwnedFd, String> {
        let (mut current, components) = if path.is_absolute() {
            (
                open("/", DIR_FLAGS, Mode::empty())
                    .map_err(|_| format!("{label} cannot be opened safely"))?,
                path.components().skip(1).collect::<Vec<_>>(),
            )
        } else {
            (
                open(".", DIR_FLAGS, Mode::empty())
                    .map_err(|_| format!("{label} cannot be opened safely"))?,
                path.components().collect::<Vec<_>>(),
            )
        };

        for component in components {
            match component {
                Component::CurDir => {}
                Component::Normal(name) => {
                    current = openat(&current, name, DIR_FLAGS, Mode::empty())
                        .map_err(|_| format!("{label} is missing, inaccessible, or unsafe"))?;
                }
                _ => return Err(format!("{label} contains an unsupported path component")),
            }
        }
        Ok(current)
    }

    fn is_filesystem_root(root: &OwnedFd) -> Result<bool, String> {
        let parent = openat(root, "..", DIR_FLAGS, Mode::empty())
            .map_err(|_| "root parent cannot be opened safely".to_owned())?;
        Ok(identity_for_metadata(
            &File::from(parent)
                .metadata()
                .map_err(|_| "root parent metadata is unavailable".to_owned())?,
        ) == identity_for_metadata(
            &File::from(
                root.try_clone()
                    .map_err(|_| "root handle cannot be cloned".to_owned())?,
            )
            .metadata()
            .map_err(|_| "root metadata is unavailable".to_owned())?,
        ))
    }

    fn open_candidate(
        root: &OwnedFd,
        relative_path: &str,
        aggregate_bytes: &mut usize,
    ) -> Result<Option<(FileIdentity, Vec<u8>)>, OpenFailure> {
        open_candidate_with_hook(root, relative_path, aggregate_bytes, || {})
    }

    fn open_candidate_with_hook(
        root: &OwnedFd,
        relative_path: &str,
        aggregate_bytes: &mut usize,
        after_open: impl FnOnce(),
    ) -> Result<Option<(FileIdentity, Vec<u8>)>, OpenFailure> {
        let components = validate_relative_registry_path(relative_path)
            .map_err(|_| OpenFailure::UnsafeFilesystem)?;
        let mut current = root
            .try_clone()
            .map_err(|_| OpenFailure::UnsafeFilesystem)?;
        for component in &components[..components.len() - 1] {
            current = match openat(&current, *component, DIR_FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                Err(Errno::ACCESS | Errno::PERM) => return Err(OpenFailure::PermissionDenied),
                Err(_) => return Err(OpenFailure::UnsafeFilesystem),
            };
        }

        let fd = match openat(
            &current,
            components[components.len() - 1],
            FILE_FLAGS,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::ACCESS | Errno::PERM) => return Err(OpenFailure::PermissionDenied),
            Err(_) => return Err(OpenFailure::UnsafeFilesystem),
        };
        let mut file = File::from(fd);
        let before = file.metadata().map_err(|_| OpenFailure::UnsafeFilesystem)?;
        if !before.file_type().is_file() {
            return Err(OpenFailure::Unsupported);
        }
        if before.len() > super::super::MAX_CONFIG_BYTES as u64 {
            return Err(OpenFailure::ConfigLimitReached);
        }
        if *aggregate_bytes >= MAX_AGGREGATE_BYTES {
            return Err(OpenFailure::InvocationLimitReached);
        }
        after_open();
        let available = MAX_AGGREGATE_BYTES - *aggregate_bytes;
        let read_limit = (super::super::MAX_CONFIG_BYTES + 1).min(available.saturating_add(1));
        let mut bytes = Vec::with_capacity((before.len() as usize).min(read_limit));
        file.by_ref()
            .take(read_limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| OpenFailure::Changed)?;
        if bytes.len() > super::super::MAX_CONFIG_BYTES || bytes.len() > available {
            return Err(if bytes.len() > super::super::MAX_CONFIG_BYTES {
                OpenFailure::ConfigLimitReached
            } else {
                OpenFailure::InvocationLimitReached
            });
        }
        let after = file.metadata().map_err(|_| OpenFailure::Changed)?;
        if metadata_signature(&before) != metadata_signature(&after) {
            return Err(OpenFailure::Changed);
        }
        *aggregate_bytes += bytes.len();
        Ok(Some((identity_for_metadata(&after), bytes)))
    }

    #[cfg(test)]
    pub(super) fn open_candidate_with_hook_for_test(
        root_path: &Path,
        relative_path: &str,
        after_open: impl FnOnce(),
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let root = open_root(root_path, "test root").map_err(|_| "root")?;
        let mut aggregate_bytes = 0;
        match open_candidate_with_hook(&root, relative_path, &mut aggregate_bytes, after_open) {
            Ok(result) => Ok(result.map(|(_, bytes)| bytes)),
            Err(OpenFailure::Changed) => Err("changed"),
            Err(_) => Err("other"),
        }
    }

    fn identity_for_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn metadata_signature(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    }

    enum OpenFailure {
        PermissionDenied,
        Unsupported,
        UnsafeFilesystem,
        Changed,
        ConfigLimitReached,
        InvocationLimitReached,
    }
}

#[cfg(not(unix))]
mod platform {
    use super::*;

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

    #[cfg(unix)]
    #[test]
    fn registry_paths_are_strict_relative_paths() {
        for descriptor in registry() {
            assert!(validate_relative_registry_path(descriptor.relative_path).is_ok());
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
        assert!(envelope
            .sources
            .iter()
            .any(|source| source.status == SourceStatus::Malformed));
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
                super::super::MAX_DIRECTORIES_PER_INVOCATION / 2
            )
        );
    }
}
