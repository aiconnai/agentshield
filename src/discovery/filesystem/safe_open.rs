#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::io::OwnedFd;
#[cfg(unix)]
use std::path::Component;
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, open, openat};

#[cfg(unix)]
use super::budget::DiscoveryBudget;
#[cfg(unix)]
use super::candidate::candidate_path_ref;
#[cfg(unix)]
use super::candidate::validate_relative_registry_path;
#[cfg(unix)]
use super::candidate::{Candidate, OpenFailure, OpenedCandidate, open_candidate};
#[cfg(unix)]
use super::failed_source;
#[cfg(unix)]
use crate::discovery::{
    DiagnosticCode, DiscoveryBase, DiscoveryMethod, MAX_CANDIDATE_FILES_PER_INVOCATION,
    MAX_CANDIDATE_FILES_PER_ROOT, MAX_OPENED_CONFIGS_PER_INVOCATION, MAX_OPENED_CONFIGS_PER_ROOT,
    ParsedDiscoverySource, SourceStatus, registry,
};

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
}

#[cfg(unix)]
pub(super) fn metadata_signature(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u64, i64, i64, i64, i64) {
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

#[cfg(unix)]
pub(super) fn identity_for_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
pub(super) const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[cfg(unix)]
pub(super) const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);

#[cfg(unix)]
pub(super) fn is_filesystem_root(root: &OwnedFd) -> Result<bool, String> {
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

#[cfg(unix)]
pub(super) fn open_root(path: &Path, label: &str) -> Result<OwnedFd, String> {
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

#[cfg(unix)]
pub(super) fn inspect_descriptors<'a>(
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
        let limit_reached = invocation_budget.candidate_files >= MAX_CANDIDATE_FILES_PER_INVOCATION
            || root_budget.candidate_files >= MAX_CANDIDATE_FILES_PER_ROOT
            || invocation_budget.opened_configs >= MAX_OPENED_CONFIGS_PER_INVOCATION
            || root_budget.opened_configs >= MAX_OPENED_CONFIGS_PER_ROOT
            || invocation_budget
                .directories
                .saturating_add(directory_count)
                > crate::discovery::MAX_DIRECTORIES_PER_INVOCATION
            || root_budget.directories.saturating_add(directory_count)
                > crate::discovery::MAX_DIRECTORIES_PER_ROOT;
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

#[cfg(unix)]
pub(super) fn validate_user_root_syntax(path: &Path, index: usize) -> Result<(), String> {
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
