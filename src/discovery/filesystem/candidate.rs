use crate::discovery::{
    DiagnosticCode, DiscoveryDescriptor, DiscoveryMethod, ParsedDiscoverySource, RedactedPathRef,
    SourceStatus, parse_source,
};

#[cfg(unix)]
use rustix::fs::{Mode, openat};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::OwnedFd;
#[cfg(unix)]
use std::path::{Component, Path};

#[cfg(unix)]
use super::failed_source;
#[cfg(unix)]
use super::safe_open::{FileIdentity, identity_for_metadata, metadata_signature};
#[cfg(unix)]
use crate::discovery::{MAX_AGGREGATE_BYTES, ProvenanceObservation};

#[cfg(unix)]
#[derive(Debug)]
pub(super) struct Candidate<'a> {
    pub(super) descriptor: &'a DiscoveryDescriptor,
    pub(super) path_ref: RedactedPathRef,
    pub(super) method: DiscoveryMethod,
    pub(super) root_index: Option<usize>,
}

#[cfg(unix)]
#[derive(Debug)]
pub(super) struct OpenedCandidate<'a> {
    pub(super) candidate: Candidate<'a>,
    pub(super) identity: FileIdentity,
    pub(super) bytes: Vec<u8>,
}

#[cfg(unix)]
pub(super) enum OpenFailure {
    PermissionDenied,
    Unsupported,
    UnsafeFilesystem,
    Changed,
    ConfigLimitReached,
    InvocationLimitReached,
}

#[cfg(unix)]
pub(super) fn open_candidate(
    root: &OwnedFd,
    relative_path: &str,
    aggregate_bytes: &mut usize,
) -> Result<Option<(FileIdentity, Vec<u8>)>, OpenFailure> {
    open_candidate_with_hook(root, relative_path, aggregate_bytes, || {})
}

#[cfg(unix)]
pub(super) fn open_candidate_with_hook(
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
        current = match openat(
            &current,
            *component,
            super::safe_open::DIR_FLAGS,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::ACCESS | Errno::PERM) => return Err(OpenFailure::PermissionDenied),
            Err(_) => return Err(OpenFailure::UnsafeFilesystem),
        };
    }

    let fd = match openat(
        &current,
        components[components.len() - 1],
        super::safe_open::FILE_FLAGS,
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
    if before.len() > crate::discovery::MAX_CONFIG_BYTES as u64 {
        return Err(OpenFailure::ConfigLimitReached);
    }
    if *aggregate_bytes >= MAX_AGGREGATE_BYTES {
        return Err(OpenFailure::InvocationLimitReached);
    }
    after_open();
    let available = MAX_AGGREGATE_BYTES - *aggregate_bytes;
    let read_limit = (crate::discovery::MAX_CONFIG_BYTES + 1).min(available.saturating_add(1));
    let mut bytes = Vec::with_capacity((before.len() as usize).min(read_limit));
    file.by_ref()
        .take(read_limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| OpenFailure::Changed)?;
    if bytes.len() > crate::discovery::MAX_CONFIG_BYTES || bytes.len() > available {
        return Err(if bytes.len() > crate::discovery::MAX_CONFIG_BYTES {
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

#[cfg(unix)]
pub(super) fn merge_opened(opened: Vec<OpenedCandidate<'_>>) -> Vec<ParsedDiscoverySource> {
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

pub(super) fn candidate_path_ref(
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
pub(super) fn validate_relative_registry_path(path: &str) -> Result<Vec<&str>, String> {
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
