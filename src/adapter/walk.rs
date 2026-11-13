//! File-walk policy shared by every adapter.
//!
//! The scanned tree is untrusted input: a package must not be able to hide a
//! payload from the scan with an ignore file, a look-alike tooling directory,
//! deep nesting or an oversized file. This module owns the one policy.
//!
//! * Ignore files (`.gitignore`, `.ignore`, the global gitignore,
//!   `.git/info/exclude`, parent repositories) are never honoured, and hidden
//!   entries are walked.
//! * A directory is pruned only when it demonstrably is a dependency, build or
//!   tooling directory (see [`PRUNED_DIRS`]); everything else is walked.
//! * Files up to [`MAX_SOURCE_FILE_BYTES`] are read whole; larger files are
//!   read up to the cap. Anything pruned, truncated or unreadable is recorded
//!   in the scan's [`CoverageRecorder`] instead of being dropped silently.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::config::ScanPathFilter;
use crate::coverage::{CoverageReason, CoverageRecorder};
use crate::ir::{Language, SourceFile};

/// Largest number of bytes read from one source file (8 MiB). Larger files are
/// scanned up to this size and reported as truncated.
pub(crate) const MAX_SOURCE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Deepest directory level walked. Symlinks are not followed, so loops cannot
/// occur; this only bounds pathological trees, and reaching it is reported.
pub(crate) const MAX_SOURCE_WALK_DEPTH: usize = 512;

/// A directory the walker prunes, with the evidence it must show first.
pub(crate) struct PrunedDir {
    name: &'static str,
    /// The directory is pruned only if at least one marker is present.
    /// `"x"` is a direct child named `x`; `"*/x"` is `x` inside any child
    /// directory; `"*.ext"` is any child whose name ends with `.ext`.
    markers: &'static [&'static str],
    /// Prune without a marker when the directory is a direct child of the
    /// scan root (the package's own dependencies).
    root_child_always: bool,
}

/// Directories pruned from the walk. This is the single list to edit.
///
/// Trade-off: an ignore file is attacker-controlled, so it cannot decide what
/// is scanned; but without it the walker would descend into dependency and
/// build trees (thousands of files, thousands of findings, a several-fold
/// slowdown). A name alone is also attacker-controlled (`.venv/payload.py`
/// run through `runpy` by a visible `server.py`), so a directory is pruned
/// only when it carries the marker the real tool leaves behind, and every
/// pruned directory is listed in the report's coverage. Markers can be forged,
/// which is why pruning is visible rather than silent.
///
/// `dist` and `build` are deliberately absent: compiled output is how many npm
/// MCP servers are distributed, so pruning them would blind the scanner to the
/// published code. Exclude them with `[scan] exclude = ["dist/**"]` when they
/// are generated from sources that are scanned directly.
pub(crate) const PRUNED_DIRS: &[PrunedDir] = &[
    PrunedDir {
        name: ".git",
        markers: &["HEAD"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".venv",
        markers: &["pyvenv.cfg"],
        root_child_always: false,
    },
    PrunedDir {
        name: "venv",
        markers: &["pyvenv.cfg"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".tox",
        markers: &["*/pyvenv.cfg"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".nox",
        markers: &["*/pyvenv.cfg"],
        root_child_always: false,
    },
    PrunedDir {
        name: "site-packages",
        markers: &["*.dist-info", "*.egg-info"],
        root_child_always: false,
    },
    PrunedDir {
        name: "__pycache__",
        markers: &["*.pyc", "*.pyo"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".mypy_cache",
        markers: &["CACHEDIR.TAG"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".pytest_cache",
        markers: &["CACHEDIR.TAG"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".ruff_cache",
        markers: &["CACHEDIR.TAG"],
        root_child_always: false,
    },
    PrunedDir {
        name: "node_modules",
        markers: &[
            ".package-lock.json",
            ".yarn-integrity",
            ".modules.yaml",
            ".bin",
        ],
        root_child_always: true,
    },
    PrunedDir {
        name: "target",
        markers: &["CACHEDIR.TAG", ".rustc_info.json"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".next",
        markers: &["BUILD_ID", "build-manifest.json", "cache", "trace"],
        root_child_always: false,
    },
    PrunedDir {
        name: ".turbo",
        markers: &["cache", "daemon"],
        root_child_always: false,
    },
];

/// Walker for framework detection and other walks that do not report coverage.
pub(crate) fn source_walker(root: &Path) -> ignore::Walk {
    build_walker(root, None)
}

/// Walker that also honours `[scan] exclude` directory patterns and records
/// pruned directories and depth-limit hits in the filter's coverage log.
/// `scan_root` is the root the filter's patterns are relative to.
pub(crate) fn source_walker_for(
    walk_root: &Path,
    scan_root: &Path,
    filter: &ScanPathFilter,
) -> ignore::Walk {
    build_walker(walk_root, Some((scan_root.to_path_buf(), filter.clone())))
}

fn build_walker(root: &Path, scoped: Option<(PathBuf, ScanPathFilter)>) -> ignore::Walk {
    ignore::WalkBuilder::new(root)
        .hidden(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .require_git(false)
        .follow_links(false)
        .max_depth(Some(MAX_SOURCE_WALK_DEPTH))
        .filter_entry(move |entry| {
            let is_dir = entry.file_type().is_some_and(|kind| kind.is_dir());
            if is_dir && entry.depth() >= MAX_SOURCE_WALK_DEPTH {
                if let Some((_, filter)) = &scoped {
                    filter.coverage().record(
                        entry.path(),
                        CoverageReason::DepthLimit,
                        Some(format!("walk stops at depth {MAX_SOURCE_WALK_DEPTH}")),
                    );
                }
            }
            if entry.depth() > 0 && !is_dir && is_gitfile(entry) {
                return false;
            }
            if let Some(pruned) = is_dir
                .then(|| pruned_dir(entry.path(), entry.depth()))
                .flatten()
            {
                if let Some((_, filter)) = &scoped {
                    filter.coverage().record(
                        entry.path(),
                        CoverageReason::Pruned,
                        Some(format!("{pruned} (dependency or tooling directory)")),
                    );
                }
                return false;
            }
            if is_dir && entry.depth() > 0 {
                if let Some((scan_root, filter)) = &scoped {
                    if filter.excludes_directory(scan_root, entry.path()) {
                        return false;
                    }
                }
            }
            true
        })
        .build()
}

/// A `.git` file (a gitfile pointing at the real repository) holds no source.
fn is_gitfile(entry: &ignore::DirEntry) -> bool {
    entry.file_name() == ".git"
}

/// Maximum size read from small Git pointer files (`.git`, `commondir`, `gitdir`).
const MAX_GIT_POINTER_BYTES: u64 = 4096;

fn read_small_trimmed_file(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_GIT_POINTER_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_GIT_POINTER_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// True when `dir` is a genuine linked Git worktree (`git worktree add`,
/// `.claude/worktrees/<branch>`, `.worktrees/<branch>`), verified against its
/// enclosing repository's `.git/worktrees/<id>` metadata and backlink.
fn is_linked_git_worktree(dir: &Path) -> bool {
    let dot_git = dir.join(".git");
    let Some(pointer) = read_small_trimmed_file(&dot_git) else {
        return false;
    };
    let Some(gitdir_raw) = pointer.strip_prefix("gitdir:").map(str::trim) else {
        return false;
    };
    if gitdir_raw.is_empty() {
        return false;
    }

    let (Ok(canon_dir), Ok(canon_admin)) = (
        std::fs::canonicalize(dir),
        std::fs::canonicalize(dir.join(gitdir_raw)),
    ) else {
        return false;
    };
    if !canon_admin.is_dir()
        || canon_admin.starts_with(&canon_dir)
        || !canon_admin.join("HEAD").is_file()
    {
        return false;
    }

    let Some(commondir_raw) = read_small_trimmed_file(&canon_admin.join("commondir")) else {
        return false;
    };
    let Ok(canon_common) = std::fs::canonicalize(canon_admin.join(commondir_raw)) else {
        return false;
    };
    if canon_common.starts_with(&canon_dir)
        || !canon_common.join("HEAD").is_file()
        || canon_admin.parent() != Some(canon_common.join("worktrees").as_path())
    {
        return false;
    }

    let Some(backlink_raw) = read_small_trimmed_file(&canon_admin.join("gitdir")) else {
        return false;
    };
    let Ok(canon_backlink) = std::fs::canonicalize(canon_admin.join(backlink_raw)) else {
        return false;
    };
    canon_backlink == canon_dir.join(".git")
}

/// The pruned directory's name if `path` is one, judged by name and marker.
fn pruned_dir(path: &Path, depth: usize) -> Option<&'static str> {
    if depth == 0 {
        // The scan root is what the user asked to scan, whatever it is named.
        return None;
    }
    if let Some(name) = path.file_name().and_then(|os| os.to_str()) {
        if let Some(rule) = PRUNED_DIRS.iter().find(|rule| rule.name == name) {
            let looks_real = (rule.root_child_always && depth == 1)
                || rule.markers.iter().any(|marker| has_marker(path, marker));
            if looks_real {
                return Some(rule.name);
            }
        }
    }
    is_linked_git_worktree(path).then_some("git worktree")
}

fn has_marker(dir: &Path, marker: &str) -> bool {
    if let Some(inner) = marker.strip_prefix("*/") {
        return child_dirs(dir).any(|child| child.join(inner).exists());
    }
    if let Some(suffix) = marker.strip_prefix('*') {
        return std::fs::read_dir(dir).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().ends_with(suffix))
        });
    }
    dir.join(marker).exists()
}

fn child_dirs(dir: &Path) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
}

/// Path of the entry a walk error refers to, when it names one.
pub(crate) fn walk_error_path(err: &ignore::Error) -> Option<PathBuf> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path.clone()),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            walk_error_path(err)
        }
        ignore::Error::Partial(errors) => errors.iter().find_map(walk_error_path),
        _ => None,
    }
}

/// Record a walk error (for example a directory with mode 000) as a gap.
pub(crate) fn record_walk_error(coverage: &CoverageRecorder, err: &ignore::Error) {
    if let Some(path) = walk_error_path(err) {
        coverage.record(&path, CoverageReason::Unreadable, Some(err.to_string()));
    }
}

/// Read at most [`MAX_SOURCE_FILE_BYTES`] of `path`.
///
/// Returns the bytes and the file's full size. A larger file is truncated and
/// recorded in `coverage`; a file that cannot be read is recorded as
/// unreadable. Nothing is dropped silently.
pub(crate) fn read_capped_bytes(
    path: &Path,
    coverage: &CoverageRecorder,
) -> Option<(Vec<u8>, u64)> {
    let result = std::fs::File::open(path).and_then(|file| {
        let size = file.metadata()?.len();
        let mut bytes = Vec::new();
        file.take(MAX_SOURCE_FILE_BYTES).read_to_end(&mut bytes)?;
        Ok((bytes, size))
    });
    match result {
        Ok((bytes, size)) => {
            if size > MAX_SOURCE_FILE_BYTES {
                coverage.record(
                    path,
                    CoverageReason::Truncated,
                    Some(format!(
                        "scanned the first {MAX_SOURCE_FILE_BYTES} of {size} bytes"
                    )),
                );
            }
            Some((bytes, size))
        }
        Err(err) => {
            coverage.record(path, CoverageReason::Unreadable, Some(err.to_string()));
            None
        }
    }
}

/// Read `path` into a [`SourceFile`], decoding lossily so one non-UTF-8 byte
/// cannot remove the file from the scan.
pub(crate) fn read_source_file(
    path: &Path,
    language: Language,
    coverage: &CoverageRecorder,
) -> Option<SourceFile> {
    let (bytes, size) = read_capped_bytes(path, coverage)?;
    let content_hash = format!("{:x}", sha2::Sha256::new().chain_update(&bytes).finalize());
    Some(SourceFile {
        path: path.to_path_buf(),
        language,
        size_bytes: size,
        content_hash,
        content: String::from_utf8_lossy(&bytes).into_owned(),
    })
}
