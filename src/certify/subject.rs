//! Content-bound subject digest for attestations (predicate v2).
//!
//! The attestation subject digest is the SHA-256 of a *source manifest*: one
//! line per scanned source file, sorted by path,
//!
//! ```text
//! <sha256 of the file bytes, lowercase hex><two spaces><path>\n
//! ```
//!
//! where `<path>` is relative to the scan root with `/` separators (a `\` is
//! written as `\\` and a newline as `\n`). Files are the deduplicated
//! `source_files` of every scan target, that is exactly the files the adapters
//! loaded after test-file and include/exclude filtering. The digest therefore
//! changes when the content of a scanned file changes, or when a file is added
//! to, removed from or renamed within the scanned set, and does not depend on
//! the name or location of the scan root directory.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::ir::ScanTarget;
use crate::rules::fingerprint::scan_relative_path;

/// Identifier of the manifest format hashed into the subject digest.
pub const SOURCE_MANIFEST_FORMAT: &str = "agentshield-source-manifest-v1";

/// Build the sorted source manifest described in the module documentation.
pub fn source_manifest(scan_root: &Path, targets: &[ScanTarget]) -> String {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for file in targets.iter().flat_map(|target| &target.source_files) {
        let path = escape_path(&scan_relative_path(&file.path, scan_root));
        let digest = if is_sha256_hex(&file.content_hash) {
            file.content_hash.to_ascii_lowercase()
        } else {
            hex::encode(Sha256::digest(file.content.as_bytes()))
        };
        files.entry(path).or_insert(digest);
    }

    files
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect()
}

/// SHA-256 (lowercase hex) of [`source_manifest`].
pub fn source_manifest_digest(scan_root: &Path, targets: &[ScanTarget]) -> String {
    hex::encode(Sha256::digest(
        source_manifest(scan_root, targets).as_bytes(),
    ))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn escape_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ir::{Framework, Language, SourceFile};

    fn target(root: &str, files: &[(&str, &str)]) -> ScanTarget {
        ScanTarget {
            name: "t".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from(root),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: files
                .iter()
                .map(|(path, content)| SourceFile {
                    path: PathBuf::from(format!("{root}/{path}")),
                    language: Language::Python,
                    content: (*content).into(),
                    size_bytes: content.len() as u64,
                    content_hash: hex::encode(Sha256::digest(content.as_bytes())),
                })
                .collect(),
        }
    }

    #[test]
    fn manifest_is_sorted_relative_and_deduplicated() {
        let a = target("/r", &[("b.py", "B"), ("a/x.py", "X")]);
        let b = target("/r", &[("a/x.py", "X")]);
        let manifest = source_manifest(Path::new("/r"), &[a, b]);
        let expected = format!(
            "{}  a/x.py\n{}  b.py\n",
            hex::encode(Sha256::digest(b"X")),
            hex::encode(Sha256::digest(b"B"))
        );
        assert_eq!(manifest, expected);
    }

    #[test]
    fn digest_tracks_content_not_root_name() {
        let root = |name: &str, body: &str| {
            source_manifest_digest(
                Path::new(name),
                &[target(name, &[("server.py", body), ("lib.py", "y")])],
            )
        };
        assert_eq!(root("/one", "x"), root("/renamed", "x"));
        assert_ne!(root("/one", "x"), root("/one", "x2"));
    }

    #[test]
    fn non_sha256_content_hash_falls_back_to_content() {
        let mut t = target("/r", &[("a.py", "A")]);
        t.source_files[0].content_hash = "hash".into();
        let expected = format!("{}  a.py\n", hex::encode(Sha256::digest(b"A")));
        assert_eq!(source_manifest(Path::new("/r"), &[t]), expected);
    }
}
