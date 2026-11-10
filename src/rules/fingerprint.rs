//! Stable, distinct finding fingerprints (scheme v2).
//!
//! A fingerprint identifies one finding across scan runs. It is used by
//! `--baseline` / `--write-baseline`, by `[[policy.suppressions]]` entries and
//! by the `fingerprint` field of the JSON, SARIF, HTML and console outputs.
//!
//! # Scheme v2
//!
//! The fingerprint is the SHA-256 (hex) of these length-prefixed fields:
//!
//! 1. the scheme tag `agentshield-fingerprint-v2`;
//! 2. the rule id (for example `SHIELD-001`);
//! 3. the finding's file path relative to the scan root, with `/` separators
//!    (empty when the finding has no location);
//! 4. the normalized evidence text: every evidence description and snippet,
//!    with the file path rewritten relative to the scan root and runs of
//!    whitespace collapsed (the message is used only when there is no
//!    evidence);
//! 5. the occurrence index of the finding among the findings of the same scan
//!    that share fields 2 to 4, ordered by line and column.
//!
//! Line and column numbers are deliberately **not** hashed: editing code above
//! a finding moves every finding of the group by the same amount, so their
//! relative order, and therefore their occurrence indexes, stay the same. The
//! occurrence index keeps findings with identical text distinct, so a baseline
//! or a suppression never hides a second, new finding of the same rule in the
//! same file.
//!
//! Because the occurrence index depends on the other findings, fingerprints are
//! computed for a whole scan with [`compute_fingerprints`], before policy or
//! baseline filtering, and carried alongside the findings.
//!
//! # Legacy scheme v1
//!
//! [`Finding::legacy_fingerprint`] reproduces the original algorithm (rule id,
//! raw path stripped of the scan root, first evidence description, attack
//! category). It collides for same-rule findings in one file and changes with
//! the spelling of the scan path. It is kept only so that schema-v1 baselines
//! and suppressions written by earlier releases keep matching.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::finding::Finding;

/// Version of the fingerprint scheme produced by [`compute_fingerprints`].
pub const FINGERPRINT_SCHEME_VERSION: u32 = 2;

const SCHEME_TAG: &str = "agentshield-fingerprint-v2";

/// Compute scheme-v2 fingerprints for every finding of one scan.
///
/// The result is aligned with `findings`: element `i` is the fingerprint of
/// `findings[i]`. Pass the complete, unfiltered set of findings of a scan so
/// that occurrence indexes do not depend on suppressions or baselines.
pub fn compute_fingerprints(findings: &[Finding], scan_root: &Path) -> Vec<String> {
    let keys: Vec<IdentityKey> = findings
        .iter()
        .map(|finding| IdentityKey::of(finding, scan_root))
        .collect();

    let mut groups: HashMap<&IdentityKey, Vec<usize>> = HashMap::new();
    for (index, key) in keys.iter().enumerate() {
        groups.entry(key).or_default().push(index);
    }

    let mut occurrence = vec![0_usize; findings.len()];
    for members in groups.values_mut() {
        members.sort_by(|&a, &b| position_order(&findings[a], &findings[b]).then(a.cmp(&b)));
        for (rank, &index) in members.iter().enumerate() {
            occurrence[index] = rank;
        }
    }

    keys.iter()
        .zip(occurrence)
        .map(|(key, rank)| key.digest(rank))
        .collect()
}

/// Return `path` relative to `scan_root`, with `/` separators.
///
/// Handles findings whose paths are spelled relative to the working directory
/// (`scan .`, `scan sub/dir`) as well as absolute paths through symlinked
/// prefixes (for example `/var` and `/private/var` on macOS). Falls back to the
/// lexically normalized path when it does not lie under the scan root.
pub fn scan_relative_path(path: &Path, scan_root: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(scan_root) {
        return slash_path(&lexical_normalize(relative), path);
    }

    let absolute = if path.is_absolute() {
        lexical_normalize(path)
    } else {
        std::env::current_dir()
            .map(|cwd| lexical_normalize(&cwd.join(path)))
            .unwrap_or_else(|_| lexical_normalize(path))
    };
    let root = lexical_normalize(scan_root);
    if let Ok(relative) = absolute.strip_prefix(&root) {
        return slash_path(relative, path);
    }

    if let (Ok(file), Ok(root)) = (absolute.canonicalize(), scan_root.canonicalize()) {
        if let Ok(relative) = file.strip_prefix(&root) {
            return slash_path(relative, path);
        }
    }

    slash_path(&lexical_normalize(path), path)
}

/// The occurrence-independent part of a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IdentityKey {
    rule_id: String,
    path: String,
    evidence: String,
}

impl IdentityKey {
    fn of(finding: &Finding, scan_root: &Path) -> Self {
        let (path, raw_path) = match finding.location.as_ref() {
            Some(location) => (
                scan_relative_path(&location.file, scan_root),
                Some(location.file.display().to_string()),
            ),
            None => (String::new(), None),
        };
        let rewrite = |text: &str| normalize_text(text, raw_path.as_deref(), &path, scan_root);

        let evidence = if finding.evidence.is_empty() {
            rewrite(&finding.message)
        } else {
            finding
                .evidence
                .iter()
                .map(|evidence| {
                    let snippet = evidence.snippet.as_deref().map(rewrite).unwrap_or_default();
                    format!("{}\u{1f}{}", rewrite(&evidence.description), snippet)
                })
                .collect::<Vec<_>>()
                .join("\u{1e}")
        };

        Self {
            rule_id: finding.rule_id.clone(),
            path,
            evidence,
        }
    }

    fn digest(&self, occurrence: usize) -> String {
        let mut hasher = Sha256::new();
        for field in [
            SCHEME_TAG,
            self.rule_id.as_str(),
            self.path.as_str(),
            self.evidence.as_str(),
            occurrence.to_string().as_str(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

fn position_order(a: &Finding, b: &Finding) -> Ordering {
    let position = |finding: &Finding| {
        finding.location.as_ref().map(|location| {
            (
                location.line,
                location.column,
                location.end_line,
                location.end_column,
            )
        })
    };
    position(a).cmp(&position(b))
}

/// Rewrite path spellings to the scan-relative path and collapse whitespace.
fn normalize_text(text: &str, raw_path: Option<&str>, relative: &str, scan_root: &Path) -> String {
    let mut rewritten = text.to_owned();
    if let Some(raw) = raw_path.filter(|raw| !raw.is_empty() && *raw != relative) {
        rewritten = rewritten.replace(raw, relative);
    }
    let root = scan_root.display().to_string();
    if !root.is_empty() {
        rewritten = rewritten.replace(&format!("{root}/"), "");
    }
    rewritten.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn slash_path(relative: &Path, original: &Path) -> String {
    let joined = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            Component::ParentDir => Some("..".to_owned()),
            Component::RootDir | Component::Prefix(_) => Some(String::new()),
            Component::CurDir => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        // The scan root is the file itself: fall back to its file name.
        original
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::ir::SourceLocation;
    use crate::rules::{AttackCategory, Confidence, Evidence, Severity};

    fn finding(file: &str, line: usize, description: &str, snippet: &str) -> Finding {
        Finding {
            rule_id: "SHIELD-001".into(),
            rule_name: "Command Injection".into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: format!("subprocess call at line {line}"),
            location: Some(SourceLocation {
                file: PathBuf::from(file),
                line,
                column: 4,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: description.into(),
                location: None,
                snippet: Some(snippet.into()),
            }],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    #[test]
    fn same_rule_findings_in_one_file_are_distinct() {
        let root = Path::new("/project");
        let findings = vec![
            finding("/project/a.py", 10, "subprocess receives cmd", "run(cmd)"),
            finding("/project/a.py", 20, "subprocess receives cmd", "run(cmd)"),
            finding("/project/a.py", 30, "subprocess receives cmd", "run(other)"),
        ];
        let fps = compute_fingerprints(&findings, root);
        assert_ne!(fps[0], fps[1], "identical text must still differ");
        assert_ne!(fps[0], fps[2]);
        assert_ne!(fps[1], fps[2]);
        // The legacy scheme collides for all three.
        assert_eq!(
            findings[0].legacy_fingerprint(root),
            findings[1].legacy_fingerprint(root)
        );
    }

    #[test]
    fn line_shift_above_findings_keeps_fingerprints() {
        let root = Path::new("/project");
        let before = vec![
            finding("/project/a.py", 10, "subprocess receives cmd", "run(cmd)"),
            finding("/project/a.py", 20, "subprocess receives cmd", "run(cmd)"),
        ];
        let after = vec![
            finding("/project/a.py", 27, "subprocess receives cmd", "run(cmd)"),
            finding("/project/a.py", 17, "subprocess receives cmd", "run(cmd)"),
        ];
        let before_fps = compute_fingerprints(&before, root);
        let after_fps = compute_fingerprints(&after, root);
        // Order of emission must not matter: line 17 is the first occurrence.
        assert_eq!(before_fps[0], after_fps[1]);
        assert_eq!(before_fps[1], after_fps[0]);
    }

    #[test]
    fn relative_and_absolute_scan_paths_agree() {
        let cwd = std::env::current_dir().expect("cwd");
        let root = cwd.join("tests/fixtures");
        let relative = vec![finding(
            "tests/fixtures/x/a.py",
            3,
            "in tests/fixtures/x/a.py",
            "run(cmd)",
        )];
        let absolute_file = root.join("x/a.py");
        let absolute = vec![finding(
            absolute_file.to_str().expect("utf-8"),
            3,
            &format!("in {}", absolute_file.display()),
            "run(cmd)",
        )];
        assert_eq!(
            compute_fingerprints(&relative, &root),
            compute_fingerprints(&absolute, &root)
        );
        assert_eq!(scan_relative_path(&absolute_file, &root), "x/a.py");
        assert_eq!(
            scan_relative_path(Path::new("./tests/fixtures/x/a.py"), &root),
            "x/a.py"
        );
    }

    #[test]
    fn renaming_or_moving_the_scan_root_keeps_fingerprints() {
        let a = vec![finding("/one/src/a.py", 3, "d", "s")];
        let b = vec![finding("/two/src/a.py", 3, "d", "s")];
        assert_eq!(
            compute_fingerprints(&a, Path::new("/one")),
            compute_fingerprints(&b, Path::new("/two"))
        );
    }

    #[test]
    fn different_rules_files_and_evidence_differ() {
        let root = Path::new("/p");
        let base = finding("/p/a.py", 1, "d", "s");
        let mut other_rule = base.clone();
        other_rule.rule_id = "SHIELD-002".into();
        let other_file = finding("/p/b.py", 1, "d", "s");
        let other_evidence = finding("/p/a.py", 1, "d", "t");
        let fps = compute_fingerprints(&[base, other_rule, other_file, other_evidence], root);
        let unique: std::collections::HashSet<_> = fps.iter().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn message_line_numbers_do_not_matter_when_evidence_exists() {
        let root = Path::new("/p");
        let a = finding("/p/a.py", 1, "d", "s");
        let mut b = a.clone();
        b.message = "subprocess call at line 99".into();
        assert_eq!(
            compute_fingerprints(&[a], root),
            compute_fingerprints(&[b], root)
        );
    }

    #[test]
    fn fingerprints_are_hex_sha256() {
        let fps = compute_fingerprints(&[finding("/p/a.py", 1, "d", "s")], Path::new("/p"));
        assert_eq!(fps[0].len(), 64);
        assert!(fps[0].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn scheme_v2_digest_is_pinned() {
        // Golden value: changing it breaks every stored baseline/suppression.
        let fps = compute_fingerprints(
            &[finding("/p/src/a.py", 1, "desc", "snip")],
            Path::new("/p"),
        );
        let mut hasher = Sha256::new();
        for field in [
            "agentshield-fingerprint-v2",
            "SHIELD-001",
            "src/a.py",
            "desc\u{1f}snip",
            "0",
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        assert_eq!(fps[0], hex::encode(hasher.finalize()));
    }
}
