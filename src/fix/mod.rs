use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::rules::Finding;

pub mod dependencies;
pub mod deserializer;

/// Summary of a fix applied to a single line or AST node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFix {
    pub rule_id: String,
    pub description: String,
    pub line_number: usize,
}

/// A patch containing original and modified file contents along with applied fixes.
#[derive(Debug, Clone)]
pub struct FilePatch {
    pub file_path: PathBuf,
    pub original_content: String,
    pub modified_content: String,
    pub applied_fixes: Vec<AppliedFix>,
}

impl FilePatch {
    pub fn has_changes(&self) -> bool {
        self.original_content != self.modified_content
    }

    /// Write modified content to disk atomically.
    pub fn write_to_disk(&self) -> std::io::Result<()> {
        let parent = self.file_path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;

        use std::io::Write;
        temp_file.write_all(self.modified_content.as_bytes())?;
        temp_file.flush()?;

        if let Ok(metadata) = std::fs::metadata(&self.file_path) {
            let _ = temp_file.as_file().set_permissions(metadata.permissions());
        }

        temp_file.persist(&self.file_path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Generate a unified diff representation of the patch.
    pub fn render_diff(&self) -> String {
        generate_unified_diff(
            &self.file_path,
            &self.original_content,
            &self.modified_content,
        )
    }
}

/// Core autofix orchestrator.
#[derive(Default)]
pub struct FixEngine;

impl FixEngine {
    pub fn new() -> Self {
        Self
    }

    /// Generate patches for a set of findings across a project root.
    pub fn generate_patches(
        &self,
        findings: &[Finding],
        project_root: &Path,
        filter_rules: Option<&[String]>,
    ) -> Result<Vec<FilePatch>> {
        let mut file_map: std::collections::HashMap<PathBuf, Vec<&Finding>> =
            std::collections::HashMap::new();

        for finding in findings {
            if let Some(rules) = filter_rules {
                if !rules.is_empty()
                    && !rules
                        .iter()
                        .any(|r| r.eq_ignore_ascii_case(&finding.rule_id))
                {
                    continue;
                }
            }

            if let Some(ref loc) = finding.location {
                let resolved_path = if loc.file.exists() {
                    loc.file.clone()
                } else if project_root.join(&loc.file).exists() {
                    project_root.join(&loc.file)
                } else if let Some(file_name) = loc.file.file_name() {
                    if project_root.join(file_name).exists() {
                        project_root.join(file_name)
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                let abs_path = resolved_path.canonicalize().unwrap_or(resolved_path);
                file_map.entry(abs_path).or_default().push(finding);
            }
        }

        let mut patches = Vec::new();

        for (file_path, file_findings) in file_map {
            if !file_path.exists() || !file_path.is_file() {
                continue;
            }

            let content = match std::fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut current_content = content.clone();
            let mut applied_fixes = Vec::new();

            // Run deserializer fixer on SHIELD-016 findings
            if file_findings.iter().any(|f| f.rule_id == "SHIELD-016") {
                if let Some(patched) =
                    deserializer::fix_unsafe_deserializers(&current_content, &file_path)
                {
                    current_content = patched.content;
                    applied_fixes.extend(patched.fixes);
                }
            }

            // Run dependency pinning fixer on SHIELD-009 findings
            if file_findings.iter().any(|f| f.rule_id == "SHIELD-009") {
                if let Some(patched) =
                    dependencies::fix_unpinned_dependencies(&current_content, &file_path)
                {
                    current_content = patched.content;
                    applied_fixes.extend(patched.fixes);
                }
            }

            if current_content != content {
                patches.push(FilePatch {
                    file_path,
                    original_content: content,
                    modified_content: current_content,
                    applied_fixes,
                });
            }
        }

        Ok(patches)
    }
}

/// Helper struct returned by individual fixer modules.
#[derive(Debug, Clone)]
pub struct FixOutput {
    pub content: String,
    pub fixes: Vec<AppliedFix>,
}

/// Simple line-based unified diff generator.
pub fn generate_unified_diff(file_path: &Path, original: &str, modified: &str) -> String {
    let orig_lines: Vec<&str> = original.lines().collect();
    let mod_lines: Vec<&str> = modified.lines().collect();

    let mut diff = String::new();
    diff.push_str(&format!("--- a/{}\n", file_path.display()));
    diff.push_str(&format!("+++ b/{}\n", file_path.display()));

    let mut i = 0;
    let mut j = 0;

    while i < orig_lines.len() || j < mod_lines.len() {
        if i < orig_lines.len() && j < mod_lines.len() && orig_lines[i] == mod_lines[j] {
            i += 1;
            j += 1;
            continue;
        }

        let start_i = i;
        let start_j = j;

        // Collect changed lines
        let mut orig_chunk = Vec::new();
        let mut mod_chunk = Vec::new();

        while i < orig_lines.len() && (j >= mod_lines.len() || orig_lines[i] != mod_lines[j]) {
            orig_chunk.push(orig_lines[i]);
            i += 1;
            if i >= orig_lines.len() || j >= mod_lines.len() || orig_lines[i] == mod_lines[j] {
                break;
            }
        }

        while j < mod_lines.len() && (i >= orig_lines.len() || orig_lines[i] != mod_lines[j]) {
            mod_chunk.push(mod_lines[j]);
            j += 1;
            if i < orig_lines.len() && j < mod_lines.len() && orig_lines[i] == mod_lines[j] {
                break;
            }
        }

        diff.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            start_i + 1,
            orig_chunk.len(),
            start_j + 1,
            mod_chunk.len()
        ));

        for line in orig_chunk {
            diff.push_str(&format!("-{line}\n"));
        }
        for line in mod_chunk {
            diff.push_str(&format!("+{line}\n"));
        }
    }

    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_write_to_disk_atomic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_atomic.txt");

        std::fs::write(&file_path, "original").unwrap();

        let patch = FilePatch {
            file_path: file_path.clone(),
            original_content: "original".into(),
            modified_content: "modified".into(),
            applied_fixes: vec![],
        };

        patch.write_to_disk().unwrap();

        let mut content = String::new();
        std::fs::File::open(&file_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "modified");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_to_disk_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_perms.txt");

        std::fs::write(&file_path, "original").unwrap();
        let mut perms = std::fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&file_path, perms).unwrap();

        let patch = FilePatch {
            file_path: file_path.clone(),
            original_content: "original".into(),
            modified_content: "modified".into(),
            applied_fixes: vec![],
        };

        patch.write_to_disk().unwrap();

        let new_perms = std::fs::metadata(&file_path).unwrap().permissions();
        assert_eq!(new_perms.mode() & 0o777, 0o755);
    }

    #[test]
    fn test_generate_unified_diff() {
        let orig = "line 1\nline 2\nline 3\n";
        let modified = "line 1\nline 2 modified\nline 3\n";
        let diff = generate_unified_diff(Path::new("test.txt"), orig, modified);
        assert!(diff.contains("--- a/test.txt"));
        assert!(diff.contains("+++ b/test.txt"));
        assert!(diff.contains("-line 2"));
        assert!(diff.contains("+line 2 modified"));
    }
}
