use std::path::Path;

use sha2::Digest;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::{Language, SourceFile};

pub(crate) fn collect_hermes_source_files(
    root: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    for path in [
        root.join("config.yaml"),
        root.join(".hermes").join("config.yaml"),
        root.join(".hermes.md"),
        root.join("SOUL.md"),
    ] {
        push_source_file_if_allowed(root, &path, filter, source_files)?;
    }

    collect_profile_configs(root, filter, source_files)?;

    for dir in [
        root.join("skills"),
        root.join("optional-skills"),
        root.join("optional-mcps"),
    ] {
        collect_artifact_tree(root, &dir, filter, source_files)?;
    }

    Ok(())
}

pub(crate) fn collect_profile_configs(
    root: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    let profiles_dir = root.join("profiles");
    let Ok(entries) = std::fs::read_dir(profiles_dir) else {
        return Ok(());
    };

    for entry in entries.flatten() {
        push_source_file_if_allowed(
            root,
            &entry.path().join("config.yaml"),
            filter,
            source_files,
        )?;
    }

    Ok(())
}

pub(crate) fn collect_artifact_tree(
    root: &Path,
    dir: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    let walker = ignore::WalkBuilder::new(dir)
        .hidden(true)
        .git_ignore(true)
        .max_depth(Some(6))
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if filter.ignore_tests() && super::super::mcp::is_test_file(path) {
            continue;
        }

        if !filter.allows_path(root, path) {
            continue;
        }

        let Some(file_name) = path.file_name().map(|n| n.to_string_lossy()) else {
            continue;
        };

        let language = language_for_path(path);
        let is_relevant = file_name == "SKILL.md"
            || file_name == "manifest.yaml"
            || matches!(
                language,
                Language::Python
                    | Language::Shell
                    | Language::JavaScript
                    | Language::TypeScript
                    | Language::Json
                    | Language::Yaml
                    | Language::Markdown
            );

        if is_relevant {
            push_source_file(path, source_files)?;
        }
    }

    Ok(())
}

pub(crate) fn push_source_file_if_allowed(
    root: &Path,
    path: &Path,
    filter: &ScanPathFilter,
    source_files: &mut Vec<SourceFile>,
) -> Result<()> {
    if filter.allows_path(root, path) {
        push_source_file(path, source_files)?;
    }
    Ok(())
}

pub(crate) fn push_source_file(path: &Path, source_files: &mut Vec<SourceFile>) -> Result<()> {
    if !path.exists() || !path.is_file() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)?;
    if metadata.len() > 1_048_576 {
        return Ok(());
    }

    if let Ok(content) = std::fs::read_to_string(path) {
        let hash = format!(
            "{:x}",
            sha2::Digest::finalize(sha2::Sha256::new().chain_update(content.as_bytes()))
        );
        source_files.push(SourceFile {
            path: path.to_path_buf(),
            language: language_for_path(path),
            size_bytes: metadata.len(),
            content_hash: hash,
            content,
        });
    }

    Ok(())
}

pub(crate) fn language_for_path(path: &Path) -> Language {
    let Some(file_name) = path.file_name().map(|n| n.to_string_lossy()) else {
        return Language::Unknown;
    };

    if file_name == ".hermes.md" || file_name == "SKILL.md" || file_name == "SOUL.md" {
        return Language::Markdown;
    }

    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    Language::from_extension(&ext)
}

pub(crate) fn is_yaml_file(path: &Path) -> bool {
    matches!(language_for_path(path), Language::Yaml)
}
