use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::{Language, SourceFile};

pub(crate) const OPENAPI_EXTENSIONS: &[&str] = &["json", "yaml", "yml"];

/// OpenAPI spec filenames that GPT Actions typically use.
pub(crate) const OPENAPI_FILENAMES: &[&str] = &[
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
];

/// Legacy ChatGPT plugin manifest filenames.
pub(crate) const PLUGIN_MANIFEST_FILENAMES: &[&str] = &["ai-plugin.json", "actions.json"];

/// OpenAI function and tool definition filenames.
pub(crate) const OPENAI_TOOL_FILENAMES: &[&str] = &[
    "tools.json",
    "functions.json",
    "assistant.json",
    "tools.yaml",
    "tools.yml",
];

/// Check whether any plugin manifest file exists under root.
pub(crate) fn has_plugin_manifest(root: &Path) -> bool {
    for filename in PLUGIN_MANIFEST_FILENAMES {
        if root.join(filename).exists() {
            return true;
        }
    }
    root.join(".well-known").join("ai-plugin.json").exists()
}

/// Find the first OpenAPI spec file present under root, in preference order.
pub(crate) fn find_openapi_spec(root: &Path, filter: &ScanPathFilter) -> Option<PathBuf> {
    for filename in OPENAPI_FILENAMES {
        let path = root.join(filename);
        if path.exists() && filter.allows_path(root, &path) {
            return Some(path);
        }
    }
    None
}

/// Collect OpenAPI spec files and plugin manifests as `SourceFile` entries.
pub(crate) fn collect_spec_source_files(root: &Path, filter: &ScanPathFilter) -> Vec<SourceFile> {
    let mut files = Vec::new();

    let candidates: Vec<PathBuf> = OPENAPI_FILENAMES
        .iter()
        .chain(PLUGIN_MANIFEST_FILENAMES.iter())
        .map(|f| root.join(f))
        .chain(std::iter::once(
            root.join(".well-known").join("ai-plugin.json"),
        ))
        .collect();

    for path in candidates {
        if !path.exists() {
            continue;
        }
        if !filter.allows_path(root, &path) {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > 1_048_576 {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let lang = Language::from_extension(&ext);

        let hash = format!(
            "{:x}",
            sha2::Digest::finalize(sha2::Sha256::new().chain_update(content.as_bytes()))
        );

        files.push(SourceFile {
            path,
            language: lang,
            size_bytes: metadata.len(),
            content_hash: hash,
            content,
        });
    }

    files
}

pub(crate) fn parse_openapi_spec(spec_path: &Path) -> Result<serde_json::Value> {
    let content = std::fs::read_to_string(spec_path)?;
    let extension = spec_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if OPENAPI_EXTENSIONS.contains(&extension.as_str()) && extension != "json" {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&content).map_err(|err| crate::error::ShieldError::Parse {
                file: spec_path.display().to_string(),
                message: format!("Failed to parse OpenAPI YAML: {err}"),
            })?;
        return serde_json::to_value(yaml).map_err(|err| crate::error::ShieldError::Parse {
            file: spec_path.display().to_string(),
            message: format!("Failed to convert OpenAPI YAML AST: {err}"),
        });
    }

    serde_json::from_str(&content).map_err(|err| crate::error::ShieldError::Parse {
        file: spec_path.display().to_string(),
        message: format!("Failed to parse OpenAPI JSON: {err}"),
    })
}
