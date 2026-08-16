use std::path::Path;

use crate::config::ScanPathFilter;
use crate::ir::provenance_surface::ProvenanceSurface;

/// Find the 1-based line number where a JSON key (e.g. `"package-name"`) appears.
/// Falls back to line 1 if the key is not found.
pub fn find_json_key_line(content: &str, key: &str) -> usize {
    let needle = format!("\"{}\"", key);
    for (idx, line) in content.lines().enumerate() {
        if line.contains(&needle) {
            return idx + 1;
        }
    }
    1
}

pub fn parse_provenance(root: &Path, filter: &ScanPathFilter) -> ProvenanceSurface {
    let mut prov = ProvenanceSurface::default();

    // From package.json
    let pkg_json = root.join("package.json");
    if pkg_json.exists() && filter.allows_path(root, &pkg_json) {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                prov.author = value
                    .get("author")
                    .and_then(|v| {
                        v.as_str()
                            .or_else(|| v.get("name").and_then(|n| n.as_str()))
                    })
                    .map(|s| s.to_string());
                prov.repository = value
                    .get("repository")
                    .and_then(|v| v.get("url").or(Some(v)))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                prov.license = value
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
    }

    // From pyproject.toml
    let pyproject = root.join("pyproject.toml");
    if pyproject.exists() && filter.allows_path(root, &pyproject) {
        if let Ok(content) = std::fs::read_to_string(&pyproject) {
            if let Ok(value) = content.parse::<toml::Value>() {
                if let Some(project) = value.get("project") {
                    prov.license = project
                        .get("license")
                        .and_then(|v| v.get("text").or(Some(v)))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let Some(authors) = project.get("authors").and_then(|v| v.as_array()) {
                        if let Some(first) = authors.first() {
                            prov.author = first
                                .get("name")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                }
                if let Some(urls) = value.get("project").and_then(|p| p.get("urls")) {
                    prov.repository = urls
                        .get("Repository")
                        .or(urls.get("repository"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    prov
}
