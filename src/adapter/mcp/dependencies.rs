use std::path::Path;

use serde_json::Value;

use crate::config::ScanPathFilter;
use crate::ir::SourceLocation;
use crate::ir::dependency_surface::{
    self, Dependency, DependencySurface, LockfileFormat, LockfileInfo,
};

use super::provenance::find_json_key_line;

pub fn parse_dependencies(root: &Path, filter: &ScanPathFilter) -> DependencySurface {
    let mut surface = DependencySurface::default();

    // Parse requirements.txt as a dependency manifest (NOT a lockfile)
    let req_file = root.join("requirements.txt");
    if req_file.exists() && filter.allows_path(root, &req_file) {
        if let Some(content) = crate::adapter::read_file_capped(&req_file) {
            for (idx, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                    continue;
                }
                let (name, version) = if let Some(pos) = line.find("==") {
                    (
                        line[..pos].trim().to_string(),
                        Some(line[pos + 2..].trim().to_string()),
                    )
                } else if let Some(pos) = line.find(">=") {
                    (
                        line[..pos].trim().to_string(),
                        Some(line[pos..].trim().to_string()),
                    )
                } else {
                    (line.to_string(), None)
                };

                surface.dependencies.push(Dependency {
                    name,
                    version_constraint: version,
                    locked_version: None,
                    locked_hash: None,
                    registry: "pypi".into(),
                    is_dev: false,
                    location: Some(SourceLocation {
                        file: req_file.clone(),
                        line: idx + 1,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    }),
                });
            }
        }
    }

    // Check for Python lockfiles
    for (filename, format) in [
        ("Pipfile.lock", LockfileFormat::PipenvLock),
        ("poetry.lock", LockfileFormat::PoetryLock),
        ("uv.lock", LockfileFormat::UvLock),
    ] {
        let lock_path = root.join(filename);
        if lock_path.exists() && filter.allows_path(root, &lock_path) {
            if let Some(content) = crate::adapter::read_file_capped(&lock_path) {
                let (all_pinned, all_hashed) = detect_dependency_lock_confidence(format, &content);
                surface.lockfile = Some(LockfileInfo {
                    path: lock_path,
                    format,
                    all_pinned,
                    all_hashed,
                });
                break;
            }
        }
    }

    // Parse package.json dependencies
    let pkg_json = root.join("package.json");
    if pkg_json.exists() && filter.allows_path(root, &pkg_json) {
        if let Some(content) = crate::adapter::read_file_capped(&pkg_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                for (key, is_dev) in [("dependencies", false), ("devDependencies", true)] {
                    if let Some(deps) = value.get(key).and_then(|v| v.as_object()) {
                        for (name, version) in deps {
                            let line = find_json_key_line(&content, name);
                            surface.dependencies.push(Dependency {
                                name: name.clone(),
                                version_constraint: version.as_str().map(|s| s.to_string()),
                                locked_version: None,
                                locked_hash: None,
                                registry: "npm".into(),
                                is_dev,
                                location: Some(SourceLocation {
                                    file: pkg_json.clone(),
                                    line,
                                    column: 0,
                                    end_line: None,
                                    end_column: None,
                                }),
                            });
                        }
                    }
                }
            }
        }

        // Check for npm / yarn / pnpm lockfiles
        for (filename, format) in [
            (
                "package-lock.json",
                dependency_surface::LockfileFormat::NpmLock,
            ),
            (
                "pnpm-lock.yaml",
                dependency_surface::LockfileFormat::PnpmLock,
            ),
            ("yarn.lock", dependency_surface::LockfileFormat::YarnLock),
        ] {
            let lock_path = root.join(filename);
            if lock_path.exists() && filter.allows_path(root, &lock_path) {
                if let Some(content) = crate::adapter::read_file_capped(&lock_path) {
                    let (all_pinned, all_hashed) =
                        detect_dependency_lock_confidence(format, &content);
                    surface.lockfile = Some(LockfileInfo {
                        path: lock_path,
                        format,
                        all_pinned,
                        all_hashed,
                    });
                    break;
                }
            }
        }
    }

    surface
}

pub(crate) fn detect_dependency_lock_confidence(
    format: dependency_surface::LockfileFormat,
    content: &str,
) -> (bool, bool) {
    match format {
        dependency_surface::LockfileFormat::PipenvLock => detect_pipenv_lock_confidence(content),
        dependency_surface::LockfileFormat::PoetryLock => detect_poetry_lock_confidence(content),
        dependency_surface::LockfileFormat::UvLock => detect_uv_lock_confidence(content),
        dependency_surface::LockfileFormat::NpmLock => detect_npm_lock_confidence(content),
        dependency_surface::LockfileFormat::PnpmLock => detect_pnpm_lock_confidence(content),
        dependency_surface::LockfileFormat::YarnLock => detect_yarn_lock_confidence(content),
        dependency_surface::LockfileFormat::PipRequirements => (false, false),
    }
}

pub(crate) fn detect_pipenv_lock_confidence(content: &str) -> (bool, bool) {
    let Ok(value) = serde_json::from_str::<Value>(content) else {
        return (false, false);
    };

    let mut all_pinned = true;
    let mut all_hashed = true;
    let mut packages_seen = 0usize;

    for bucket_name in ["default", "develop", "packages", "dev-packages"] {
        if let Some(bucket) = value.get(bucket_name).and_then(|v| v.as_object()) {
            for (_, meta) in bucket {
                let Some(meta_obj) = meta.as_object() else {
                    continue;
                };
                packages_seen += 1;

                let version = meta_obj
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim();
                if !is_exact_pinned_version(version) {
                    all_pinned = false;
                }

                let has_hash = meta_obj
                    .get("hashes")
                    .and_then(|v| v.as_array())
                    .is_some_and(|hashes| !hashes.is_empty());
                if !has_hash {
                    all_hashed = false;
                }
            }
        }
    }

    if packages_seen == 0 {
        (false, false)
    } else {
        (all_pinned, all_hashed)
    }
}

pub(crate) fn detect_poetry_lock_confidence(content: &str) -> (bool, bool) {
    let Ok(value) = content.parse::<toml::Value>() else {
        return (false, false);
    };

    let mut all_pinned = true;
    let mut all_hashed = true;
    let mut packages_seen = 0usize;

    let Some(packages) = value.get("package").and_then(|v| v.as_array()) else {
        return (false, false);
    };

    for pkg in packages {
        let Some(pkg_obj) = pkg.as_table() else {
            continue;
        };
        packages_seen += 1;

        let version = pkg_obj
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_exact_pinned_version(version) {
            all_pinned = false;
        }

        // Poetry lockfiles typically carry checksums in package.files[].hashes entries.
        let mut package_hashed = false;
        if let Some(files) = pkg_obj.get("files").and_then(|v| v.as_array()) {
            if files.iter().any(|entry| {
                entry
                    .as_table()
                    .is_some_and(|file_entry| file_entry.get("hash").is_some())
            }) {
                package_hashed = true;
            }
        }

        if !package_hashed {
            all_hashed = false;
        }
    }

    if packages_seen == 0 {
        (false, false)
    } else {
        (all_pinned, all_hashed)
    }
}

pub(crate) fn detect_uv_lock_confidence(content: &str) -> (bool, bool) {
    let Ok(value) = content.parse::<toml::Value>() else {
        return (false, false);
    };

    let mut all_pinned = true;
    let mut all_hashed = true;
    let mut packages_seen = 0usize;

    let Some(packages) = value
        .get("package")
        .or_else(|| value.get("packages"))
        .and_then(|v| v.as_array())
    else {
        return (false, false);
    };

    for pkg in packages {
        let Some(pkg_obj) = pkg.as_table() else {
            continue;
        };
        packages_seen += 1;

        let version = pkg_obj
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_exact_pinned_version(version) {
            all_pinned = false;
        }

        let has_hash = pkg_obj.get("hash").is_some()
            || pkg_obj
                .get("hashes")
                .is_some_and(|v| !v.as_array().is_none_or(|arr| arr.is_empty()))
            || pkg_obj.get("sdist").and_then(|s| s.get("hash")).is_some()
            || pkg_obj
                .get("wheels")
                .and_then(|w| w.as_array())
                .is_some_and(|arr| {
                    !arr.is_empty() && arr.iter().all(|wheel| wheel.get("hash").is_some())
                });
        if !has_hash {
            all_hashed = false;
        }
    }

    if packages_seen == 0 {
        (false, false)
    } else {
        (all_pinned, all_hashed)
    }
}

pub(crate) fn detect_npm_lock_confidence(content: &str) -> (bool, bool) {
    let Ok(value) = serde_json::from_str::<Value>(content) else {
        return (false, false);
    };

    let mut all_pinned = true;
    let mut all_hashed = true;
    let mut packages_seen = 0usize;

    if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
        for (pkg_path, pkg_value) in packages {
            if pkg_path.is_empty() {
                continue;
            }
            if let Some(pkg_obj) = pkg_value.as_object() {
                packages_seen += 1;

                let version = pkg_obj
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if !is_exact_pinned_version(version) {
                    all_pinned = false;
                }

                let has_integrity = pkg_obj
                    .get("integrity")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_integrity {
                    all_hashed = false;
                }
            }
        }
    }

    if let Some(dependencies) = value.get("dependencies").and_then(|v| v.as_object()) {
        for (_, dep_value) in dependencies {
            if let Some(dep_obj) = dep_value.as_object() {
                if let Some(version) = dep_obj.get("version").and_then(|v| v.as_str()) {
                    packages_seen += 1;
                    if !is_exact_pinned_version(version) {
                        all_pinned = false;
                    }

                    let has_integrity = dep_obj
                        .get("integrity")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| !v.trim().is_empty());
                    if !has_integrity {
                        all_hashed = false;
                    }
                } else if let Some(nested_deps) =
                    dep_obj.get("dependencies").and_then(|v| v.as_object())
                {
                    for (_, nested_dep_value) in nested_deps {
                        if let Some(nested_obj) = nested_dep_value.as_object() {
                            packages_seen += 1;
                            let version = nested_obj
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            if !is_exact_pinned_version(version) {
                                all_pinned = false;
                            }

                            let has_integrity = nested_obj
                                .get("integrity")
                                .and_then(|v| v.as_str())
                                .is_some_and(|v| !v.trim().is_empty());
                            if !has_integrity {
                                all_hashed = false;
                            }
                        }
                    }
                }
            }
        }
    }

    if packages_seen == 0 {
        (false, false)
    } else {
        (all_pinned, all_hashed)
    }
}

pub(crate) fn detect_pnpm_lock_confidence(content: &str) -> (bool, bool) {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return (false, false);
    };

    let mut all_pinned = true;
    let mut all_hashed = true;
    let mut packages_seen = 0usize;

    let Some(packages) = value
        .as_mapping()
        .and_then(|m| m.get("packages"))
        .and_then(|v| v.as_mapping())
    else {
        return (false, false);
    };

    for (_key, package_value) in packages {
        let Some(package_obj) = package_value.as_mapping() else {
            continue;
        };
        packages_seen += 1;

        let version = package_obj
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        if !is_exact_pinned_version(version) {
            all_pinned = false;
        }

        let has_integrity = package_obj
            .get("resolution")
            .and_then(|v| v.as_mapping())
            .and_then(|r| r.get("integrity"))
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.trim().is_empty())
            || package_obj
                .get("integrity")
                .and_then(|v| v.as_str())
                .is_some_and(|v| !v.trim().is_empty());
        if !has_integrity {
            all_hashed = false;
        }
    }

    if packages_seen == 0 {
        (false, false)
    } else {
        (all_pinned, all_hashed)
    }
}

pub(crate) fn detect_yarn_lock_confidence(content: &str) -> (bool, bool) {
    let mut all_pinned = true;
    let mut all_hashed = true;
    let mut packages_seen = 0usize;

    let mut in_package_block = false;
    let mut current_has_version = false;
    let mut current_has_integrity = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let is_package_header =
            !raw_line.starts_with(' ') && !raw_line.starts_with('\t') && line.ends_with(':');
        if is_package_header {
            if in_package_block {
                if !current_has_version {
                    all_pinned = false;
                }
                if !current_has_integrity {
                    all_hashed = false;
                }
            }

            in_package_block = !line.starts_with("__");
            current_has_version = false;
            current_has_integrity = false;
            if in_package_block {
                packages_seen += 1;
            }
            continue;
        }

        if !in_package_block {
            continue;
        }

        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if line.starts_with("version ") {
                current_has_version = true;
            }
            if line.starts_with("resolved ") || line.starts_with("integrity ") {
                current_has_integrity = true;
            }
        }
    }

    if in_package_block {
        if !current_has_version {
            all_pinned = false;
        }
        if !current_has_integrity {
            all_hashed = false;
        }
    }

    if packages_seen == 0 {
        (false, false)
    } else {
        (all_pinned, all_hashed)
    }
}

pub(crate) fn is_exact_pinned_version(version: &str) -> bool {
    let version = version.trim();
    if version.is_empty() {
        return false;
    }

    let normalized = version
        .trim_start_matches("==")
        .trim_start_matches("~=")
        .trim_start_matches('=')
        .trim_start_matches('v')
        .trim();

    if normalized.contains('*')
        || normalized.contains('x')
        || normalized.contains('>')
        || normalized.contains('<')
        || normalized.contains('^')
        || normalized.contains('~')
        || normalized.contains('|')
        || normalized.contains(',')
        || normalized.contains(' ')
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_lock_skips_root_package() {
        let content = r#"{
            "packages": {
                "": {"name": "root"},
                "node_modules/foo": {"version": "1.0.0", "integrity": "sha512-abc"}
            }
        }"#;
        assert_eq!(detect_npm_lock_confidence(content), (true, true));
    }

    #[test]
    fn npm_lock_detects_unpinned() {
        let content = r#"{
            "packages": {
                "node_modules/foo": {"version": "1.0.0"}
            }
        }"#;
        assert_eq!(detect_npm_lock_confidence(content), (true, false));
    }

    #[test]
    fn uv_lock_requires_all_wheels_hashed() {
        let content = r#"
        [[package]]
        name = "foo"
        version = "1.0.0"
        wheels = [
            {url = "https://...", hash = "sha256:abc"},
            {url = "https://..."}
        ]
        "#;
        assert_eq!(detect_uv_lock_confidence(content), (true, false));
    }

    #[test]
    fn uv_lock_detects_sdist_hash() {
        let content = r#"
        [[package]]
        name = "foo"
        version = "1.0.0"
        [package.sdist]
        hash = "sha256:abc"
        "#;
        assert_eq!(detect_uv_lock_confidence(content), (true, true));
    }

    #[test]
    fn uv_lock_fully_pinned_and_hashed() {
        let content = r#"
        [[package]]
        name = "foo"
        version = "1.0.0"
        wheels = [
            {url = "https://...", hash = "sha256:abc"}
        ]
        "#;
        assert_eq!(detect_uv_lock_confidence(content), (true, true));
    }
}
