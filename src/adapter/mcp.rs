use std::path::{Path, PathBuf};

use crate::analysis::cross_file::apply_cross_file_sanitization;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::execution_surface::ExecutionSurface;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;
use crate::parser;

/// MCP Server adapter.
///
/// Detects MCP servers by looking for:
/// - package.json with `@modelcontextprotocol/sdk` dependency
/// - Python files importing `mcp` or `mcp.server`
/// - mcp.json / mcp-config.json manifest
pub struct McpAdapter;

impl super::Adapter for McpAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        let metadata_root =
            super::mcp_metadata::metadata_root_for_scan(root).unwrap_or_else(|| root.to_path_buf());
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "mcp-server".into());

        let mut source_files = Vec::new();
        let mut execution = ExecutionSurface::default();
        let mut tools = Vec::new();

        // Collect source files
        collect_source_files_with_filter(root, filter, &mut source_files)?;
        for source_file in &source_files {
            if matches!(
                source_file.language,
                Language::TypeScript | Language::JavaScript
            ) {
                tools.extend(extract_mcp_tools_from_source(
                    &source_file.path,
                    &source_file.content,
                ));
            }
        }

        // Phase 1: Parse each source file, collecting results for cross-file analysis.
        let mut parsed_files: Vec<(PathBuf, parser::ParsedFile)> = Vec::new();
        for sf in &source_files {
            if let Some(parser) = parser::parser_for_language(sf.language) {
                if let Ok(parsed) = parser.parse_file(&sf.path, &sf.content) {
                    parsed_files.push((sf.path.clone(), parsed));
                }
            }
        }

        // Phase 2: Cross-file sanitizer-aware analysis — downgrade operations
        // in functions that are only called with sanitized arguments.
        apply_cross_file_sanitization(&mut parsed_files);

        // Phase 3: Merge parsed results into execution surface.
        for (_, parsed) in parsed_files {
            execution.commands.extend(parsed.commands);
            execution.file_operations.extend(parsed.file_operations);
            execution
                .network_operations
                .extend(parsed.network_operations);
            execution.env_accesses.extend(parsed.env_accesses);
            execution.dynamic_exec.extend(parsed.dynamic_exec);
        }

        // Parse tool definitions from JSON if available
        let tools_json = root.join("tools.json");
        if tools_json.exists() && filter.allows_path(root, &tools_json) {
            if let Ok(content) = std::fs::read_to_string(&tools_json) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                    tools.extend(parser::json_schema::parse_tools_from_json(&value));
                    tools = dedupe_tools_by_name(tools);
                }
            }
        }

        let (dependencies, provenance) = if super::mcp_metadata::same_path(root, &metadata_root) {
            (
                parse_dependencies(root, filter),
                parse_provenance(root, filter),
            )
        } else {
            let metadata_filter = ScanPathFilter::for_ignore_tests(filter.ignore_tests());
            (
                parse_dependencies(&metadata_root, &metadata_filter),
                parse_provenance(&metadata_root, &metadata_filter),
            )
        };

        let data = build_data_surface(&tools, &execution);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::Mcp,
            root_path: metadata_root,
            tools,
            execution,
            data,
            dependencies,
            provenance,
            source_files,
        }])
    }
}

/// Check if a file path belongs to a test file or test directory.
///
/// Matches common conventions across Python, TypeScript, and JavaScript:
/// - Directories: `test/`, `tests/`, `__tests__/`, `__pycache__/`
/// - Suffixes: `.test.{ts,js,tsx,jsx,py,sh}`, `.spec.{ts,js,tsx,jsx,py,sh}`
/// - Python conventions: `test_*.py`, `*_test.py`
/// - Config files: `conftest.py`, `jest.config.*`, `vitest.config.*`, `pytest.ini`, `setup.cfg`
pub fn is_test_file(path: &Path) -> bool {
    // Check if any path component is a test directory
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                "test" | "tests" | "__tests__" | "__pycache__"
            ) {
                return true;
            }
        }
    }

    let file_name = match path.file_name() {
        Some(n) => n.to_string_lossy(),
        None => return false,
    };
    let file_name = file_name.as_ref();

    // Test config files
    if matches!(file_name, "conftest.py" | "pytest.ini" | "setup.cfg")
        || file_name.starts_with("jest.config.")
        || file_name.starts_with("vitest.config.")
    {
        return true;
    }

    // pytest conventions: test_*.py and *_test.py
    if file_name.ends_with(".py")
        && (file_name.starts_with("test_") || file_name.ends_with("_test.py"))
    {
        return true;
    }

    // Suffix conventions: *.test.{ts,js,tsx,jsx,py,sh}, *.spec.{ts,js,tsx,jsx,py,sh}
    for suffix in [
        ".test.ts",
        ".test.js",
        ".test.tsx",
        ".test.jsx",
        ".test.py",
        ".test.sh",
        ".spec.ts",
        ".spec.js",
        ".spec.tsx",
        ".spec.jsx",
        ".spec.py",
        ".spec.sh",
    ] {
        if file_name.ends_with(suffix) {
            return true;
        }
    }

    false
}

fn extract_mcp_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = find_next_mcp_tool_call(&content[offset..]) {
        let call_start = offset + relative_start;
        let Some(open_paren) = content[call_start..].find('(').map(|pos| call_start + pos) else {
            break;
        };
        let args_start = open_paren + 1;
        let Some((name, after_name)) = parse_string_literal_at(content, args_start) else {
            offset = args_start;
            continue;
        };
        let description = parse_next_string_argument(content, after_name);
        let line = content[..call_start].lines().count() + 1;

        tools.push(ToolSurface {
            name,
            description,
            input_schema: None,
            output_schema: None,
            declared_permissions: Vec::new(),
            defined_at: Some(source_loc(path, line)),
        });

        offset = after_name;
    }

    dedupe_tools_by_name(tools)
}

fn find_next_mcp_tool_call(content: &str) -> Option<usize> {
    match (content.find(".tool("), content.find(".registerTool(")) {
        (Some(tool), Some(register_tool)) => Some(tool.min(register_tool)),
        (Some(tool), None) => Some(tool),
        (None, Some(register_tool)) => Some(register_tool),
        (None, None) => None,
    }
}

fn parse_next_string_argument(content: &str, offset: usize) -> Option<String> {
    let mut index = skip_whitespace(content, offset);
    if content[index..].starts_with(',') {
        index += 1;
    } else {
        return None;
    }

    let index = skip_whitespace(content, index);
    parse_string_literal_at(content, index).map(|(value, _)| value)
}

fn parse_string_literal_at(content: &str, offset: usize) -> Option<(String, usize)> {
    let offset = skip_whitespace(content, offset);
    let quote = content[offset..].chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }

    let mut value = String::new();
    let mut escaped = false;
    for (relative_index, ch) in content[offset + quote.len_utf8()..].char_indices() {
        let absolute_index = offset + quote.len_utf8() + relative_index;
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some((value, absolute_index + quote.len_utf8()));
        }
        value.push(ch);
    }

    None
}

fn skip_whitespace(content: &str, mut offset: usize) -> usize {
    while let Some(ch) = content[offset..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

fn dedupe_tools_by_name(tools: Vec<ToolSurface>) -> Vec<ToolSurface> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for tool in tools {
        if seen.insert(tool.name.clone()) {
            deduped.push(tool);
        }
    }
    deduped
}

fn source_loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

pub(super) fn collect_source_files_with_filter(
    root: &Path,
    filter: &ScanPathFilter,
    files: &mut Vec<SourceFile>,
) -> Result<()> {
    let walker = ignore::WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .max_depth(Some(5))
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if filter.ignore_tests() && is_test_file(path) {
            continue;
        }

        if !filter.allows_path(root, path) {
            continue;
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let lang = Language::from_extension(&ext);

        if matches!(lang, Language::Unknown) {
            continue;
        }

        // Skip files larger than 1MB
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 1_048_576 {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(path) {
            let hash = format!(
                "{:x}",
                sha2::Digest::finalize(sha2::Sha256::new().chain_update(content.as_bytes()))
            );
            files.push(SourceFile {
                path: path.to_path_buf(),
                language: lang,
                size_bytes: metadata.len(),
                content_hash: hash,
                content,
            });
        }
    }

    Ok(())
}

pub(super) fn parse_dependencies(
    root: &Path,
    filter: &ScanPathFilter,
) -> dependency_surface::DependencySurface {
    use crate::ir::dependency_surface::*;
    let mut surface = DependencySurface::default();

    // Parse requirements.txt as a dependency manifest (NOT a lockfile)
    let req_file = root.join("requirements.txt");
    if req_file.exists() && filter.allows_path(root, &req_file) {
        if let Ok(content) = std::fs::read_to_string(&req_file) {
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

    // Check for actual Python lockfiles
    for (filename, format) in [
        ("Pipfile.lock", LockfileFormat::PipenvLock),
        ("poetry.lock", LockfileFormat::PoetryLock),
        ("uv.lock", LockfileFormat::UvLock),
    ] {
        let lock_path = root.join(filename);
        if lock_path.exists() && filter.allows_path(root, &lock_path) {
            surface.lockfile = Some(LockfileInfo {
                path: lock_path,
                format,
                all_pinned: true,
                all_hashed: false,
            });
            break;
        }
    }

    // Parse package.json dependencies
    let pkg_json = root.join("package.json");
    if pkg_json.exists() && filter.allows_path(root, &pkg_json) {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
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

        // Check for lockfile
        let lock = root.join("package-lock.json");
        if lock.exists() {
            surface.lockfile = Some(LockfileInfo {
                path: lock,
                format: dependency_surface::LockfileFormat::NpmLock,
                all_pinned: true,
                all_hashed: false,
            });
        }
    }

    surface
}

/// Find the 1-based line number where a JSON key (e.g. `"package-name"`) appears.
/// Falls back to line 1 if the key is not found.
fn find_json_key_line(content: &str, key: &str) -> usize {
    let needle = format!("\"{}\"", key);
    for (idx, line) in content.lines().enumerate() {
        if line.contains(&needle) {
            return idx + 1;
        }
    }
    1
}

pub(super) fn parse_provenance(
    root: &Path,
    filter: &ScanPathFilter,
) -> provenance_surface::ProvenanceSurface {
    let mut prov = provenance_surface::ProvenanceSurface::default();

    // From package.json
    let pkg_json = root.join("package.json");
    if pkg_json.exists() && filter.allows_path(root, &pkg_json) {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                prov.author = value
                    .get("author")
                    .and_then(|v| v.as_str())
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

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_detection_covers_shell_and_suffix_python_tests() {
        assert!(is_test_file(Path::new("scripts/check.test.sh")));
        assert!(is_test_file(Path::new("scripts/check.spec.sh")));
        assert!(is_test_file(Path::new("scripts/import_data_test.py")));
        assert!(is_test_file(Path::new("tests/unit.py")));
        assert!(!is_test_file(Path::new("scripts/load.py")));
    }

    #[test]
    fn extracts_typescript_mcp_server_tool_declarations() {
        let content = r#"
const server = new McpServer({ name: "demo" })

server.tool(
  'search_party',
  'Busca fuzzy por nome.',
  {},
  async () => ({ content: [] })
)

server.registerTool("create_report", { description: "Create report" }, async () => {})
"#;

        let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.ts"), content);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "search_party");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("Busca fuzzy por nome.")
        );
        assert_eq!(tools[0].defined_at.as_ref().map(|loc| loc.line), Some(5));
        assert_eq!(tools[1].name, "create_report");
        assert_eq!(tools[1].description, None);
    }
}
