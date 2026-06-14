//! GPT Actions adapter.
//!
//! Detects OpenAPI specs used by ChatGPT custom actions (GPTs / plugin manifests)
//! and loads each path+method combination as a `ToolSurface`. Server URLs are
//! emitted as `NetworkOperation` entries so SSRF detectors can evaluate them.

use std::path::{Path, PathBuf};

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::execution_surface::{ExecutionSurface, NetworkOperation};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::tool_surface::ToolSurface;
use crate::ir::*;

/// OpenAPI spec filenames that GPT Actions typically use.
const OPENAPI_FILENAMES: &[&str] = &[
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
];

/// Legacy ChatGPT plugin manifest filenames.
const PLUGIN_MANIFEST_FILENAMES: &[&str] = &["ai-plugin.json", "actions.json"];

/// GPT Actions adapter.
///
/// Detects OpenAPI specs for ChatGPT custom actions by looking for:
/// - `ai-plugin.json` (legacy ChatGPT plugin manifest)
/// - `.well-known/ai-plugin.json`
/// - `openapi.json` / `openapi.yaml` / `swagger.json` / `swagger.yaml`
///   with `x-openai-*` extensions or alongside an `ai-plugin.json`
/// - `actions.json`
pub struct GptActionsAdapter;

impl super::Adapter for GptActionsAdapter {
    fn framework(&self) -> Framework {
        Framework::GptActions
    }

    fn detect(&self, root: &Path) -> bool {
        // Legacy plugin manifest at root or .well-known/
        for filename in PLUGIN_MANIFEST_FILENAMES {
            if root.join(filename).exists() {
                return true;
            }
        }
        if root.join(".well-known").join("ai-plugin.json").exists() {
            return true;
        }

        // OpenAPI spec with x-openai-* extensions
        for filename in OPENAPI_FILENAMES {
            let path = root.join(filename);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains("x-openai-") || content.contains("x-openai") {
                        return true;
                    }
                    // JSON spec: check for openapi version field alongside plugin manifest check
                    if content.contains("\"openapi\"") || content.contains("openapi:") {
                        // Also accept if ai-plugin.json exists anywhere nearby
                        if has_plugin_manifest(root) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "gpt-actions".into());

        let mut tools: Vec<ToolSurface> = Vec::new();
        let mut execution = ExecutionSurface::default();

        // Find the OpenAPI spec (prefer openapi.json, then others)
        let spec_path = find_openapi_spec(root, filter);

        if let Some(spec_path) = spec_path {
            if let Ok(content) = std::fs::read_to_string(&spec_path) {
                if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Extract server URLs as network operations
                    extract_server_urls(&spec, &spec_path, &mut execution);

                    // Extract paths as tool surfaces
                    extract_path_tools(&spec, &spec_path, &mut tools);
                }
            }
        }

        let source_files = collect_spec_source_files(root, filter);
        let dependencies = super::mcp::parse_dependencies(root, filter);
        let provenance = super::mcp::parse_provenance(root, filter);
        let data = build_data_surface(&tools, &execution);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::GptActions,
            root_path: root.to_path_buf(),
            tools,
            execution,
            data,
            dependencies,
            provenance,
            source_files,
        }])
    }
}

/// Check whether any plugin manifest file exists under root.
fn has_plugin_manifest(root: &Path) -> bool {
    for filename in PLUGIN_MANIFEST_FILENAMES {
        if root.join(filename).exists() {
            return true;
        }
    }
    root.join(".well-known").join("ai-plugin.json").exists()
}

/// Find the first OpenAPI spec file present under root, in preference order.
fn find_openapi_spec(root: &Path, filter: &ScanPathFilter) -> Option<PathBuf> {
    for filename in OPENAPI_FILENAMES {
        let path = root.join(filename);
        if path.exists() && filter.allows_path(root, &path) {
            return Some(path);
        }
    }
    None
}

/// Extract server URLs from the OpenAPI `servers` array and emit them as
/// `NetworkOperation` entries. This lets SSRF and data-exfiltration detectors
/// inspect the domains the action contacts.
fn extract_server_urls(
    spec: &serde_json::Value,
    spec_path: &Path,
    execution: &mut ExecutionSurface,
) {
    let servers = match spec.get("servers").and_then(|v| v.as_array()) {
        Some(s) => s,
        None => return,
    };

    for (idx, server) in servers.iter().enumerate() {
        let url = server
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if url.is_empty() {
            continue;
        }

        execution.network_operations.push(NetworkOperation {
            function: "openapi_server".to_string(),
            url_arg: ArgumentSource::Literal(url),
            method: None,
            sends_data: false,
            location: SourceLocation {
                file: spec_path.to_path_buf(),
                // Line numbers are not easily derivable from parsed JSON; use index as proxy
                line: idx + 1,
                column: 0,
                end_line: None,
                end_column: None,
            },
        });
    }
}

/// Extract each OpenAPI path+method as a `ToolSurface`.
///
/// Name format: `{method}_{path}` (e.g. `get_/forecast`).
/// Operation parameters are mapped to the input schema `properties`.
fn extract_path_tools(spec: &serde_json::Value, spec_path: &Path, tools: &mut Vec<ToolSurface>) {
    let paths = match spec.get("paths").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return,
    };

    const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

    for (path_str, path_item) in paths {
        let path_obj = match path_item.as_object() {
            Some(o) => o,
            None => continue,
        };

        for method in HTTP_METHODS {
            let operation = match path_obj.get(*method) {
                Some(op) => op,
                None => continue,
            };

            let tool_name = format!("{}_{}", method, path_str);
            let description = operation
                .get("summary")
                .or_else(|| operation.get("description"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let input_schema = build_input_schema_from_operation(operation);

            tools.push(ToolSurface {
                name: tool_name,
                description,
                input_schema: Some(input_schema),
                output_schema: None,
                declared_permissions: vec![],
                defined_at: Some(SourceLocation {
                    file: spec_path.to_path_buf(),
                    line: 1,
                    column: 0,
                    end_line: None,
                    end_column: None,
                }),
            });
        }
    }
}

/// Build a JSON Schema `properties` object from the operation's `parameters`
/// and `requestBody`, mirroring the shape expected by downstream detectors.
fn build_input_schema_from_operation(operation: &serde_json::Value) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<serde_json::Value> = Vec::new();

    // Path / query / header parameters
    if let Some(params) = operation.get("parameters").and_then(|v| v.as_array()) {
        for param in params {
            let name = match param.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let schema = param
                .get("schema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"type": "string"}));
            properties.insert(name.to_string(), schema);

            if param
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                required.push(serde_json::Value::String(name.to_string()));
            }
        }
    }

    // requestBody (JSON only)
    if let Some(rb_schema) = operation
        .get("requestBody")
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|m| m.get("schema"))
    {
        if let Some(props) = rb_schema.get("properties").and_then(|v| v.as_object()) {
            for (k, v) in props {
                properties.insert(k.clone(), v.clone());
            }
        }
        if let Some(req_arr) = rb_schema.get("required").and_then(|v| v.as_array()) {
            required.extend(req_arr.iter().cloned());
        }
    }

    let mut schema = serde_json::json!({
        "type": "object",
        "properties": serde_json::Value::Object(properties)
    });
    if !required.is_empty() {
        schema["required"] = serde_json::Value::Array(required);
    }
    schema
}

/// Collect OpenAPI spec files and plugin manifests as `SourceFile` entries.
///
/// We do not parse them with language parsers (there is no Rust/Python source),
/// but including them lets detectors and output formatters reference them.
fn collect_spec_source_files(root: &Path, filter: &ScanPathFilter) -> Vec<SourceFile> {
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

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Adapter;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gpt_actions")
    }

    #[test]
    fn test_detect_gpt_actions() {
        let dir = fixture_dir();
        let adapter = GptActionsAdapter;
        assert!(
            adapter.detect(&dir),
            "should detect GPT Actions fixture with ai-plugin.json + openapi.json"
        );
    }

    #[test]
    fn test_detect_non_gpt_project() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/safe_calculator");
        let adapter = GptActionsAdapter;
        assert!(
            !adapter.detect(&dir),
            "should not detect GPT Actions in an MCP calculator fixture"
        );
    }

    #[test]
    fn test_load_gpt_actions_tools() {
        let dir = fixture_dir();
        let adapter = GptActionsAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        assert_eq!(targets.len(), 1);

        let target = &targets[0];
        assert_eq!(target.framework, Framework::GptActions);

        // Fixture has /forecast (GET) and /alerts (GET) = 2 tools
        assert!(
            target.tools.len() >= 2,
            "expected at least 2 tools from openapi.json paths, got {}",
            target.tools.len()
        );

        // Tool names follow "{method}_{path}" format
        let tool_names: Vec<&str> = target.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(
            tool_names.contains(&"get_/forecast"),
            "expected 'get_/forecast' tool"
        );
        assert!(
            tool_names.contains(&"get_/alerts"),
            "expected 'get_/alerts' tool"
        );
    }

    #[test]
    fn test_load_gpt_actions_input_schema() {
        let dir = fixture_dir();
        let adapter = GptActionsAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // /forecast has parameters: location (required), days (optional)
        let forecast_tool = target
            .tools
            .iter()
            .find(|t| t.name == "get_/forecast")
            .expect("get_/forecast tool not found");

        let schema = forecast_tool
            .input_schema
            .as_ref()
            .expect("input_schema should be present");
        let props = schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("properties should be an object");

        assert!(
            props.contains_key("location"),
            "expected 'location' parameter"
        );
        assert!(props.contains_key("days"), "expected 'days' parameter");
    }

    #[test]
    fn test_load_gpt_actions_network_operations() {
        let dir = fixture_dir();
        let adapter = GptActionsAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // openapi.json has servers: [{ url: "https://api.weather.example.com" }]
        assert!(
            !target.execution.network_operations.is_empty(),
            "expected network operations from servers array"
        );

        let server_url = target
            .execution
            .network_operations
            .iter()
            .find(|op| matches!(&op.url_arg, ArgumentSource::Literal(u) if u.contains("weather.example.com")));
        assert!(
            server_url.is_some(),
            "expected weather.example.com server URL"
        );
    }

    #[test]
    fn test_load_gpt_actions_source_files() {
        let dir = fixture_dir();
        let adapter = GptActionsAdapter;
        let targets = adapter.load(&dir, false).unwrap();
        let target = &targets[0];

        // Should include openapi.json and ai-plugin.json
        assert!(
            !target.source_files.is_empty(),
            "expected source files from fixture directory"
        );

        let file_names: Vec<String> = target
            .source_files
            .iter()
            .map(|sf| {
                sf.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        assert!(
            file_names.contains(&"openapi.json".to_string()),
            "expected openapi.json in source files"
        );
    }
}
