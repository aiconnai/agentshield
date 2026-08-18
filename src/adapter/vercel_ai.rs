use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::capability::{project_declared_description, project_declared_permissions};
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

static VERCEL_TOOL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)(?:const|let|var|export\s+const|export\s+let)\s+(\w+)\s*=\s*tool\s*\(\s*\{(?:\s*description\s*:\s*["'`]([^"'`]+)["'`])?"#)
        .expect("static regex pattern is valid")
});

static VERCEL_PROPERTY_DESC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(\w+)\s*:\s*z\.\w+\([^)]*\)\.describe\(\s*["'`]([^"'`]+)["'`]\s*\)"#)
        .expect("static regex pattern is valid")
});

/// Vercel AI SDK adapter (`ai` and `@ai-sdk/*`).
///
/// Detects Vercel AI SDK projects by looking for:
/// - `package.json` with `ai` or `@ai-sdk/*` dependencies
/// - `ai.config.ts` or `ai.config.js`
/// - TypeScript / JavaScript files importing `from "ai"` or `from "@ai-sdk/"`
pub struct VercelAiAdapter;

impl super::Adapter for VercelAiAdapter {
    fn framework(&self) -> Framework {
        Framework::VercelAi
    }

    fn detect(&self, root: &Path) -> bool {
        let package_json = root.join("package.json");
        if package_json.exists() {
            if let Some(content) = super::read_file_capped(&package_json) {
                if content.contains("\"ai\"")
                    || content.contains("@ai-sdk/")
                    || content.contains("\"@ai-sdk/openai\"")
                    || content.contains("\"@ai-sdk/anthropic\"")
                {
                    return true;
                }
            }
        }

        if root.join("ai.config.ts").exists() || root.join("ai.config.js").exists() {
            return true;
        }

        let walker = ignore::WalkBuilder::new(root)
            .hidden(true)
            .git_ignore(true)
            .max_depth(Some(4))
            .build();

        for entry in walker.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
            if !matches!(ext, "ts" | "tsx" | "js" | "jsx" | "mjs") {
                continue;
            }

            if let Some(content) = super::read_file_capped(path) {
                if content.contains("from 'ai'")
                    || content.contains("from \"ai\"")
                    || content.contains("from '@ai-sdk/")
                    || content.contains("from \"@ai-sdk/")
                {
                    return true;
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
            .unwrap_or_else(|| "vercel-ai-project".into());

        let mut source_files = Vec::new();
        super::mcp::collect_source_files_with_filter(root, filter, &mut source_files)?;

        source_files.retain(|sf| {
            matches!(
                sf.language,
                Language::TypeScript | Language::JavaScript
            )
        });

        let mut tools = Vec::new();
        for sf in &source_files {
            tools.extend(extract_vercel_ai_tools_from_source(&sf.path, &sf.content));
        }

        for tool in &mut tools {
            project_declared_permissions(tool);
            project_declared_description(tool);
        }

        let execution = super::pipeline::build_execution_surface(&source_files);
        let data = build_data_surface(&tools, &execution);
        let dependencies = super::mcp::parse_dependencies(root, filter);
        let provenance = super::mcp::parse_provenance(root, filter);

        Ok(vec![ScanTarget {
            name,
            framework: Framework::VercelAi,
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

pub(crate) fn extract_vercel_ai_tools_from_source(path: &Path, content: &str) -> Vec<ToolSurface> {
    let mut tools = Vec::new();

    for cap in VERCEL_TOOL_RE.captures_iter(content) {
        let tool_name = cap[1].to_string();
        let description = cap.get(2).map(|m| m.as_str().to_string());
        let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line = content[..match_start].lines().count() + 1;

        let tool_snippet = &content[match_start..(match_start + 1500).min(content.len())];
        let mut parameter_descriptions = Vec::new();

        for prop_cap in VERCEL_PROPERTY_DESC_RE.captures_iter(tool_snippet) {
            let prop_name = prop_cap[1].to_string();
            let prop_desc = prop_cap[2].to_string();
            parameter_descriptions.push(format!("{prop_name}: {prop_desc}"));
        }

        let combined_desc = if !parameter_descriptions.is_empty() {
            let params_text = parameter_descriptions.join("\n");
            match description {
                Some(desc) => Some(format!("{desc}\nParameters:\n{params_text}")),
                None => Some(format!("Parameters:\n{params_text}")),
            }
        } else {
            description
        };

        tools.push(ToolSurface {
            name: tool_name,
            description: combined_desc,
            input_schema: None,
            output_schema: None,
            declared_permissions: Vec::new(),
            declared_capabilities: std::collections::BTreeSet::new(),
            capability_declarations: Vec::new(),
            observed_capabilities: std::collections::BTreeSet::new(),
            capability_evidence: Vec::new(),
            capability_observation_complete: false,
            defined_at: Some(SourceLocation {
                file: path.to_path_buf(),
                line,
                column: 0,
                end_line: Some(line),
                end_column: None,
            }),
        });
    }

    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Adapter;

    #[test]
    fn detects_vercel_ai_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        std::fs::write(&pkg, r#"{"dependencies": {"ai": "^3.1.0"}}"#).unwrap();

        let adapter = VercelAiAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detects_vercel_ai_import() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("tool.ts");
        std::fs::write(&src, "import { tool } from 'ai';\n").unwrap();

        let adapter = VercelAiAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn extracts_vercel_ai_tool_declarations() {
        let content = r#"
import { tool } from 'ai';
import { z } from 'zod';

export const getWeather = tool({
  description: 'Get the current weather for a city',
  parameters: z.object({
    city: z.string().describe('The target city name'),
  }),
  execute: async ({ city }) => {
    return fetch(`https://api.weather.com/${city}`);
  },
});
"#;
        let tools = extract_vercel_ai_tools_from_source(Path::new("tools.ts"), content);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "getWeather");
        assert!(tools[0].description.as_deref().unwrap().contains("weather for a city"));
        assert!(tools[0].description.as_deref().unwrap().contains("The target city name"));
        assert_eq!(tools[0].defined_at.as_ref().unwrap().line, 5);
    }
}
