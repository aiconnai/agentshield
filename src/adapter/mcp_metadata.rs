use std::path::{Path, PathBuf};

pub(super) fn metadata_root_for_scan(scan_root: &Path) -> Option<PathBuf> {
    if has_mcp_metadata(scan_root) {
        return Some(scan_root.to_path_buf());
    }

    if let Some(metadata_root) = ancestor_metadata_root(scan_root) {
        if contains_mcp_tool_source(scan_root) {
            return Some(metadata_root);
        }
    }

    contains_mcp_sdk_source(scan_root).then(|| scan_root.to_path_buf())
}

pub(super) fn same_path(left: &Path, right: &Path) -> bool {
    let normalized_left = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let normalized_right = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    normalized_left == normalized_right
}

fn ancestor_metadata_root(scan_root: &Path) -> Option<PathBuf> {
    scan_root
        .ancestors()
        .skip(1)
        .find(|ancestor| has_mcp_metadata(ancestor))
        .map(Path::to_path_buf)
}

fn has_mcp_metadata(root: &Path) -> bool {
    package_json_declares_mcp(root)
        || pyproject_declares_mcp(root)
        || requirements_declare_mcp(root)
        || root.join("mcp.json").exists()
        || root.join("mcp-config.json").exists()
}

fn package_json_declares_mcp(root: &Path) -> bool {
    let path = root.join("package.json");
    std::fs::read_to_string(path).is_ok_and(|content| {
        content.contains("@modelcontextprotocol/sdk") || content.contains("mcp-server")
    })
}

fn pyproject_declares_mcp(root: &Path) -> bool {
    std::fs::read_to_string(root.join("pyproject.toml"))
        .is_ok_and(|content| content.contains("mcp"))
}

fn requirements_declare_mcp(root: &Path) -> bool {
    std::fs::read_to_string(root.join("requirements.txt")).is_ok_and(|content| {
        content
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("mcp"))
    })
}

fn contains_mcp_tool_source(root: &Path) -> bool {
    contains_mcp_source(root, SourceDetectionMode::ToolSurface)
}

fn contains_mcp_sdk_source(root: &Path) -> bool {
    contains_mcp_source(root, SourceDetectionMode::SdkUsage)
}

#[derive(Debug, Clone, Copy)]
enum SourceDetectionMode {
    SdkUsage,
    ToolSurface,
}

fn contains_mcp_source(root: &Path, mode: SourceDetectionMode) -> bool {
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
        if !is_mcp_source_candidate(path) {
            continue;
        }
        if std::fs::read_to_string(path)
            .is_ok_and(|content| source_mentions_mcp(path, &content, mode))
        {
            return true;
        }
    }

    false
}

fn is_mcp_source_candidate(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("py" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
    )
}

fn source_mentions_mcp(path: &Path, content: &str, mode: SourceDetectionMode) -> bool {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("py") => {
            content.contains("from mcp")
                || content.contains("import mcp")
                || matches!(mode, SourceDetectionMode::ToolSurface)
                    && content.contains("@server.tool")
        }
        Some("ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs") => {
            content.contains("@modelcontextprotocol/sdk")
                || content.contains("McpServer")
                || matches!(mode, SourceDetectionMode::ToolSurface)
                    && (content.contains(".registerTool(") || content.contains(".tool("))
        }
        Some(_) | None => false,
    }
}
