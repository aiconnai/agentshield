use std::path::Path;

use agentshield::ir::Framework;
use agentshield::{scan, ScanOptions};
use tempfile::TempDir;

const ROOT_PACKAGE_JSON: &str = r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;
const VULNERABLE_PACKAGE_JSON: &str =
    r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0","event-stream":"3.3.6"}}"#;

const MCP_SERVER_TS: &str = r#"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo" });

server.tool("echo", "Echo input", {}, async () => ({ content: [] }));
"#;

const MCP_SERVER_PY: &str = r#"
from mcp import Server

server = Server("demo")

@server.tool("echo")
def echo(value: str) -> str:
    return "ok"
"#;

#[test]
fn subdirectory_scan_uses_ancestor_mcp_metadata_without_expanding_source_boundary() {
    let fixture = Fixture::new();
    fixture.write("package.json", ROOT_PACKAGE_JSON);
    fixture.write("src/mcp/server.ts", MCP_SERVER_TS);
    fixture.write("src/outside.ts", MCP_SERVER_TS);

    let scan_root = fixture.path().join("src/mcp");
    let report = scan(&scan_root, &ScanOptions::default()).unwrap();

    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0];
    assert_eq!(target.framework, Framework::Mcp);
    assert_eq!(
        target.root_path.canonicalize().unwrap(),
        fixture.canonical_root()
    );
    assert!(target
        .dependencies
        .dependencies
        .iter()
        .any(|dep| dep.name == "@modelcontextprotocol/sdk"));
    assert_eq!(source_paths(&report), vec!["server.ts"]);

    let rendered = agentshield::ux::render_explain(
        &report,
        &agentshield::ux::ExplainOptions {
            ignore_tests: false,
        },
    );

    assert!(rendered.contains("- Scan root:"));
    assert!(rendered.contains("- Metadata root:"));
}

#[test]
fn subdirectory_scan_detects_typescript_mcp_source_without_root_package() {
    let fixture = Fixture::new();
    fixture.write("src/mcp/server.ts", MCP_SERVER_TS);

    let scan_root = fixture.path().join("src/mcp");
    let report = scan(&scan_root, &ScanOptions::default()).unwrap();

    assert_eq!(report.targets.len(), 1);
    assert_eq!(report.targets[0].framework, Framework::Mcp);
    assert_eq!(
        report.targets[0].root_path.canonicalize().unwrap(),
        scan_root.canonicalize().unwrap()
    );
    assert_eq!(source_paths(&report), vec!["server.ts"]);
}

#[test]
fn subdirectory_scan_honors_metadata_root_exclude_for_package_json() {
    let fixture = Fixture::new();
    fixture.write("package.json", VULNERABLE_PACKAGE_JSON);
    fixture.write(
        ".agentshield.toml",
        "[scan]\nexclude = [\"package.json\"]\n",
    );
    fixture.write("src/mcp/server.ts", MCP_SERVER_TS);

    let report = scan(
        &fixture.path().join("src/mcp"),
        &ScanOptions {
            config_path: Some(fixture.path().join(".agentshield.toml")),
            ..ScanOptions::default()
        },
    )
    .unwrap();

    assert_eq!(source_paths(&report), vec!["server.ts"]);
    assert_no_finding_from(&report, "package.json");
    assert!(report.targets[0].dependencies.dependencies.is_empty());
}

#[test]
fn subdirectory_scan_honors_metadata_root_exclude_for_requirements_txt() {
    let fixture = Fixture::new();
    fixture.write("requirements.txt", "mcp==1.0.0\nevent-stream==3.3.6\n");
    fixture.write(
        ".agentshield.toml",
        "[scan]\nexclude = [\"requirements.txt\"]\n",
    );
    fixture.write("src/mcp/server.py", MCP_SERVER_PY);

    let report = scan(
        &fixture.path().join("src/mcp"),
        &ScanOptions {
            config_path: Some(fixture.path().join(".agentshield.toml")),
            ..ScanOptions::default()
        },
    )
    .unwrap();

    assert_eq!(source_paths(&report), vec!["server.py"]);
    assert_no_finding_from(&report, "requirements.txt");
    assert!(report.targets[0].dependencies.dependencies.is_empty());
}

#[test]
fn subdirectory_scan_honors_metadata_root_include_for_package_json() {
    let fixture = Fixture::new();
    fixture.write("package.json", VULNERABLE_PACKAGE_JSON);
    fixture.write(".agentshield.toml", "[scan]\ninclude = [\"server.ts\"]\n");
    fixture.write("src/mcp/server.ts", MCP_SERVER_TS);

    let report = scan(
        &fixture.path().join("src/mcp"),
        &ScanOptions {
            config_path: Some(fixture.path().join(".agentshield.toml")),
            ..ScanOptions::default()
        },
    )
    .unwrap();

    assert_eq!(source_paths(&report), vec!["server.ts"]);
    assert_no_finding_from(&report, "package.json");
    assert!(report.targets[0].dependencies.dependencies.is_empty());
}

struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn canonical_root(&self) -> std::path::PathBuf {
        self.dir.path().canonicalize().unwrap()
    }

    fn write(&self, relative_path: &str, content: &str) {
        let path = self.dir.path().join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }
}

fn source_paths(report: &agentshield::ScanReport) -> Vec<String> {
    report
        .targets
        .iter()
        .flat_map(|target| target.source_files.iter())
        .map(|source| relative_path(&report.scan_root, &source.path))
        .collect()
}

fn assert_no_finding_from(report: &agentshield::ScanReport, file_name: &str) {
    assert!(
        !report.findings.iter().any(|finding| finding
            .location
            .as_ref()
            .is_some_and(|location| location.file.ends_with(file_name))),
        "expected no findings from {file_name}, got: {:?}",
        report
            .findings
            .iter()
            .map(|finding| (
                finding.rule_id.as_str(),
                finding
                    .location
                    .as_ref()
                    .map(|location| location.file.clone())
            ))
            .collect::<Vec<_>>()
    );
}

fn relative_path(root: &Path, path: &Path) -> String {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    canonical_path
        .strip_prefix(&canonical_root)
        .unwrap_or(path)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            std::path::Component::CurDir => None,
            std::path::Component::ParentDir => Some("..".to_string()),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => None,
        })
        .collect::<Vec<String>>()
        .join("/")
}
