use std::path::Path;

use agentshield::ux::ExplainOptions;
use agentshield::{scan, ScanOptions};
use tempfile::TempDir;

const PACKAGE_JSON: &str = r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;

const VULNERABLE_TOOL: &str = r#"
import subprocess
from mcp import Server

server = Server("filtered")

@server.tool("run")
def run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
"#;

const SAFE_TOOL: &str = r#"
from mcp import Server

server = Server("safe")

@server.tool("echo")
def echo(value: str) -> str:
    return "ok"
"#;

#[test]
fn include_only_paths_when_configured() {
    let fixture = FilterFixture::new();
    fixture.write(".agentshield.toml", "[scan]\ninclude = [\"src/**\"]\n");
    fixture.write("src/allowed.py", VULNERABLE_TOOL);
    fixture.write("legacy/excluded.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/allowed.py".to_string()));
    assert!(!source_paths(&report).contains(&"legacy/excluded.py".to_string()));
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "SHIELD-001"
            && finding
                .location
                .as_ref()
                .is_some_and(|location| location.file.ends_with("src/allowed.py"))
    }));
}

#[test]
fn exclude_paths_when_configured() {
    let fixture = FilterFixture::new();
    fixture.write(".agentshield.toml", "[scan]\nexclude = [\"legacy/**\"]\n");
    fixture.write("src/safe.py", SAFE_TOOL);
    fixture.write("legacy/vulnerable.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/safe.py".to_string()));
    assert!(!source_paths(&report).contains(&"legacy/vulnerable.py".to_string()));
    assert!(!report.findings.iter().any(|finding| {
        finding.rule_id == "SHIELD-001"
            && finding
                .location
                .as_ref()
                .is_some_and(|location| location.file.ends_with("legacy/vulnerable.py"))
    }));
}

#[test]
fn exclude_wins_over_include_when_both_match() {
    let fixture = FilterFixture::new();
    fixture.write(
        ".agentshield.toml",
        "[scan]\ninclude = [\"src/**\"]\nexclude = [\"src/generated/**\"]\n",
    );
    fixture.write("src/main.py", VULNERABLE_TOOL);
    fixture.write("src/generated/skip.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/main.py".to_string()));
    assert!(!source_paths(&report).contains(&"src/generated/skip.py".to_string()));
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "SHIELD-001"
            && finding
                .location
                .as_ref()
                .is_some_and(|location| location.file.ends_with("src/main.py"))
    }));
    assert!(!report.findings.iter().any(|finding| {
        finding.rule_id == "SHIELD-001"
            && finding
                .location
                .as_ref()
                .is_some_and(|location| location.file.ends_with("src/generated/skip.py"))
    }));
}

#[test]
fn explain_reports_path_filters_when_configured() {
    let fixture = FilterFixture::new();
    fixture.write(
        ".agentshield.toml",
        "[scan]\ninclude = [\"src/**\"]\nexclude = [\"src/generated/**\"]\n",
    );
    fixture.write("src/main.py", SAFE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();
    let rendered = agentshield::ux::render_explain(
        &report,
        &ExplainOptions {
            ignore_tests: false,
        },
    );

    assert!(rendered.contains("- Path filters: include src/**; exclude src/generated/**"));
}

struct FilterFixture {
    dir: TempDir,
}

impl FilterFixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let fixture = Self { dir };
        fixture.write("package.json", PACKAGE_JSON);
        fixture
    }

    fn path(&self) -> &Path {
        self.dir.path()
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
