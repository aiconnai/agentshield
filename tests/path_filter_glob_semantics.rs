use std::path::Path;

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
fn wildcard_segment_does_not_cross_directories_when_excluding() {
    let fixture = FilterFixture::new();
    fixture.write(".agentshield.toml", "[scan]\nexclude = [\"*.py\"]\n");
    fixture.write("src/vulnerable.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/vulnerable.py".to_string()));
    assert!(has_shield_001_for_file(&report, "src/vulnerable.py"));
}

#[test]
fn trailing_slash_excludes_directory_contents() {
    let fixture = FilterFixture::new();
    fixture.write(".agentshield.toml", "[scan]\nexclude = [\"legacy/\"]\n");
    fixture.write("src/safe.py", SAFE_TOOL);
    fixture.write("legacy/vulnerable.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/safe.py".to_string()));
    assert!(!source_paths(&report).contains(&"legacy/vulnerable.py".to_string()));
    assert!(!has_shield_001_for_file(&report, "legacy/vulnerable.py"));
}

#[test]
fn dot_slash_patterns_are_relative_to_scan_root() {
    let fixture = FilterFixture::new();
    fixture.write(".agentshield.toml", "[scan]\ninclude = [\"./src/**\"]\n");
    fixture.write("src/vulnerable.py", VULNERABLE_TOOL);
    fixture.write("legacy/vulnerable.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/vulnerable.py".to_string()));
    assert!(!source_paths(&report).contains(&"legacy/vulnerable.py".to_string()));
    assert!(has_shield_001_for_file(&report, "src/vulnerable.py"));
}

#[test]
fn double_star_prefix_matches_root_and_nested_directories() {
    let fixture = FilterFixture::new();
    fixture.write(
        ".agentshield.toml",
        "[scan]\nexclude = [\"**/generated/**\"]\n",
    );
    fixture.write("src/safe.py", SAFE_TOOL);
    fixture.write("generated/root.py", VULNERABLE_TOOL);
    fixture.write("src/generated/nested.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/safe.py".to_string()));
    assert!(!source_paths(&report).contains(&"generated/root.py".to_string()));
    assert!(!source_paths(&report).contains(&"src/generated/nested.py".to_string()));
    assert!(!has_shield_001_for_file(&report, "generated/root.py"));
    assert!(!has_shield_001_for_file(&report, "src/generated/nested.py"));
}

#[test]
fn path_filters_are_case_sensitive() {
    let fixture = FilterFixture::new();
    fixture.write(".agentshield.toml", "[scan]\nexclude = [\"SRC/**\"]\n");
    fixture.write("src/vulnerable.py", VULNERABLE_TOOL);

    let report = scan(fixture.path(), &ScanOptions::default()).unwrap();

    assert!(source_paths(&report).contains(&"src/vulnerable.py".to_string()));
    assert!(has_shield_001_for_file(&report, "src/vulnerable.py"));
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

fn has_shield_001_for_file(report: &agentshield::ScanReport, suffix: &str) -> bool {
    report.findings.iter().any(|finding| {
        finding.rule_id == "SHIELD-001"
            && finding
                .location
                .as_ref()
                .is_some_and(|location| location.file.ends_with(suffix))
    })
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
