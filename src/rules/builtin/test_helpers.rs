use std::path::PathBuf;

use crate::adapter::auto_detect_and_load;
use crate::ir::dependency_surface::Dependency;
use crate::ir::execution_surface::{CommandInvocation, FileOperation};
use crate::ir::{
    DataSurface, DependencySurface, ExecutionSurface, Framework, Language, ProvenanceSurface,
    ScanTarget, SourceFile, SourceLocation,
};
use crate::rules::{Finding, RuleEngine};

pub(crate) fn loc() -> SourceLocation {
    loc_at("test.py", 5)
}

pub(crate) fn loc_at(file: &str, line: usize) -> SourceLocation {
    SourceLocation {
        file: PathBuf::from(file),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

pub(crate) fn empty_target() -> ScanTarget {
    ScanTarget {
        name: "test".into(),
        framework: Framework::Mcp,
        root_path: PathBuf::from("/test"),
        tools: Vec::new(),
        execution: ExecutionSurface::default(),
        data: DataSurface::default(),
        dependencies: DependencySurface::default(),
        provenance: ProvenanceSurface::default(),
        source_files: Vec::new(),
    }
}

pub(crate) fn target_with_commands(commands: Vec<CommandInvocation>) -> ScanTarget {
    let mut target = empty_target();
    target.execution.commands = commands;
    target
}

pub(crate) fn target_with_file_ops(file_operations: Vec<FileOperation>) -> ScanTarget {
    let mut target = empty_target();
    target.execution.file_operations = file_operations;
    target
}

pub(crate) fn target_with_deps(dependencies: Vec<Dependency>) -> ScanTarget {
    let mut target = empty_target();
    target.dependencies.dependencies = dependencies;
    target
}

pub(crate) fn make_target_from_files(files: Vec<(&str, Language, &str)>) -> ScanTarget {
    let mut target = empty_target();
    target.source_files = files
        .into_iter()
        .map(|(path, language, content)| SourceFile {
            path: PathBuf::from(path),
            language,
            size_bytes: content.len() as u64,
            content_hash: "hash".into(),
            content: content.into(),
        })
        .collect();
    target
}

pub(crate) fn make_target_with_source(filename: &str, content: &str, lang: Language) -> ScanTarget {
    make_target_from_files(vec![(filename, lang, content)])
}

pub(crate) fn make_target_with_lang_source(content: &str, lang: Language) -> ScanTarget {
    let filename = match lang {
        Language::Python => "tool.py",
        Language::TypeScript => "tool.ts",
        Language::JavaScript => "tool.js",
        _ => "tool.txt",
    };
    make_target_with_source(filename, content, lang)
}

pub(crate) fn fixture_findings(name: &str) -> Vec<Finding> {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_servers")
        .join(name);
    let engine = RuleEngine::new();

    auto_detect_and_load(&fixture_path, false)
        .unwrap_or_else(|err| panic!("failed to load fixture {name}: {err}"))
        .iter()
        .flat_map(|target| engine.run(target))
        .collect()
}

#[test]
fn vuln_ts_cmd_inject_fixture_triggers_invariant_rules() {
    let findings = fixture_findings("vuln_ts_cmd_inject");

    for expected_rule in ["SHIELD-001", "SHIELD-003", "SHIELD-004", "SHIELD-011"] {
        assert!(
            findings.iter().any(|f| f.rule_id == expected_rule),
            "expected vuln_ts_cmd_inject fixture to trigger {expected_rule}, got rules: {:?}",
            findings
                .iter()
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "typescript")]
    assert!(
        findings.iter().any(|f| f.rule_id == "SHIELD-002"),
        "expected vuln_ts_cmd_inject fixture to trigger SHIELD-002 with typescript AST enabled"
    );
}
