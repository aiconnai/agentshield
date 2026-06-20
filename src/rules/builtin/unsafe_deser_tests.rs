use super::*;
use crate::ir::execution_surface::*;
use crate::ir::*;
use std::path::PathBuf;

fn loc() -> SourceLocation {
    SourceLocation {
        file: PathBuf::from("test.py"),
        line: 5,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

fn empty_target() -> ScanTarget {
    ScanTarget {
        name: "test".into(),
        framework: Framework::Mcp,
        root_path: PathBuf::from("."),
        tools: vec![],
        execution: ExecutionSurface::default(),
        data: DataSurface::default(),
        dependencies: Default::default(),
        provenance: Default::default(),
        source_files: vec![],
    }
}

fn target_with_source(language: Language, content: &str) -> ScanTarget {
    let mut target = empty_target();
    target.source_files.push(SourceFile {
        path: PathBuf::from("loader.py"),
        language,
        content: content.into(),
        size_bytes: content.len() as u64,
        content_hash: "abc123".into(),
    });
    target
}

#[test]
fn detects_pickle_loads() {
    let mut target = empty_target();
    target.execution.dynamic_exec.push(DynamicExec {
        function: "pickle.loads".into(),
        code_arg: ArgumentSource::Parameter {
            name: "data".into(),
        },
        location: loc(),
    });

    let findings = UnsafeDeserDetector.run(&target);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SHIELD-016");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn detects_pickle_loads_in_source_file() {
    let target = target_with_source(
        Language::Python,
        "import pickle\ndata = pickle.loads(user_input)\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("pickle.loads"));
}

#[test]
fn ignores_pickle_loads_in_python_comment() {
    let target = target_with_source(
        Language::Python,
        "result = data\n# pickle.loads(user_input)\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert!(findings.is_empty());
}

#[test]
fn ignores_pickle_loads_in_python_string_literal() {
    let target = target_with_source(
        Language::Python,
        "message = \"pickle.loads(user_input)\"\nother = 'marshal.loads(data)'\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert!(findings.is_empty());
}

#[test]
fn ignores_pickle_loads_in_python_triple_quoted_string() {
    let target = target_with_source(
        Language::Python,
        "\"\"\"\npickle.loads(user_input)\n\"\"\"\nresult = data\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert!(findings.is_empty());
}

#[test]
fn detects_yaml_load_without_safe_loader() {
    let target = target_with_source(
        Language::Python,
        "import yaml\ndata = yaml.load(user_input)\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("yaml.load"));
    assert!(findings[0].message.contains("without SafeLoader"));
}

#[test]
fn no_finding_for_yaml_safe_load() {
    let target = target_with_source(
        Language::Python,
        "import yaml\ndata = yaml.safe_load(user_input)\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert!(findings.is_empty());
}

#[test]
fn no_finding_for_yaml_load_with_safe_loader() {
    let target = target_with_source(
        Language::Python,
        "import yaml\ndata = yaml.load(user_input, Loader=SafeLoader)\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert!(findings.is_empty());
}

#[test]
fn detects_vm_run_in_context() {
    let mut target = empty_target();
    target.execution.dynamic_exec.push(DynamicExec {
        function: "vm.runInNewContext".into(),
        code_arg: ArgumentSource::Parameter {
            name: "code".into(),
        },
        location: loc(),
    });

    let findings = UnsafeDeserDetector.run(&target);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("vm.runInNewContext"));
}

#[test]
fn ignores_yaml_load_in_markdown() {
    let target = target_with_source(
        Language::Markdown,
        "We can do yaml.load(user_input) here in docs.\n",
    );

    let findings = UnsafeDeserDetector.run(&target);
    assert!(findings.is_empty());
}
