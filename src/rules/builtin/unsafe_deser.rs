use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-016: Unsafe Deserialization
///
/// Detects unsafe deserialization functions that can execute arbitrary code
/// when processing untrusted input (CWE-502).
pub struct UnsafeDeserDetector;

/// Python unsafe deserializers that can execute arbitrary code.
const UNSAFE_DESERIALIZERS: &[&str] = &[
    "pickle.load",
    "pickle.loads",
    "yaml.unsafe_load",
    "yaml.full_load",
    "marshal.load",
    "marshal.loads",
    "shelve.open",
    "jsonpickle.decode",
    "jsonpickle.loads",
];

/// `yaml.load` is only unsafe when used without `Loader=SafeLoader`.
const YAML_LOAD: &str = "yaml.load";

/// JavaScript/TypeScript unsafe patterns in dynamic exec.
const JS_UNSAFE_PATTERNS: &[&str] = &[
    "vm.runInContext",
    "vm.runInNewContext",
    "vm.runInThisContext",
    "Function(",
    "new Function(",
];

/// Check if a function name matches an unsafe deserializer.
fn is_unsafe_deserializer(function: &str) -> Option<&'static str> {
    let func_lower = function.to_lowercase();
    UNSAFE_DESERIALIZERS
        .iter()
        .find(|deser| func_lower.contains(&deser.to_lowercase()))
        .copied()
}

impl Detector for UnsafeDeserDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-016".into(),
            name: "Unsafe Deserialization".into(),
            description: "Unsafe deserialization functions that can execute arbitrary code \
                          when processing untrusted input"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::CodeInjection,
            cwe_id: Some("CWE-502".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Check dynamic_exec for known unsafe deserializers
        for dyn_exec in &target.execution.dynamic_exec {
            if let Some(deser) = is_unsafe_deserializer(&dyn_exec.function) {
                findings.push(Finding {
                    rule_id: "SHIELD-016".into(),
                    rule_name: "Unsafe Deserialization".into(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::CodeInjection,
                    message: format!(
                        "'{}' uses unsafe deserializer '{}' — can execute arbitrary code",
                        dyn_exec.function, deser
                    ),
                    location: Some(dyn_exec.location.clone()),
                    evidence: vec![Evidence {
                        description: format!(
                            "Unsafe deserializer '{deser}' found in dynamic execution"
                        ),
                        location: Some(dyn_exec.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Replace unsafe deserializers with safe alternatives: use \
                         `json.loads()` instead of `pickle.loads()`, \
                         `yaml.safe_load()` instead of `yaml.load()`, \
                         or schema-validated JSON parsing."
                            .into(),
                    ),
                    cwe_id: Some("CWE-502".into()),
                });
                continue;
            }

            // Check for JS unsafe patterns
            for pattern in JS_UNSAFE_PATTERNS {
                if dyn_exec.function.contains(pattern) {
                    findings.push(Finding {
                        rule_id: "SHIELD-016".into(),
                        rule_name: "Unsafe Deserialization".into(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CodeInjection,
                        message: format!(
                            "'{}' uses unsafe code execution pattern '{}' \
                             — can execute arbitrary code",
                            dyn_exec.function, pattern
                        ),
                        location: Some(dyn_exec.location.clone()),
                        evidence: vec![Evidence {
                            description: format!("Unsafe code execution pattern '{pattern}'"),
                            location: Some(dyn_exec.location.clone()),
                            snippet: None,
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Avoid `vm.runInContext` and `new Function()` for \
                             deserializing data. Use `JSON.parse()` with schema \
                             validation instead."
                                .into(),
                        ),
                        cwe_id: Some("CWE-502".into()),
                    });
                    break;
                }
            }
        }

        // Phase 2: Scan source files for yaml.load without SafeLoader
        for source_file in &target.source_files {
            for (line_idx, line) in source_file.content.lines().enumerate() {
                if line.contains(YAML_LOAD)
                    && !line.contains("safe_load")
                    && !line.contains("SafeLoader")
                    && !line.contains("yaml.safe_load")
                    && !line.contains("CSafeLoader")
                    // Exclude import lines
                    && !line.trim_start().starts_with("import")
                    && !line.trim_start().starts_with("from")
                {
                    findings.push(Finding {
                        rule_id: "SHIELD-016".into(),
                        rule_name: "Unsafe Deserialization".into(),
                        severity: Severity::Critical,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::CodeInjection,
                        message: format!(
                            "'yaml.load' used without SafeLoader in {} — can execute \
                             arbitrary code",
                            source_file.path.display()
                        ),
                        location: Some(crate::ir::SourceLocation {
                            file: source_file.path.clone(),
                            line: line_idx + 1,
                            column: 0,
                            end_line: None,
                            end_column: None,
                        }),
                        evidence: vec![Evidence {
                            description: "yaml.load without SafeLoader".into(),
                            location: Some(crate::ir::SourceLocation {
                                file: source_file.path.clone(),
                                line: line_idx + 1,
                                column: 0,
                                end_line: None,
                                end_column: None,
                            }),
                            snippet: Some(line.trim().to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Use `yaml.safe_load()` or `yaml.load(data, Loader=SafeLoader)` \
                             instead of `yaml.load(data)`."
                                .into(),
                        ),
                        cwe_id: Some("CWE-502".into()),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
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
    fn detects_yaml_load_without_safe_loader() {
        let mut target = empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("config.py"),
            language: Language::Python,
            content: "import yaml\ndata = yaml.load(user_input)\n".into(),
            size_bytes: 40,
            content_hash: "abc123".into(),
        });

        let findings = UnsafeDeserDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("yaml.load"));
        assert!(findings[0].message.contains("without SafeLoader"));
    }

    #[test]
    fn no_finding_for_yaml_safe_load() {
        let mut target = empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("config.py"),
            language: Language::Python,
            content: "import yaml\ndata = yaml.safe_load(user_input)\n".into(),
            size_bytes: 45,
            content_hash: "abc123".into(),
        });

        let findings = UnsafeDeserDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_for_yaml_load_with_safe_loader() {
        let mut target = empty_target();
        target.source_files.push(SourceFile {
            path: PathBuf::from("config.py"),
            language: Language::Python,
            content: "import yaml\ndata = yaml.load(user_input, Loader=SafeLoader)\n".into(),
            size_bytes: 55,
            content_hash: "abc123".into(),
        });

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
}
