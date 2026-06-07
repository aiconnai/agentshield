use crate::ir::{ScanTarget, SinkClass};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-011: Dynamic Code Execution
///
/// Flags eval/exec/compile/__import__ with non-literal arguments.
/// Dynamic code execution with user-controlled input is a critical
/// code injection vulnerability.
pub struct DynamicExecDetector;

impl Detector for DynamicExecDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-011".into(),
            name: "Dynamic Code Execution".into(),
            description: "eval/exec/compile with non-literal argument".into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::CodeInjection,
            cwe_id: Some("CWE-95".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for exec in &target.execution.dynamic_exec {
            if !exec.code_arg.is_tainted_for_sink(SinkClass::DynamicExec) {
                continue; // Literal eval("1+1") is safe
            }

            let (confidence, detail) = match &exec.code_arg {
                crate::ir::ArgumentSource::Parameter { name } => {
                    (Confidence::High, format!("from parameter '{}'", name))
                }
                crate::ir::ArgumentSource::Interpolated => {
                    (Confidence::High, "from interpolated string".into())
                }
                crate::ir::ArgumentSource::Unknown => {
                    (Confidence::Medium, "from unknown source".into())
                }
                crate::ir::ArgumentSource::EnvVar { name } => {
                    (Confidence::Medium, format!("from env var '{}'", name))
                }
                // Reached only past the is_tainted_for_sink(DynamicExec) gate
                // above, i.e. a sanitizer of the wrong category (e.g. a type
                // coercion or path validator guarding an eval sink).
                crate::ir::ArgumentSource::Sanitized { sanitizer } => (
                    Confidence::High,
                    format!("from wrong-category sanitizer '{sanitizer}'"),
                ),
                crate::ir::ArgumentSource::Literal(_) => continue,
            };

            findings.push(Finding {
                rule_id: "SHIELD-011".into(),
                rule_name: "Dynamic Code Execution".into(),
                severity: Severity::Critical,
                confidence,
                attack_category: AttackCategory::CodeInjection,
                message: format!(
                    "'{}' executes code {} — arbitrary code injection risk",
                    exec.function, detail
                ),
                location: Some(exec.location.clone()),
                evidence: vec![Evidence {
                    description: format!("Dynamic code execution via '{}'", exec.function),
                    location: Some(exec.location.clone()),
                    snippet: None,
                }],
                taint_path: None,
                remediation: Some(
                    "Never pass user-controlled input to eval/exec. Use a safe \
                     expression parser (e.g., ast.literal_eval) or a sandboxed environment."
                        .into(),
                ),
                cwe_id: Some("CWE-95".into()),
            });
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
            file: PathBuf::from("server.py"),
            line: 10,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_eval_with_parameter() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                dynamic_exec: vec![DynamicExec {
                    function: "eval".into(),
                    code_arg: ArgumentSource::Parameter {
                        name: "expression".into(),
                    },
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = DynamicExecDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn passes_literal_eval() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                dynamic_exec: vec![DynamicExec {
                    function: "eval".into(),
                    code_arg: ArgumentSource::Literal("1+1".into()),
                    location: loc(),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };
        let findings = DynamicExecDetector.run(&target);
        assert!(findings.is_empty());
    }
}
