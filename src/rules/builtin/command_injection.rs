use crate::ir::{ArgumentSource, ScanTarget, SinkClass};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-001: Command Injection
///
/// Flags subprocess/os.system execution when command argument source is
/// Parameter, Interpolated, or Unknown. Literal remains pass unless literal
/// includes shell metacharacter expansion patterns.
pub struct CommandInjectionDetector;

impl Detector for CommandInjectionDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-001".into(),
            name: "Command Injection".into(),
            description: "Subprocess or system command with untrusted input as argument".into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::CommandInjection,
            cwe_id: Some("CWE-78".into()),
            owasp_mcp: Some(OwaspMcp::CommandExecution),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cmd in &target.execution.commands {
            let (should_flag, confidence) = match &cmd.command_arg {
                ArgumentSource::Parameter { .. } => (true, Confidence::High),
                ArgumentSource::Interpolated => (true, Confidence::High),
                ArgumentSource::Unknown => (true, Confidence::Medium),
                ArgumentSource::Literal(val) => {
                    // Flag literals with shell metacharacters that expand variables
                    let has_expansion = val.contains('$') || val.contains('`');
                    (has_expansion, Confidence::Medium)
                }
                ArgumentSource::EnvVar { .. } => (true, Confidence::Medium),
                // A sanitizer clears command taint only if it guards a command
                // sink. No sanitizer category currently does (type coercion is
                // not shell-escaping), so a wrong-category sanitizer stays
                // flagged rather than silently suppressing the finding.
                ArgumentSource::Sanitized { .. } => (
                    cmd.command_arg.is_tainted_for_sink(SinkClass::Command),
                    Confidence::High,
                ),
            };

            if should_flag {
                let param_desc = match &cmd.command_arg {
                    ArgumentSource::Parameter { name } => {
                        format!("parameter '{name}'")
                    }
                    ArgumentSource::Interpolated => "interpolated string".into(),
                    ArgumentSource::EnvVar { name } => format!("env var '{name}'"),
                    ArgumentSource::Literal(val) => {
                        format!("literal with shell expansion: '{val}'")
                    }
                    ArgumentSource::Unknown => "unknown source".into(),
                    ArgumentSource::Sanitized { .. } => unreachable!(),
                };

                findings.push(Finding {
                    rule_id: "SHIELD-001".into(),
                    rule_name: "Command Injection".into(),
                    severity: Severity::Critical,
                    confidence,
                    attack_category: AttackCategory::CommandInjection,
                    message: format!(
                        "'{}' receives {} as command argument",
                        cmd.function, param_desc
                    ),
                    location: Some(cmd.location.clone()),
                    evidence: vec![Evidence {
                        description: format!(
                            "{} flows into '{}'",
                            param_desc, cmd.function
                        ),
                        location: Some(cmd.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Validate and sanitize the input, or use an allowlist of permitted commands. \
                         Avoid shell=True when possible."
                            .into(),
                    ),
                    cwe_id: Some("CWE-78".into()),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::execution_surface::{CommandInvocation, ExecutionSurface};
    use crate::ir::{Framework, SourceLocation};
    use std::path::PathBuf;

    fn make_target(commands: Vec<CommandInvocation>) -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                commands,
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    fn loc() -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("test.py"),
            line: 1,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_parameter_source() {
        let target = make_target(vec![CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: ArgumentSource::Parameter { name: "cmd".into() },
            location: loc(),
        }]);
        let findings = CommandInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-001");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn passes_safe_literal() {
        let target = make_target(vec![CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: ArgumentSource::Literal("ls -la".into()),
            location: loc(),
        }]);
        let findings = CommandInjectionDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_literal_with_shell_expansion() {
        let target = make_target(vec![CommandInvocation {
            function: "os.system".into(),
            command_arg: ArgumentSource::Literal("echo $USER".into()),
            location: loc(),
        }]);
        let findings = CommandInjectionDetector.run(&target);
        assert_eq!(findings.len(), 1);
    }
}
