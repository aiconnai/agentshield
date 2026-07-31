use crate::analysis::runtime_install::is_runtime_install_command;
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-005: Runtime Package Install
///
/// Flags runtime package install commands (pip install, npm install,
/// uv pip install) in executable code paths.
pub struct RuntimeInstallDetector;

impl Detector for RuntimeInstallDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-005".into(),
            name: "Runtime Package Install".into(),
            description: "Installs packages at runtime (pip install, npm install, etc.)".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::SupplyChain,
            cwe_id: Some("CWE-829".into()),
            owasp_mcp: Some(OwaspMcp::SupplyChain),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check command invocations for install patterns
        for cmd in &target.execution.commands {
            let cmd_str = match &cmd.command_arg {
                crate::ir::ArgumentSource::Literal(s) => s.clone(),
                _ => continue,
            };

            if is_runtime_install_command(&cmd_str) {
                findings.push(Finding {
                    rule_id: "SHIELD-005".into(),
                    rule_name: "Runtime Package Install".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::SupplyChain,
                    message: format!("Runtime package installation detected: '{}'", cmd_str),
                    location: Some(cmd.location.clone()),
                    evidence: vec![Evidence {
                        description: format!("'{}' executes '{}'", cmd.function, cmd_str),
                        location: Some(cmd.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Install dependencies at build time, not runtime. \
                             Pin versions and verify hashes in a lockfile."
                            .into(),
                    ),
                    cwe_id: Some("CWE-829".into()),
                });
            }
        }

        // Also check dynamic exec for pip.main(['install', ...])
        for dyn_exec in &target.execution.dynamic_exec {
            if dyn_exec.function.contains("pip.main") || dyn_exec.function.contains("importlib") {
                findings.push(Finding {
                    rule_id: "SHIELD-005".into(),
                    rule_name: "Runtime Package Install".into(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    attack_category: AttackCategory::SupplyChain,
                    message: format!(
                        "Programmatic package installation via '{}'",
                        dyn_exec.function
                    ),
                    location: Some(dyn_exec.location.clone()),
                    evidence: vec![Evidence {
                        description: format!("Dynamic install call: '{}'", dyn_exec.function),
                        location: Some(dyn_exec.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some("Avoid programmatic package installation at runtime.".into()),
                    cwe_id: Some("CWE-829".into()),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir;
    use crate::ir::execution_surface::CommandInvocation;
    use std::path::PathBuf;

    fn target_with_commands(commands: Vec<CommandInvocation>) -> ir::ScanTarget {
        ir::ScanTarget {
            name: "sample".into(),
            framework: ir::Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: crate::ir::ExecutionSurface {
                commands,
                file_operations: vec![],
                network_operations: vec![],
                env_accesses: vec![],
                dynamic_exec: vec![],
            },
            data: ir::DataSurface::default(),
            dependencies: ir::DependencySurface::default(),
            provenance: ir::ProvenanceSurface::default(),
            source_files: vec![],
        }
    }

    fn loc() -> crate::ir::SourceLocation {
        crate::ir::SourceLocation {
            file: PathBuf::from("test.sh"),
            line: 1,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_runtime_pip_install_command() {
        let target = target_with_commands(vec![CommandInvocation {
            function: "shell".into(),
            command_arg: crate::ir::ArgumentSource::Literal("pip install requests".into()),
            location: loc(),
        }]);

        let findings = RuntimeInstallDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-005");
    }

    #[test]
    fn ignores_safe_command_literals() {
        let target = target_with_commands(vec![CommandInvocation {
            function: "shell".into(),
            command_arg: crate::ir::ArgumentSource::Literal("echo hello".into()),
            location: loc(),
        }]);

        let findings = RuntimeInstallDetector.run(&target);
        assert!(findings.is_empty());
    }
}
