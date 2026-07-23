use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

/// SHIELD-005: Runtime Package Install
///
/// Flags runtime package install commands (pip install, npm install,
/// uv pip install) in executable code paths.
pub struct RuntimeInstallDetector;

static INSTALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"pip\s+install").expect("static regex pattern is valid"),
        Regex::new(r"pip3\s+install").expect("static regex pattern is valid"),
        Regex::new(r"npm\s+install").expect("static regex pattern is valid"),
        Regex::new(r"npm\s+i\b").expect("static regex pattern is valid"),
        Regex::new(r"uv\s+pip\s+install").expect("static regex pattern is valid"),
        Regex::new(r"yarn\s+add").expect("static regex pattern is valid"),
        Regex::new(r"pnpm\s+add").expect("static regex pattern is valid"),
    ]
});

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

            for pattern in INSTALL_PATTERNS.iter() {
                if pattern.is_match(&cmd_str) {
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
                    break;
                }
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
