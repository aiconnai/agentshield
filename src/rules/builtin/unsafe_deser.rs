use super::unsafe_deser_patterns::{
    code_outside_literals, is_unsafe_deserializer, LiteralScanState, JS_UNSAFE_PATTERNS, YAML_LOAD,
};

use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-016: Unsafe Deserialization
///
/// Detects unsafe deserialization functions that can execute arbitrary code
/// when processing untrusted input (CWE-502).
pub struct UnsafeDeserDetector;

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
            owasp_mcp: Some(OwaspMcp::CommandExecution),
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
            if source_file.language.is_documentation() {
                continue;
            }
            let mut literal_state = LiteralScanState::default();
            for (line_idx, line) in source_file.content.lines().enumerate() {
                let searchable =
                    code_outside_literals(line, source_file.language, &mut literal_state);

                if let Some(deser) = is_unsafe_deserializer(&searchable) {
                    let location = crate::ir::SourceLocation {
                        file: source_file.path.clone(),
                        line: line_idx + 1,
                        column: 0,
                        end_line: None,
                        end_column: None,
                    };
                    findings.push(Finding {
                        rule_id: "SHIELD-016".into(),
                        rule_name: "Unsafe Deserialization".into(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CodeInjection,
                        message: format!(
                            "'{}' uses unsafe deserializer '{}' — can execute arbitrary code",
                            source_file.path.display(),
                            deser
                        ),
                        location: Some(location.clone()),
                        evidence: vec![Evidence {
                            description: format!("Unsafe deserializer '{deser}' found in source"),
                            location: Some(location),
                            snippet: Some(line.trim().to_string()),
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

                if searchable.contains(YAML_LOAD)
                    && !searchable.contains("safe_load")
                    && !searchable.contains("SafeLoader")
                    && !searchable.contains("yaml.safe_load")
                    && !searchable.contains("CSafeLoader")
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
#[path = "unsafe_deser_tests.rs"]
mod unsafe_deser_tests;
