use std::path::Path;

use glob::Pattern;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ShieldError};
use crate::ir::{ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// Match specification inside a custom rule definition.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomRuleMatch {
    /// Regular expression pattern to search for in source files.
    pub regex: Option<String>,
    /// File glob filter (e.g. "*.py", "*.{ts,js}"). If omitted, matches all source files.
    pub file_glob: Option<String>,
    /// List of banned dependencies.
    pub banned_dependencies: Option<Vec<BannedDepSpec>>,
    /// Regex pattern matching prohibited tool names.
    pub tool_name_regex: Option<String>,
    /// Custom finding message override.
    pub message: Option<String>,
    /// Remediation advice.
    pub remediation: Option<String>,
}

/// Banned dependency entry in custom rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannedDepSpec {
    pub name: String,
    pub reason: Option<String>,
}

/// A declarative custom rule definition (parsed from YAML or JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleDef {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_attack_category")]
    pub attack_category: AttackCategory,
    pub cwe_id: Option<String>,
    pub owasp_mcp: Option<OwaspMcp>,
    pub r#match: CustomRuleMatch,
}

fn default_severity() -> Severity {
    Severity::Medium
}

fn default_attack_category() -> AttackCategory {
    AttackCategory::SupplyChain
}

/// Runtime detector instantiated from a `CustomRuleDef`.
pub struct CustomRuleDetector {
    def: CustomRuleDef,
    compiled_regex: Option<Regex>,
    compiled_glob: Option<Pattern>,
    compiled_tool_name_regex: Option<Regex>,
}

impl CustomRuleDetector {
    pub fn from_def(def: CustomRuleDef) -> Result<Self> {
        let compiled_regex = match &def.r#match.regex {
            Some(pattern) => Some(Regex::new(pattern).map_err(|e| {
                ShieldError::Config(format!("Invalid regex in custom rule '{}': {}", def.id, e))
            })?),
            None => None,
        };

        let compiled_glob = match &def.r#match.file_glob {
            Some(glob_pattern) => Some(Pattern::new(glob_pattern).map_err(|e| {
                ShieldError::Config(format!(
                    "Invalid file_glob in custom rule '{}': {}",
                    def.id, e
                ))
            })?),
            None => None,
        };

        let compiled_tool_name_regex = match &def.r#match.tool_name_regex {
            Some(pattern) => Some(Regex::new(pattern).map_err(|e| {
                ShieldError::Config(format!(
                    "Invalid tool_name_regex in custom rule '{}': {}",
                    def.id, e
                ))
            })?),
            None => None,
        };

        Ok(Self {
            def,
            compiled_regex,
            compiled_glob,
            compiled_tool_name_regex,
        })
    }

    pub fn def(&self) -> &CustomRuleDef {
        &self.def
    }
}

impl Detector for CustomRuleDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: self.def.id.clone(),
            name: self.def.name.clone(),
            description: self.def.description.clone(),
            default_severity: self.def.severity,
            attack_category: self.def.attack_category,
            cwe_id: self.def.cwe_id.clone(),
            owasp_mcp: self.def.owasp_mcp,
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Match source files with regex & file_glob
        if let Some(ref re) = self.compiled_regex {
            for sf in &target.source_files {
                let file_name = sf.path.file_name().and_then(|f| f.to_str()).unwrap_or("");

                if let Some(ref glob) = self.compiled_glob {
                    let rel_path = sf.path.strip_prefix(&target.root_path).unwrap_or(&sf.path);
                    if !glob.matches(file_name) && !glob.matches_path(rel_path) {
                        continue;
                    }
                }

                for (line_idx, line) in sf.content.lines().enumerate() {
                    if re.is_match(line) {
                        let msg = self.def.r#match.message.clone().unwrap_or_else(|| {
                            format!(
                                "Line matches custom rule '{}' pattern: {}",
                                self.def.id,
                                line.trim()
                            )
                        });

                        let loc = SourceLocation {
                            file: sf.path.clone(),
                            line: line_idx + 1,
                            column: 1,
                            end_line: Some(line_idx + 1),
                            end_column: Some(line.len()),
                        };

                        findings.push(Finding {
                            rule_id: self.def.id.clone(),
                            rule_name: self.def.name.clone(),
                            severity: self.def.severity,
                            confidence: Confidence::High,
                            attack_category: self.def.attack_category,
                            message: msg,
                            location: Some(loc.clone()),
                            evidence: vec![Evidence {
                                description: format!(
                                    "Matched custom pattern '{}'",
                                    self.def.r#match.regex.as_deref().unwrap_or_default()
                                ),
                                location: Some(loc),
                                snippet: Some(line.trim().to_string()),
                            }],
                            taint_path: None,
                            remediation: self.def.r#match.remediation.clone(),
                            cwe_id: self.def.cwe_id.clone(),
                        });
                    }
                }
            }
        }

        // 2. Match banned dependencies
        if let Some(ref banned_deps) = self.def.r#match.banned_dependencies {
            for banned in banned_deps {
                for dep in &target.dependencies.dependencies {
                    if dep.name.eq_ignore_ascii_case(&banned.name) {
                        let reason_str = banned
                            .reason
                            .as_ref()
                            .map(|r| format!(" ({})", r))
                            .unwrap_or_default();

                        let msg =
                            format!("Banned dependency '{}' detected{}", dep.name, reason_str);

                        findings.push(Finding {
                            rule_id: self.def.id.clone(),
                            rule_name: self.def.name.clone(),
                            severity: self.def.severity,
                            confidence: Confidence::High,
                            attack_category: self.def.attack_category,
                            message: msg.clone(),
                            location: dep.location.clone(),
                            evidence: vec![Evidence {
                                description: format!("Banned dependency '{}'", dep.name),
                                location: dep.location.clone(),
                                snippet: dep.version_constraint.clone(),
                            }],
                            taint_path: None,
                            remediation: self.def.r#match.remediation.clone(),
                            cwe_id: self.def.cwe_id.clone(),
                        });
                    }
                }
            }
        }

        // 3. Match prohibited tool names
        if let Some(ref tool_re) = self.compiled_tool_name_regex {
            for tool in &target.tools {
                if tool_re.is_match(&tool.name) {
                    let msg = self.def.r#match.message.clone().unwrap_or_else(|| {
                        format!("Tool '{}' matches prohibited tool name pattern", tool.name)
                    });

                    findings.push(Finding {
                        rule_id: self.def.id.clone(),
                        rule_name: self.def.name.clone(),
                        severity: self.def.severity,
                        confidence: Confidence::High,
                        attack_category: self.def.attack_category,
                        message: msg,
                        location: tool.defined_at.clone(),
                        evidence: vec![Evidence {
                            description: format!("Prohibited tool declaration '{}'", tool.name),
                            location: tool.defined_at.clone(),
                            snippet: tool.description.clone(),
                        }],
                        taint_path: None,
                        remediation: self.def.r#match.remediation.clone(),
                        cwe_id: self.def.cwe_id.clone(),
                    });
                }
            }
        }

        findings
    }
}

/// Load a custom rule from a YAML or JSON file.
pub fn load_custom_rule_file(path: &Path) -> Result<CustomRuleDetector> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ShieldError::Config(format!(
            "Failed to read custom rule file '{}': {}",
            path.display(),
            e
        ))
    })?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let def: CustomRuleDef = if ext == "json" {
        serde_json::from_str(&content).map_err(|e| {
            ShieldError::Config(format!(
                "Failed to parse custom rule JSON '{}': {}",
                path.display(),
                e
            ))
        })?
    } else {
        serde_yaml::from_str(&content).map_err(|e| {
            ShieldError::Config(format!(
                "Failed to parse custom rule YAML '{}': {}",
                path.display(),
                e
            ))
        })?
    };

    CustomRuleDetector::from_def(def)
}

/// Load all custom rules from a directory (.yaml, .yml, .json).
pub fn load_custom_rules_from_dir(dir: &Path) -> Result<Vec<CustomRuleDetector>> {
    if !dir.exists() || !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut detectors = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| {
        ShieldError::Config(format!(
            "Failed to read custom rules dir '{}': {}",
            dir.display(),
            e
        ))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext == "yaml" || ext == "yml" || ext == "json" {
                if let Ok(detector) = load_custom_rule_file(&path) {
                    detectors.push(detector);
                }
            }
        }
    }

    Ok(detectors)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ir::dependency_surface::{Dependency, DependencySurface};
    use crate::ir::{Language, SourceFile};

    #[test]
    fn test_parse_custom_yaml_rule() {
        let yaml = r#"
id: "ORG-001"
name: "Banned Internal Token Prefix"
description: "Detects internal secret tokens"
severity: "high"
attack_category: "credential_exfiltration"
cwe_id: "CWE-798"
match:
  regex: "CORP_KEY_[A-Z0-9]{8,}"
  file_glob: "*.py"
  banned_dependencies:
    - name: "insecure-pkg"
      reason: "deprecated"
  tool_name_regex: "^admin_.*"
"#;
        let def: CustomRuleDef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.id, "ORG-001");
        assert_eq!(def.severity, Severity::High);
        assert_eq!(def.attack_category, AttackCategory::CredentialExfiltration);
        assert_eq!(def.cwe_id.as_deref(), Some("CWE-798"));

        let detector = CustomRuleDetector::from_def(def).unwrap();
        assert_eq!(detector.metadata().id, "ORG-001");
    }

    #[test]
    fn test_custom_rule_detects_regex_and_banned_dep() {
        let yaml = r#"
id: "CUSTOM-TEST"
name: "Custom Test Rule"
description: "Detects custom pattern"
severity: "critical"
attack_category: "command_injection"
match:
  regex: "danger_zone\\(\\)"
  banned_dependencies:
    - name: "evil-dep"
"#;
        let def: CustomRuleDef = serde_yaml::from_str(yaml).unwrap();
        let detector = CustomRuleDetector::from_def(def).unwrap();

        let target = ScanTarget {
            name: "test-target".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: DependencySurface {
                dependencies: vec![Dependency {
                    name: "evil-dep".into(),
                    version_constraint: Some("1.0.0".into()),
                    location: None,
                    is_dev: false,
                    locked_version: None,
                    locked_hash: None,
                    registry: "pypi".into(),
                }],
                lockfile: None,
                issues: vec![],
            },
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from("/test/main.py"),
                language: Language::Python,
                size_bytes: 50,
                content_hash: "abc".into(),
                content: "import sys\ndanger_zone()\n".into(),
            }],
        };

        let findings = detector.run(&target);
        assert_eq!(findings.len(), 2);
        let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(rule_ids, vec!["CUSTOM-TEST", "CUSTOM-TEST"]);
    }
}
