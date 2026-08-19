use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-034: Insecure Agent Checkpoint / Unsigned State Deserialization
///
/// Detects insecure deserialization of agent memory, state checkpoints, or model weights
/// (e.g. `torch.load` without `weights_only=True`, `joblib.load`, `dill.load`,
/// `cloudpickle.load`, `shelve.open`) that can lead to arbitrary code execution (CWE-502).
pub struct InsecureAgentCheckpointDetector;

// Matches torch.load( invocation start
static TORCH_LOAD_START_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\btorch\.load\s*\("#).expect("valid regex")
});

// Matches joblib, dill, cloudpickle, shelve deserializers
static UNSAFE_STATE_LOADERS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(joblib\.load|dill\.loads?|dill\.load_session|dill\.load_module|cloudpickle\.loads?|shelve\.open)\s*\("#)
        .expect("valid regex")
});

// Matches insecure checkpoint saver classes or custom pickle loaders in agents
static INSECURE_CHECKPOINT_SAVER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(PickleCheckpointSaver|UnsignedCheckpointSaver|FileCheckpointSaver)\b"#)
        .expect("valid regex")
});

// Matches weights_only=True pattern
static WEIGHTS_ONLY_TRUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\bweights_only\s*=\s*True\b"#).expect("valid regex")
});

impl Detector for InsecureAgentCheckpointDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-034".into(),
            name: "Insecure Agent Checkpoint / Unsigned State Deserialization".into(),
            description: "Insecure deserialization or unverified loading of agent memory, state \
                          checkpoints, or model weights that can lead to arbitrary code execution"
                .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::CodeInjection,
            cwe_id: Some("CWE-502".into()),
            owasp_mcp: Some(OwaspMcp::CommandExecution),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &target.source_files {
            if file.language != Language::Python {
                continue;
            }

            let lines: Vec<&str> = file.content.lines().collect();

            // 1. Scan for torch.load calls without weights_only=True
            for (line_idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') {
                    continue;
                }

                if TORCH_LOAD_START_RE.is_match(line) {
                    let mut paren_balance: i32 = 0;
                    let mut call_lines = Vec::new();
                    let end_idx = (line_idx + 15).min(lines.len());
                    // Start scanning from the torch.load( position on the first line so that
                    // any unmatched ) before torch.load (e.g. closing a prior expression) does
                    // not cause premature termination. Use == 0 (not <= 0) for correct balance.
                    let first_line_offset = line.find("torch.load").unwrap_or(0);

                    for (i, &l) in lines[line_idx..end_idx].iter().enumerate() {
                        call_lines.push(l);
                        let scan = if i == 0 { &l[first_line_offset..] } else { l };
                        for ch in scan.chars() {
                            if ch == '(' {
                                paren_balance += 1;
                            } else if ch == ')' {
                                paren_balance -= 1;
                            }
                        }
                        if paren_balance == 0 {
                            break;
                        }
                    }
                    let call_window = call_lines.join("\n");

                    if !WEIGHTS_ONLY_TRUE_RE.is_match(&call_window) {
                        let loc = SourceLocation {
                            file: file.path.clone(),
                            line: line_idx + 1,
                            column: line.find("torch.load").unwrap_or(0),
                            end_line: None,
                            end_column: None,
                        };

                        findings.push(Finding {
                            rule_id: "SHIELD-034".into(),
                            rule_name: "Insecure Agent Checkpoint / Unsigned State Deserialization".into(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            attack_category: AttackCategory::CodeInjection,
                            message: "`torch.load()` invoked without `weights_only=True` when loading agent state or checkpoint — allows arbitrary code execution via pickled objects".into(),
                            location: Some(loc.clone()),
                            evidence: vec![Evidence {
                                description: "Unsafe torch.load invocation without weights_only=True".into(),
                                location: Some(loc),
                                snippet: Some(trimmed.to_string()),
                            }],
                            taint_path: None,
                            remediation: Some(
                                "Specify `weights_only=True` in `torch.load(..., weights_only=True)` or use safe formats like safetensors (`safetensors.torch.load_file`).".into(),
                            ),
                            cwe_id: Some("CWE-502".into()),
                        });
                    }
                }

                // 2. Scan for joblib.load, dill.load, cloudpickle.load, shelve.open
                if let Some(caps) = UNSAFE_STATE_LOADERS_RE.captures(line) {
                    let loader_name = caps.get(1).map_or("unsafe loader", |m| m.as_str());
                    let loc = SourceLocation {
                        file: file.path.clone(),
                        line: line_idx + 1,
                        column: line.find(loader_name).unwrap_or(0),
                        end_line: None,
                        end_column: None,
                    };

                    findings.push(Finding {
                        rule_id: "SHIELD-034".into(),
                        rule_name: "Insecure Agent Checkpoint / Unsigned State Deserialization".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        attack_category: AttackCategory::CodeInjection,
                        message: format!(
                            "`{loader_name}()` used to restore agent state or memory — allows arbitrary code execution from untrusted checkpoint files"
                        ),
                        location: Some(loc.clone()),
                        evidence: vec![Evidence {
                            description: format!("Unsafe state loader '{loader_name}' detected"),
                            location: Some(loc),
                            snippet: Some(trimmed.to_string()),
                        }],
                        taint_path: None,
                        remediation: Some(
                            "Use cryptographic signature verification (HMAC/Ed25519) before deserialization, or replace binary pickle formats with structured JSON/msgpack and schema validation.".into(),
                        ),
                        cwe_id: Some("CWE-502".into()),
                    });
                }

                // 3. Scan for insecure checkpoint saver classes (excluding import lines)
                if !trimmed.starts_with("from ") && !trimmed.starts_with("import ") {
                    if let Some(caps) = INSECURE_CHECKPOINT_SAVER_RE.captures(line) {
                        let class_name = caps.get(1).map_or("CheckpointSaver", |m| m.as_str());
                        let loc = SourceLocation {
                            file: file.path.clone(),
                            line: line_idx + 1,
                            column: line.find(class_name).unwrap_or(0),
                            end_line: None,
                            end_column: None,
                        };

                        findings.push(Finding {
                            rule_id: "SHIELD-034".into(),
                            rule_name: "Insecure Agent Checkpoint / Unsigned State Deserialization".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            attack_category: AttackCategory::CodeInjection,
                            message: format!(
                                "Agent uses `{class_name}` for state persistence without integrity verification — susceptible to checkpoint tampering"
                            ),
                            location: Some(loc.clone()),
                            evidence: vec![Evidence {
                                description: format!("Insecure checkpoint saver class '{class_name}' found"),
                                location: Some(loc),
                                snippet: Some(trimmed.to_string()),
                            }],
                            taint_path: None,
                            remediation: Some(
                                "Sign and verify state checkpoints with digital signatures (e.g. Ed25519) or use secure encrypted storage adapters.".into(),
                            ),
                            cwe_id: Some("CWE-502".into()),
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Framework, SourceFile};
    use std::path::PathBuf;

    fn target_with_python_source(code: &str) -> ScanTarget {
        ScanTarget {
            name: "test-checkpoint-agent".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from("agent_memory.py"),
                language: Language::Python,
                size_bytes: code.len() as u64,
                content_hash: "hash".into(),
                content: code.into(),
            }],
        }
    }

    #[test]
    fn detects_unsafe_torch_load_without_weights_only() {
        let code = r#"
import torch

def restore_agent_model(checkpoint_path: str):
    checkpoint = torch.load(checkpoint_path)
    return checkpoint
"#;
        let target = target_with_python_source(code);
        let detector = InsecureAgentCheckpointDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-034");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_unsafe_multiline_torch_load() {
        let code = r#"
import torch

def restore_agent_model(checkpoint_path: str):
    checkpoint = torch.load(
        checkpoint_path,
        map_location="cpu"
    )
    return checkpoint
"#;
        let target = target_with_python_source(code);
        let detector = InsecureAgentCheckpointDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-034");
    }

    #[test]
    fn ignores_safe_torch_load_with_weights_only() {
        let code = r#"
import torch

def restore_agent_model(checkpoint_path: str):
    checkpoint = torch.load(checkpoint_path, weights_only=True)
    return checkpoint
"#;
        let target = target_with_python_source(code);
        let detector = InsecureAgentCheckpointDetector;
        let findings = detector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_safe_torch_load_with_nested_function_call() {
        let code = r#"
import os
import torch

def restore_agent_model(checkpoint_dir: str):
    checkpoint = torch.load(os.path.join(checkpoint_dir, "model.pt"), weights_only=True)
    return checkpoint
"#;
        let target = target_with_python_source(code);
        let detector = InsecureAgentCheckpointDetector;
        let findings = detector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_joblib_and_dill_and_cloudpickle() {
        let code = r#"
import joblib
import dill
import cloudpickle
import shelve

def load_state(path):
    m1 = joblib.load(path)
    m2 = dill.load(open(path, "rb"))
    m3 = cloudpickle.loads(b"raw")
    db = shelve.open("agent_db")
"#;
        let target = target_with_python_source(code);
        let detector = InsecureAgentCheckpointDetector;
        let findings = detector.run(&target);
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn detects_insecure_checkpoint_saver() {
        let code = r#"
from langgraph.checkpoint import PickleCheckpointSaver

checkpointer = PickleCheckpointSaver()
"#;
        let target = target_with_python_source(code);
        let detector = InsecureAgentCheckpointDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding (usage line only, import line must be skipped); got {}:\n{}",
            findings.len(),
            findings.iter().map(|f| format!("  [{:?}] {}", f.location, f.message)).collect::<Vec<_>>().join("\n")
        );
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
