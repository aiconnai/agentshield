pub mod builtin;
pub mod finding;
pub mod policy;

use crate::analysis::DetectionInput;
use crate::ir::ScanTarget;
use crate::ir::SourceLocation;

pub use finding::{
    AttackCategory, Confidence, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// A detector checks a `ScanTarget` and produces findings.
pub trait Detector: Send + Sync {
    /// Metadata about this rule (id, name, severity, CWE).
    fn metadata(&self) -> RuleMetadata;

    /// Run the detector against a scan target.
    fn run(&self, target: &ScanTarget) -> Vec<Finding>;
}

pub(crate) trait ContextDetector: Send + Sync {
    fn metadata(&self) -> RuleMetadata;

    fn run(&self, input: &DetectionInput<'_>) -> Vec<Finding>;
}

/// The rule engine runs all registered detectors against a target.
pub struct RuleEngine {
    detectors: Vec<Box<dyn Detector>>,
    context_detectors: Vec<Box<dyn ContextDetector>>,
}

impl RuleEngine {
    /// Create a new engine with all built-in detectors registered.
    pub fn new() -> Self {
        Self {
            detectors: builtin::all_detectors(),
            context_detectors: builtin::all_context_detectors(),
        }
    }

    /// Run all detectors against a scan target.
    pub fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let findings: Vec<Finding> = self.detectors.iter().flat_map(|d| d.run(target)).collect();
        apply_overlapping_rule_suppression(findings)
    }

    /// Run all built-in detectors, including contextual detectors.
    pub(crate) fn run_with_context(&self, input: &DetectionInput<'_>) -> Vec<Finding> {
        let mut findings = self
            .detectors
            .iter()
            .flat_map(|detector| detector.run(input.target))
            .collect::<Vec<_>>();
        findings.extend(
            self.context_detectors
                .iter()
                .flat_map(|detector| detector.run(input)),
        );
        apply_overlapping_rule_suppression(findings)
    }

    /// List metadata for all registered rules.
    pub fn list_rules(&self) -> Vec<RuleMetadata> {
        self.detectors.iter().map(|d| d.metadata()).collect()
    }

    /// List metadata for all scanner rules, including future contextual detectors.
    pub fn list_scanner_rules(&self) -> Vec<RuleMetadata> {
        let mut rules = self
            .detectors
            .iter()
            .map(|d| d.metadata())
            .collect::<Vec<_>>();
        rules.extend(self.context_detectors.iter().map(|d| d.metadata()));
        rules
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

const OVERLAPPING_RULE_PAIRS: &[(&str, &str)] = &[
    // Keep precise/specific signal and suppress broader overlap.
    ("SHIELD-013", "SHIELD-003"), // Metadata/private SSRF suppresses generic SSRF
    ("SHIELD-002", "SHIELD-018"), // Credential exfil suppresses generic secret leakage
    ("SHIELD-004", "SHIELD-015"), // Arbitrary file access suppresses overbroad filesystem scope
    ("SHIELD-011", "SHIELD-016"), // Dynamic eval/import suppression suppresses unsafe deserialization overlap
];

fn apply_overlapping_rule_suppression(findings: Vec<Finding>) -> Vec<Finding> {
    let mut suppressed = vec![false; findings.len()];

    for i in 0..findings.len() {
        let candidate = &findings[i];
        if suppressed[i] {
            continue;
        }

        for (j, dominant) in findings.iter().enumerate() {
            if i == j || suppressed[i] {
                continue;
            }

            if should_suppress(candidate, dominant) {
                suppressed[i] = true;
            }
        }
    }

    findings
        .into_iter()
        .enumerate()
        .filter_map(|(idx, finding)| if suppressed[idx] { None } else { Some(finding) })
        .collect()
}

fn should_suppress(candidate: &Finding, dominant: &Finding) -> bool {
    if !same_source_location(candidate.location.as_ref(), dominant.location.as_ref()) {
        return false;
    }

    // A tainted URL is enough to retain the critical SHIELD-013 signal, but it
    // is not proof that the destination is metadata/private. Keep the generic
    // SHIELD-003 finding in that uncertain case; suppress it only when the
    // dominant finding carries a concrete metadata/private indication (or is a
    // synthetic dominant finding with no taint path).
    if candidate.rule_id == "SHIELD-003"
        && dominant.rule_id == "SHIELD-013"
        && dominant.taint_path.is_some()
        && !dominant
            .evidence
            .iter()
            .any(|evidence| evidence.description.starts_with("Sink: HTTP request to "))
    {
        return false;
    }

    overlap_dominates(candidate.rule_id.as_str(), dominant.rule_id.as_str())
        .is_some_and(|(dominant_rule, _)| dominant.rule_id == dominant_rule)
}

fn overlap_dominates(candidate_rule: &str, dominant_rule: &str) -> Option<(String, String)> {
    OVERLAPPING_RULE_PAIRS
        .iter()
        .find_map(|(dominant, dominated)| {
            (candidate_rule == *dominated && dominant_rule == *dominant)
                .then_some((dominant.to_string(), dominated.to_string()))
        })
}

fn same_source_location(left: Option<&SourceLocation>, right: Option<&SourceLocation>) -> bool {
    match (left, right) {
        (Some(a), Some(b)) => a.file == b.file && a.line == b.line,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ArgumentSource;
    use crate::ir::data_surface::*;
    use crate::ir::execution_surface::*;
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

    fn empty_target() -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: crate::ir::Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface::default(),
            data: DataSurface::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    fn simple_finding(rule_id: &str, location: Option<SourceLocation>) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: rule_id.to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            attack_category: AttackCategory::ArbitraryFileAccess,
            message: "test".into(),
            location,
            evidence: vec![],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    #[test]
    fn all_builtin_rules_have_owasp_mcp_mapping() {
        let engine = RuleEngine::new();
        let rules = engine.list_rules();
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(
                rule.owasp_mcp.is_some(),
                "rule {} is missing an OWASP MCP Top 10 mapping",
                rule.id
            );
        }
    }

    #[test]
    fn suppresses_overlapping_014_pairs_in_engine_output() {
        let target = {
            let mut target = empty_target();
            let overlap_loc = loc();

            target.data.taint_paths.push(TaintPath {
                source: TaintSource {
                    source_type: TaintSourceType::ToolArgument,
                    description: "url".into(),
                    location: overlap_loc.clone(),
                },
                sink: TaintSink {
                    sink_type: TaintSinkType::HttpRequest,
                    description: "requests.get".into(),
                    location: overlap_loc.clone(),
                },
                through: vec![],
                confidence: 0.9,
            });
            target.execution.network_operations.push(NetworkOperation {
                function: "requests.get".into(),
                url_arg: ArgumentSource::Literal("http://169.254.169.254/latest/meta-data/".into()),
                method: Some("GET".into()),
                sends_data: false,
                location: overlap_loc.clone(),
            });

            target.execution.file_operations.push(FileOperation {
                operation: FileOpType::Read,
                path_arg: ArgumentSource::Parameter {
                    name: "path".into(),
                },
                location: overlap_loc.clone(),
            });

            target
        };

        let findings = RuleEngine::new().run(&target);
        let has_metadata_ssrf = findings.iter().any(|f| f.rule_id == "SHIELD-013");
        let has_ssrf = findings.iter().any(|f| f.rule_id == "SHIELD-003");
        assert!(has_metadata_ssrf, "should keep SHIELD-013");
        assert!(
            !has_ssrf,
            "SHIELD-003 should be suppressed when SHIELD-013 is present at same location"
        );
        assert!(has_metadata_ssrf || has_ssrf);
    }

    #[test]
    fn suppresses_overlapping_findings_for_arbitrary_file_and_overbroad_fs() {
        let target = {
            let mut target = empty_target();
            target.execution.file_operations.push(FileOperation {
                operation: FileOpType::Write,
                path_arg: ArgumentSource::Parameter {
                    name: "file_path".into(),
                },
                location: loc(),
            });
            target
        };

        let findings = RuleEngine::new().run(&target);
        let has_arf = findings.iter().any(|f| f.rule_id == "SHIELD-004");
        let has_overbroad = findings.iter().any(|f| f.rule_id == "SHIELD-015");
        assert!(has_arf);
        assert!(!has_overbroad);
    }

    #[test]
    fn suppresses_overlapping_pairs_by_rule_with_same_location() {
        let overlap_loc = loc();
        let findings = vec![
            simple_finding("SHIELD-016", Some(overlap_loc.clone())),
            simple_finding("SHIELD-011", Some(overlap_loc.clone())),
            simple_finding("SHIELD-018", Some(overlap_loc.clone())),
            simple_finding("SHIELD-002", Some(overlap_loc.clone())),
            simple_finding("SHIELD-003", Some(overlap_loc.clone())),
            simple_finding("SHIELD-013", Some(overlap_loc)),
        ];
        let filtered = apply_overlapping_rule_suppression(findings);
        let ids: Vec<_> = filtered.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"SHIELD-013"));
        assert!(!ids.contains(&"SHIELD-003"));
        assert!(ids.contains(&"SHIELD-002"));
        assert!(!ids.contains(&"SHIELD-018"));
        assert!(ids.contains(&"SHIELD-011"));
        assert!(!ids.contains(&"SHIELD-016"));
    }
}
