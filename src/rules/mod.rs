pub mod builtin;
pub mod custom;
pub mod finding;
pub mod policy;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::analysis::DetectionInput;
use crate::ir::ScanTarget;
use crate::ir::SourceLocation;

pub use custom::{CustomRuleDef, CustomRuleDetector, load_custom_rules_from_dir};
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
    custom_detectors: Vec<CustomRuleDetector>,
}

impl RuleEngine {
    /// Create a new engine with all built-in detectors registered.
    pub fn new() -> Self {
        Self {
            detectors: builtin::all_detectors(),
            context_detectors: builtin::all_context_detectors(),
            custom_detectors: Vec::new(),
        }
    }

    /// Add custom rule detectors to the engine.
    pub fn with_custom_rules(mut self, custom: Vec<CustomRuleDetector>) -> Self {
        self.custom_detectors.extend(custom);
        self
    }

    /// Load custom rules from a directory into this engine.
    pub fn load_custom_rules_from(&mut self, dir: &Path) -> crate::error::Result<()> {
        let loaded = custom::load_custom_rules_from_dir(dir)?;
        self.custom_detectors.extend(loaded);
        Ok(())
    }

    /// Run all detectors against a scan target.
    pub fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings: Vec<Finding> =
            self.detectors.iter().flat_map(|d| d.run(target)).collect();
        findings.extend(self.custom_detectors.iter().flat_map(|d| d.run(target)));
        apply_overlapping_rule_suppression(findings)
    }

    /// Run all built-in detectors, including contextual and custom detectors.
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
        findings.extend(
            self.custom_detectors
                .iter()
                .flat_map(|detector| detector.run(input.target)),
        );
        apply_overlapping_rule_suppression(findings)
    }

    /// List metadata for all registered rules, including custom rules.
    pub fn list_rules(&self) -> Vec<RuleMetadata> {
        let mut rules: Vec<RuleMetadata> = self.detectors.iter().map(|d| d.metadata()).collect();
        rules.extend(self.custom_detectors.iter().map(|d| d.metadata()));
        rules
    }

    /// List metadata for all scanner rules, including future contextual detectors.
    pub fn list_scanner_rules(&self) -> Vec<RuleMetadata> {
        let mut rules = self
            .detectors
            .iter()
            .map(|d| d.metadata())
            .collect::<Vec<_>>();
        rules.extend(self.context_detectors.iter().map(|d| d.metadata()));
        rules.extend(self.custom_detectors.iter().map(|d| d.metadata()));
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceLocationKey {
    file: PathBuf,
    line: usize,
    column: usize,
    end_line: Option<usize>,
    end_column: Option<usize>,
}

impl From<&SourceLocation> for SourceLocationKey {
    fn from(location: &SourceLocation) -> Self {
        Self {
            file: location.file.clone(),
            line: location.line,
            column: location.column,
            end_line: location.end_line,
            end_column: location.end_column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SuppressionKey {
    dominant_rule: &'static str,
    location: SourceLocationKey,
}

fn apply_overlapping_rule_suppression(findings: Vec<Finding>) -> Vec<Finding> {
    // Only dominant rules can suppress a candidate. Indexing those keys avoids
    // comparing every finding with every other finding on the scan path.
    let suppressors: HashSet<SuppressionKey> = findings
        .iter()
        .filter_map(|dominant| {
            let dominant_rule = dominant_rule_for_dominant(dominant.rule_id.as_str())?;
            let location = dominant.location.as_ref()?;
            dominant_finding_can_suppress(dominant).then_some(SuppressionKey {
                dominant_rule,
                location: location.into(),
            })
        })
        .collect();

    findings
        .into_iter()
        .filter(|candidate| {
            let Some(dominant_rule) = dominant_rule_for_candidate(candidate.rule_id.as_str())
            else {
                return true;
            };
            let Some(location) = candidate.location.as_ref() else {
                return true;
            };

            !suppressors.contains(&SuppressionKey {
                dominant_rule,
                location: location.into(),
            })
        })
        .collect()
}

fn dominant_rule_for_candidate(candidate_rule: &str) -> Option<&'static str> {
    OVERLAPPING_RULE_PAIRS
        .iter()
        .find_map(|(dominant, dominated)| (*dominated == candidate_rule).then_some(*dominant))
}

fn dominant_rule_for_dominant(dominant_rule: &str) -> Option<&'static str> {
    OVERLAPPING_RULE_PAIRS
        .iter()
        .find_map(|(dominant, _)| (*dominant == dominant_rule).then_some(*dominant))
}

fn dominant_finding_can_suppress(dominant: &Finding) -> bool {
    // A tainted URL is enough to retain the critical SHIELD-013 signal, but it
    // is not proof that the destination is metadata/private. Keep the generic
    // SHIELD-003 finding in that uncertain case; suppress it only when the
    // dominant finding carries a concrete metadata/private indication (or is a
    // synthetic dominant finding with no taint path).
    if dominant.rule_id == "SHIELD-013"
        && dominant.taint_path.is_some()
        && !dominant
            .evidence
            .iter()
            .any(|evidence| evidence.description.starts_with("Sink: HTTP request to "))
    {
        return false;
    }

    true
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

    #[test]
    fn keeps_overlapping_rules_for_distinct_spans_on_the_same_line() {
        let mut first_span = loc();
        first_span.column = 4;
        first_span.end_line = Some(first_span.line);
        first_span.end_column = Some(14);

        let mut second_span = first_span.clone();
        second_span.column = 16;
        second_span.end_column = Some(33);

        let findings = vec![
            simple_finding("SHIELD-004", Some(first_span)),
            simple_finding("SHIELD-015", Some(second_span)),
        ];

        let filtered = apply_overlapping_rule_suppression(findings);
        let ids: Vec<_> = filtered
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();

        assert_eq!(filtered.len(), 2);
        assert!(ids.contains(&"SHIELD-004"));
        assert!(ids.contains(&"SHIELD-015"));
    }
}
