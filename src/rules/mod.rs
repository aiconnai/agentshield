pub mod builtin;
pub mod finding;
pub mod policy;

use crate::ir::ScanTarget;

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

/// The rule engine runs all registered detectors against a target.
pub struct RuleEngine {
    detectors: Vec<Box<dyn Detector>>,
}

impl RuleEngine {
    /// Create a new engine with all built-in detectors registered.
    pub fn new() -> Self {
        Self {
            detectors: builtin::all_detectors(),
        }
    }

    /// Run all detectors against a scan target.
    pub fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        self.detectors.iter().flat_map(|d| d.run(target)).collect()
    }

    /// List metadata for all registered rules.
    pub fn list_rules(&self) -> Vec<RuleMetadata> {
        self.detectors.iter().map(|d| d.metadata()).collect()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
