use serde::{Deserialize, Serialize};

use crate::rules::{Confidence, Severity};

pub(crate) const MODEL_VERSION: &str = "agentshield-risk-v1";
pub(crate) const COVERAGE_SCHEMA: &str = "agentshield-coverage-v1";
pub(crate) const SATURATION_CONSTANT: u64 = 30;
pub(crate) const MAX_EMITTED_SCORE: u8 = 99;
pub(crate) const MAX_OUTPUT_CONTRIBUTIONS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RiskAssessment {
    pub(crate) model_version: String,
    pub(crate) coverage_id: String,
    pub(crate) score: u8,
    pub(crate) raw_points: u64,
    pub(crate) contributions: Vec<RiskContribution>,
    pub(crate) summary: RiskSummary,
}

impl RiskAssessment {
    #[cfg(test)]
    pub(crate) fn is_comparable_to(&self, other: &Self) -> bool {
        self.model_version == other.model_version && self.coverage_id == other.coverage_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RiskContribution {
    pub(crate) fingerprint: String,
    pub(crate) rule_id: String,
    pub(crate) effective_severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) points: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RiskSummary {
    pub(crate) input_findings: usize,
    pub(crate) unique_findings: usize,
    pub(crate) duplicate_findings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoverageDescriptor {
    pub(crate) scanner_version: String,
    pub(crate) enabled_features: Vec<String>,
    pub(crate) rules: Vec<CoverageRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CoverageRule {
    pub(crate) id: String,
    pub(crate) default_severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RiskError {
    ArithmeticOverflow,
}

impl std::fmt::Display for RiskError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArithmeticOverflow => formatter.write_str("risk assessment arithmetic overflow"),
        }
    }
}

impl std::error::Error for RiskError {}
