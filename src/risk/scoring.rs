use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::rules::{Confidence, Finding, RuleEngine, RuleMetadata, Severity};

use super::types::{
    COVERAGE_SCHEMA, CoverageDescriptor, CoverageRule, MAX_EMITTED_SCORE, MODEL_VERSION,
    RiskAssessment, RiskContribution, RiskError, RiskSummary, SATURATION_CONSTANT,
};

impl CoverageDescriptor {
    pub(crate) fn current() -> Self {
        let rules = RuleEngine::new().list_scanner_rules();
        Self::from_parts(env!("CARGO_PKG_VERSION"), enabled_feature_names(), &rules)
    }

    pub(crate) fn from_parts(
        scanner_version: &str,
        enabled_features: Vec<String>,
        rules: &[RuleMetadata],
    ) -> Self {
        let mut enabled_features = enabled_features;
        enabled_features.sort();
        enabled_features.dedup();

        let mut rules = rules
            .iter()
            .map(|rule| CoverageRule {
                id: rule.id.clone(),
                default_severity: rule.default_severity,
            })
            .collect::<Vec<_>>();
        rules.sort();
        rules.dedup();

        Self {
            scanner_version: scanner_version.to_owned(),
            enabled_features,
            rules,
        }
    }

    pub(crate) fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, COVERAGE_SCHEMA);
        hash_field(&mut hasher, &self.scanner_version);

        for feature in &self.enabled_features {
            hash_field(&mut hasher, "feature");
            hash_field(&mut hasher, feature);
        }
        for rule in &self.rules {
            hash_field(&mut hasher, "rule");
            hash_field(&mut hasher, &rule.id);
            hash_field(&mut hasher, &rule.default_severity.to_string());
        }

        hex::encode(hasher.finalize())
    }
}

pub(crate) fn assess(
    findings: &[Finding],
    scan_root: &Path,
    coverage: &CoverageDescriptor,
) -> Result<RiskAssessment, RiskError> {
    let mut deduplicated = BTreeMap::<String, RiskContribution>::new();

    for finding in findings {
        let fingerprint = finding.fingerprint(scan_root);
        let contribution = RiskContribution {
            fingerprint: fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            effective_severity: finding.severity,
            confidence: finding.confidence,
            points: contribution_points(finding.severity, finding.confidence),
        };

        deduplicated
            .entry(fingerprint)
            .and_modify(|current| {
                if contribution_rank(&contribution) > contribution_rank(current) {
                    *current = contribution.clone();
                }
            })
            .or_insert(contribution);
    }

    let contributions = deduplicated.into_values().collect::<Vec<_>>();
    let raw_points = contributions
        .iter()
        .try_fold(0_u64, |total, contribution| {
            total
                .checked_add(contribution.points)
                .ok_or(RiskError::ArithmeticOverflow)
        })?;
    let score = score_from_raw_points(raw_points)?;

    Ok(RiskAssessment {
        model_version: MODEL_VERSION.to_owned(),
        coverage_id: coverage.id(),
        score,
        raw_points,
        summary: RiskSummary {
            input_findings: findings.len(),
            unique_findings: contributions.len(),
            duplicate_findings: findings.len().saturating_sub(contributions.len()),
        },
        contributions,
    })
}

pub(crate) fn contribution_points(severity: Severity, confidence: Confidence) -> u64 {
    severity_weight(severity) * confidence_multiplier(confidence)
}

pub(crate) fn severity_weight(severity: Severity) -> u64 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 4,
        Severity::High => 10,
        Severity::Critical => 20,
    }
}

pub(crate) fn confidence_multiplier(confidence: Confidence) -> u64 {
    match confidence {
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}

pub(crate) fn contribution_rank(
    contribution: &RiskContribution,
) -> (u64, Severity, Confidence, &str) {
    (
        contribution.points,
        contribution.effective_severity,
        contribution.confidence,
        contribution.rule_id.as_str(),
    )
}

pub(crate) fn score_from_raw_points(raw_points: u64) -> Result<u8, RiskError> {
    let denominator = raw_points
        .checked_add(SATURATION_CONSTANT)
        .ok_or(RiskError::ArithmeticOverflow)?;
    let scaled = raw_points
        .checked_mul(100)
        .ok_or(RiskError::ArithmeticOverflow)?;
    let rounded_numerator = scaled
        .checked_add(denominator / 2)
        .ok_or(RiskError::ArithmeticOverflow)?;
    let score = rounded_numerator / denominator;
    Ok(score.min(u64::from(MAX_EMITTED_SCORE)) as u8)
}

pub(crate) fn enabled_feature_names() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "python") {
        features.push("python".to_owned());
    }
    if cfg!(feature = "typescript") {
        features.push("typescript".to_owned());
    }
    if cfg!(feature = "runtime") {
        features.push("runtime".to_owned());
    }
    if cfg!(feature = "runtime-guard") {
        features.push("runtime-guard".to_owned());
    }
    features
}

pub(crate) fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}
