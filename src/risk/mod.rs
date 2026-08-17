//! Crate-private, deterministic risk assessment model.
//!
//! Findings remain the security facts and policy remains the enforcement
//! boundary. This module is intentionally not part of the public API.

pub(crate) mod render;
pub(crate) mod scoring;
pub(crate) mod types;

pub(crate) use render::render_experimental;
pub(crate) use scoring::assess;
pub(crate) use types::CoverageDescriptor;

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use proptest::prelude::*;

    use super::scoring::*;
    use super::types::*;
    use super::*;
    use crate::ir::SourceLocation;
    use crate::output::OutputFormat;
    use crate::rules::policy::{Policy, Suppression};
    use crate::rules::{AttackCategory, Confidence, Evidence, Finding, RuleMetadata, Severity};

    fn finding(
        rule_id: &str,
        severity: Severity,
        confidence: Confidence,
        evidence: &str,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_owned(),
            rule_name: "Golden rule".to_owned(),
            severity,
            confidence,
            attack_category: AttackCategory::CommandInjection,
            message: "golden finding".to_owned(),
            location: Some(SourceLocation {
                file: PathBuf::from(format!("/scan/{rule_id}.rs")),
                line: 1,
                column: 1,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: evidence.to_owned(),
                location: None,
                snippet: Some("secret-bearing text is not copied".to_owned()),
            }],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    fn coverage() -> CoverageDescriptor {
        CoverageDescriptor::from_parts("0.8.7", vec!["typescript".to_owned()], &[])
    }

    #[test]
    fn all_severity_confidence_pairs_match_golden_points() {
        let cases = [
            (Severity::Info, Confidence::Low, 0),
            (Severity::Info, Confidence::Medium, 0),
            (Severity::Info, Confidence::High, 0),
            (Severity::Low, Confidence::Low, 1),
            (Severity::Low, Confidence::Medium, 2),
            (Severity::Low, Confidence::High, 3),
            (Severity::Medium, Confidence::Low, 4),
            (Severity::Medium, Confidence::Medium, 8),
            (Severity::Medium, Confidence::High, 12),
            (Severity::High, Confidence::Low, 10),
            (Severity::High, Confidence::Medium, 20),
            (Severity::High, Confidence::High, 30),
            (Severity::Critical, Confidence::Low, 20),
            (Severity::Critical, Confidence::Medium, 40),
            (Severity::Critical, Confidence::High, 60),
        ];

        for (severity, confidence, expected) in cases {
            assert_eq!(contribution_points(severity, confidence), expected);
        }
    }

    #[test]
    fn score_vectors_are_frozen() {
        let cases = [
            (0, 0),
            (1, 3),
            (2, 6),
            (3, 9),
            (4, 12),
            (8, 21),
            (10, 25),
            (20, 40),
            (30, 50),
            (40, 57),
            (60, 67),
            (120, 80),
            (300, 91),
            (5_970, 99),
        ];

        for (raw_points, expected) in cases {
            assert_eq!(score_from_raw_points(raw_points), Ok(expected));
        }
    }

    #[test]
    fn empty_and_informational_findings_score_zero() {
        let empty = assess(&[], Path::new("/scan"), &coverage()).expect("empty assessment");
        assert_eq!(empty.score, 0);

        let info = finding("SHIELD-000", Severity::Info, Confidence::High, "info");
        let assessment = assess(&[info], Path::new("/scan"), &coverage()).expect("info assessment");
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.raw_points, 0);
        assert_eq!(assessment.contributions.len(), 1);
    }

    #[test]
    fn exact_fingerprint_duplicates_do_not_inflate_score() {
        let low = finding("SHIELD-001", Severity::Low, Confidence::Low, "same");
        let mut high = low.clone();
        high.severity = Severity::Critical;
        high.confidence = Confidence::High;

        let assessment = assess(&[low, high], Path::new("/scan"), &coverage()).expect("assessment");

        assert_eq!(assessment.raw_points, 60);
        assert_eq!(assessment.summary.input_findings, 2);
        assert_eq!(assessment.summary.unique_findings, 1);
        assert_eq!(assessment.summary.duplicate_findings, 1);
        assert_eq!(
            assessment.contributions[0].effective_severity,
            Severity::Critical
        );
    }

    #[test]
    fn correlated_distinct_findings_remain_visible_as_known_inflation() {
        let first = finding(
            "SHIELD-001",
            Severity::High,
            Confidence::High,
            "one manifestation",
        );
        let second = finding(
            "SHIELD-008",
            Severity::High,
            Confidence::High,
            "same underlying behavior",
        );

        let assessment =
            assess(&[first, second], Path::new("/scan"), &coverage()).expect("assessment");

        assert_eq!(assessment.summary.unique_findings, 2);
        assert_eq!(assessment.raw_points, 60);
        assert_eq!(assessment.score, 67);
    }

    #[test]
    fn policy_and_baseline_boundary_scores_only_final_effective_findings() {
        let ignored = finding(
            "SHIELD-001",
            Severity::Critical,
            Confidence::High,
            "ignored",
        );
        let suppressed = finding(
            "SHIELD-002",
            Severity::Critical,
            Confidence::High,
            "suppressed",
        );
        let overridden = finding(
            "SHIELD-003",
            Severity::Critical,
            Confidence::High,
            "overridden",
        );
        let baselined = finding(
            "SHIELD-004",
            Severity::Critical,
            Confidence::High,
            "baselined",
        );
        let scan_root = Path::new("/scan");

        let mut policy = Policy::default();
        policy.ignore_rules.insert(ignored.rule_id.clone());
        policy
            .overrides
            .insert(overridden.rule_id.clone(), Severity::Low);
        policy.suppressions.push(Suppression {
            fingerprint: suppressed.fingerprint(scan_root),
            reason: "golden suppression".to_owned(),
            expires: None,
            created_at: None,
        });

        let mut effective = policy.apply(
            &[ignored, suppressed, overridden, baselined.clone()],
            scan_root,
        );
        let baseline_fingerprint = baselined.fingerprint(scan_root);
        effective.retain(|finding| finding.fingerprint(scan_root) != baseline_fingerprint);

        let assessment = assess(&effective, scan_root, &coverage()).expect("assessment");

        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].severity, Severity::Low);
        assert_eq!(assessment.raw_points, 3);
        assert_eq!(assessment.score, 9);
    }

    #[cfg(feature = "typescript")]
    #[test]
    fn representative_safe_and_vulnerable_fixtures_order_as_expected() {
        let options = crate::ScanOptions::default();
        let safe = crate::scan(
            Path::new("tests/fixtures/mcp_servers/safe_calculator"),
            &options,
        )
        .expect("scan safe fixture");
        let vulnerable = crate::scan(
            Path::new("tests/fixtures/mcp_servers/vuln_cmd_inject"),
            &options,
        )
        .expect("scan vulnerable fixture");
        let coverage = CoverageDescriptor::current();

        let safe_assessment =
            assess(&safe.findings, &safe.scan_root, &coverage).expect("assess safe fixture");
        let vulnerable_assessment = assess(&vulnerable.findings, &vulnerable.scan_root, &coverage)
            .expect("assess vulnerable fixture");

        // The historically named safe fixture still carries supply-chain
        // hygiene findings; the vulnerable fixture adds two critical command
        // injection findings.
        assert_eq!(safe_assessment.score, 33);
        assert_eq!(vulnerable_assessment.score, 82);
        assert!(vulnerable_assessment.score > safe_assessment.score);
    }

    #[test]
    fn golden_serialization_is_source_safe_and_stable() {
        let finding = finding(
            "SHIELD-001",
            Severity::High,
            Confidence::Medium,
            "stable evidence",
        );
        let assessment = assess(&[finding], Path::new("/scan"), &coverage()).expect("assessment");
        let serialized = serde_json::to_string(&assessment).expect("serialize assessment");

        assert_eq!(
            serialized,
            format!(
                concat!(
                    "{{\"model_version\":\"agentshield-risk-v1\",",
                    "\"coverage_id\":\"{}\",\"score\":40,\"raw_points\":20,",
                    "\"contributions\":[{{\"fingerprint\":",
                    "\"d8e066f7891f42ca2ecd189cec28889f483b19296a9734f76ba14e2d2fd7e160\",",
                    "\"rule_id\":\"SHIELD-001\",\"effective_severity\":\"high\",",
                    "\"confidence\":\"medium\",\"points\":20}}],",
                    "\"summary\":{{\"input_findings\":1,\"unique_findings\":1,",
                    "\"duplicate_findings\":0}}}}"
                ),
                coverage().id()
            )
        );
        assert!(!serialized.contains("secret-bearing"));
        assert!(!serialized.contains("stable evidence"));
    }

    #[test]
    fn coverage_identity_is_order_independent_and_context_sensitive() {
        let rules = vec![
            rule("SHIELD-002", Severity::High),
            rule("SHIELD-001", Severity::Critical),
        ];
        let reversed = vec![rules[1].clone(), rules[0].clone()];

        let first = CoverageDescriptor::from_parts(
            "0.8.7",
            vec!["typescript".to_owned(), "python".to_owned()],
            &rules,
        );
        let second = CoverageDescriptor::from_parts(
            "0.8.7",
            vec!["python".to_owned(), "typescript".to_owned()],
            &reversed,
        );
        assert_eq!(first.id(), second.id());

        let different_version =
            CoverageDescriptor::from_parts("0.8.8", first.enabled_features.clone(), &rules);
        assert_ne!(first.id(), different_version.id());

        let different_features =
            CoverageDescriptor::from_parts("0.8.7", vec!["python".to_owned()], &rules);
        assert_ne!(first.id(), different_features.id());
    }

    #[test]
    fn comparison_rejects_model_or_coverage_mismatch() {
        let base = assess(&[], Path::new("/scan"), &coverage()).expect("assessment");
        let mut other = base.clone();
        assert!(base.is_comparable_to(&other));

        other.model_version = "agentshield-risk-v2".to_owned();
        assert!(!base.is_comparable_to(&other));

        other.model_version = base.model_version.clone();
        other.coverage_id = "different".to_owned();
        assert!(!base.is_comparable_to(&other));
    }

    #[test]
    fn experimental_output_bounds_contributions_and_reports_omissions() {
        let findings = (0..51)
            .map(|index| {
                finding(
                    &format!("SHIELD-GOLDEN-{index:02}"),
                    Severity::Low,
                    Confidence::Low,
                    &format!("evidence {index}"),
                )
            })
            .collect::<Vec<_>>();
        let assessment = assess(&findings, Path::new("/scan"), &coverage()).expect("assessment");
        let rendered = render_experimental(
            r#"{"findings":[],"verdict":{"pass":true}}"#,
            &assessment,
            OutputFormat::Json,
        )
        .expect("render experimental JSON");
        let report: serde_json::Value =
            serde_json::from_str(&rendered).expect("parse experimental JSON");

        assert_eq!(
            report["risk_assessment"]["contributions"]
                .as_array()
                .expect("contributions")
                .len(),
            50
        );
        assert_eq!(report["risk_assessment"]["contributions_truncated"], 1);
    }

    #[test]
    fn arithmetic_overflow_is_explicit() {
        assert_eq!(
            score_from_raw_points(u64::MAX),
            Err(RiskError::ArithmeticOverflow)
        );
        assert_eq!(
            score_from_raw_points((u64::MAX / 100) + 1),
            Err(RiskError::ArithmeticOverflow)
        );
    }

    #[test]
    fn current_coverage_has_rules_and_is_stable() {
        let first = CoverageDescriptor::current();
        let second = CoverageDescriptor::current();
        assert!(!first.rules.is_empty());
        assert_eq!(first.id(), second.id());
        assert_eq!(first.id().len(), 64);
    }

    fn rule(id: &str, severity: Severity) -> RuleMetadata {
        RuleMetadata {
            id: id.to_owned(),
            name: "rule".to_owned(),
            description: "description".to_owned(),
            default_severity: severity,
            attack_category: AttackCategory::CommandInjection,
            cwe_id: None,
            owasp_mcp: None,
        }
    }

    proptest! {
        #[test]
        fn finding_order_does_not_change_assessment(order in prop::collection::vec(0_usize..4, 0..24)) {
            let pool = [
                finding("SHIELD-001", Severity::Low, Confidence::High, "one"),
                finding("SHIELD-002", Severity::Medium, Confidence::Medium, "two"),
                finding("SHIELD-003", Severity::High, Confidence::Low, "three"),
                finding("SHIELD-004", Severity::Critical, Confidence::High, "four"),
            ];
            let mut findings = order.iter().map(|index| pool[*index].clone()).collect::<Vec<_>>();
            let first = assess(&findings, Path::new("/scan"), &coverage()).expect("assessment");
            findings.reverse();
            let second = assess(&findings, Path::new("/scan"), &coverage()).expect("assessment");
            prop_assert_eq!(first, second);
        }

        #[test]
        fn score_is_bounded_and_monotone(raw in 0_u64..=(u64::MAX / 101 - 30), added in 0_u64..1_000_000) {
            let maximum_valid = u64::MAX / 101 - 30;
            let next = raw.saturating_add(added).min(maximum_valid);
            let score = score_from_raw_points(raw).expect("bounded input");
            let next_score = score_from_raw_points(next).expect("bounded input");
            prop_assert!(score <= MAX_EMITTED_SCORE);
            prop_assert!(next_score <= MAX_EMITTED_SCORE);
            prop_assert!(next_score >= score);
        }
    }
}
