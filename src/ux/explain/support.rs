use std::collections::{BTreeMap, BTreeSet};

use crate::config::ScanPathFilterSummary;
use crate::ir::Language;
use crate::rules::{Finding, Severity};
use crate::ScanReport;

use super::CoverageConfidence;

#[derive(Debug, Default)]
pub(super) struct CoverageSummary {
    pub(super) frameworks: BTreeSet<String>,
    pub(super) languages: BTreeSet<String>,
    pub(super) targets: usize,
    pub(super) source_files: usize,
    pub(super) tools: usize,
    pub(super) dependencies: usize,
    pub(super) lockfiles: usize,
}

pub(super) fn coverage_summary(report: &ScanReport) -> CoverageSummary {
    let mut summary = CoverageSummary {
        targets: report.targets.len(),
        ..CoverageSummary::default()
    };

    for target in &report.targets {
        summary.frameworks.insert(target.framework.to_string());
        summary.source_files += target.source_files.len();
        summary.tools += target.tools.len();
        summary.dependencies += target.dependencies.dependencies.len();
        if target.dependencies.lockfile.is_some() {
            summary.lockfiles += 1;
        }
        for source in &target.source_files {
            summary
                .languages
                .insert(display_language(source.language).into());
        }
    }

    summary
}

pub(super) fn confidence_for_report(report: &ScanReport) -> CoverageConfidence {
    if report.targets.is_empty() {
        CoverageConfidence::Low
    } else if report
        .targets
        .iter()
        .any(|target| !target.source_files.is_empty())
    {
        CoverageConfidence::High
    } else {
        CoverageConfidence::Medium
    }
}

pub(super) fn gate_reason(report: &ScanReport) -> String {
    if report.verdict.pass {
        match report.verdict.highest_severity {
            Some(severity) => format!(
                "no findings at or above the {} threshold; highest finding is {}",
                report.verdict.fail_threshold, severity
            ),
            None => format!(
                "no findings remained after policy, suppressions, and baseline filtering; threshold is {}",
                report.verdict.fail_threshold
            ),
        }
    } else {
        format!(
            "at least one finding meets or exceeds the {} threshold; highest finding is {}",
            report.verdict.fail_threshold,
            report
                .verdict
                .highest_severity
                .map(|severity| severity.to_string())
                .unwrap_or_else(|| "unknown".into())
        )
    }
}

pub(super) fn finding_group_summary(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        "none".into()
    } else {
        format!("{} ({})", findings.len(), severity_counts_refs(findings))
    }
}

pub(super) fn severity_counts(findings: &[Finding]) -> String {
    let refs: Vec<&Finding> = findings.iter().collect();
    severity_counts_refs(&refs)
}

pub(super) fn severity_counts_refs(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        return "none".into();
    }

    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.severity).or_default() += 1;
    }

    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .filter_map(|severity| {
        counts
            .get(&severity)
            .map(|count| format!("{count} {severity}"))
    })
    .collect::<Vec<_>>()
    .join(", ")
}

pub(super) fn next_actions(report: &ScanReport) -> Vec<String> {
    if report.findings.is_empty() {
        return vec![
            "Add a CI gate with `agentshield ci install`.".into(),
            "Keep `agentshield scan . --ignore-tests --fail-on high` in the pre-merge path.".into(),
        ];
    }

    let mut actions = Vec::new();
    if !report.verdict.pass {
        actions.push(format!(
            "Fix findings at or above `{}` first; they are blocking the security gate.",
            report.verdict.fail_threshold
        ));
    }

    let mut seen_rules = BTreeSet::new();
    for finding in &report.findings {
        if !seen_rules.insert(finding.rule_id.clone()) {
            continue;
        }
        if let Some(command) = exact_command_for_finding(finding) {
            actions.push(command);
        } else if let Some(remediation) = &finding.remediation {
            actions.push(remediation.clone());
        } else {
            actions.push(format!("Review `{}`: {}", finding.rule_id, finding.message));
        }

        if actions.len() >= 5 {
            break;
        }
    }

    actions.push("Run `agentshield scan . --explain` again after changes.".into());
    actions
}

fn exact_command_for_finding(finding: &Finding) -> Option<String> {
    let file_name = finding
        .location
        .as_ref()
        .and_then(|location| location.file.file_name())
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();

    match finding.rule_id.as_str() {
        "SHIELD-009" => {
            let package = package_name_from_message(&finding.message)?;
            if file_name == "package.json" {
                Some(format!(
                    "Pin `{package}` with `npm install {package}@<exact-version> --save-exact`."
                ))
            } else if file_name == "requirements.txt" {
                Some(format!(
                    "Pin `{package}` by changing the requirement to `{package}==<exact-version>`."
                ))
            } else if file_name == "pyproject.toml" {
                Some(format!(
                    "Pin `{package}` to an exact version in `pyproject.toml`, then regenerate the lockfile."
                ))
            } else {
                None
            }
        }
        "SHIELD-012" => {
            if file_name == "package.json" {
                Some("Generate an npm lockfile with `npm install`.".into())
            } else if file_name == "requirements.txt" {
                Some(
                    "Generate a reproducible Python lockfile with `uv lock` or `poetry lock`."
                        .into(),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

fn package_name_from_message(message: &str) -> Option<&str> {
    let start = message.find('\'')? + 1;
    let rest = &message[start..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

pub(super) fn display_list(values: &BTreeSet<String>, empty: &str) -> String {
    if values.is_empty() {
        empty.into()
    } else {
        values.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

pub(super) fn format_path_filters(summary: &ScanPathFilterSummary) -> String {
    if summary.include.is_empty() && summary.exclude.is_empty() {
        return "disabled".into();
    }

    let include = if summary.include.is_empty() {
        "all".into()
    } else {
        summary.include.join(", ")
    };
    let exclude = if summary.exclude.is_empty() {
        "none".into()
    } else {
        summary.exclude.join(", ")
    };

    format!("include {include}; exclude {exclude}")
}

fn display_language(language: Language) -> &'static str {
    match language {
        Language::Python => "Python",
        Language::TypeScript => "TypeScript",
        Language::JavaScript => "JavaScript",
        Language::Shell => "Shell",
        Language::Json => "JSON",
        Language::Toml => "TOML",
        Language::Yaml => "YAML",
        Language::Markdown => "Markdown",
        Language::Unknown => "Unknown",
    }
}
