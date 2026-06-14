use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::rules::{AttackCategory, Finding, Severity};
use crate::ScanReport;

const MAX_ITEMS: usize = 3;

pub(super) fn render(report: &ScanReport) -> String {
    let blocking_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= report.verdict.fail_threshold)
        .collect();

    let mut output = String::new();
    output.push_str("Hotspots:\n");

    if blocking_findings.is_empty() {
        output.push_str("- Blocking findings: none\n\n");
        return output;
    }

    let runtime_findings: Vec<&Finding> = blocking_findings
        .iter()
        .copied()
        .filter(|finding| finding.attack_category != AttackCategory::SupplyChain)
        .collect();
    let supply_chain_findings: Vec<&Finding> = blocking_findings
        .iter()
        .copied()
        .filter(|finding| finding.attack_category == AttackCategory::SupplyChain)
        .collect();

    output.push_str(&format!(
        "- Runtime-risk concentration: {}\n",
        concentration_summary(
            &runtime_findings,
            &report.scan_root,
            GroupingMode::RuntimeDirectory,
        )
    ));
    output.push_str(&format!(
        "- Supply-chain concentration: {}\n",
        concentration_summary(
            &supply_chain_findings,
            &report.scan_root,
            GroupingMode::SupplyChainFile,
        )
    ));
    output.push_str(&format!(
        "- Rule concentration: {}\n",
        rule_summary(&blocking_findings)
    ));

    if mostly_outside_tool_sources(report, &blocking_findings) {
        output.push_str(
            "- Most blocking findings are outside discovered tool source files; consider `[scan] include/exclude` or a baseline.\n",
        );
    }

    output.push('\n');
    output
}

#[derive(Debug, Clone, Copy)]
enum GroupingMode {
    RuntimeDirectory,
    SupplyChainFile,
}

#[derive(Debug)]
struct GroupCount {
    label: String,
    total: usize,
    severity_counts: BTreeMap<Severity, usize>,
}

fn concentration_summary(
    findings: &[&Finding],
    scan_root: &Path,
    grouping_mode: GroupingMode,
) -> String {
    if findings.is_empty() {
        return "none".into();
    }

    let mut groups: BTreeMap<String, GroupCount> = BTreeMap::new();
    for finding in findings {
        let label = group_label(finding, scan_root, grouping_mode);
        let entry = groups.entry(label.clone()).or_insert_with(|| GroupCount {
            label,
            total: 0,
            severity_counts: BTreeMap::new(),
        });
        entry.total += 1;
        *entry.severity_counts.entry(finding.severity).or_default() += 1;
    }

    let mut ranked: Vec<GroupCount> = groups.into_values().collect();
    ranked.sort_by(|left, right| {
        right
            .total
            .cmp(&left.total)
            .then_with(|| left.label.cmp(&right.label))
    });

    ranked
        .into_iter()
        .take(MAX_ITEMS)
        .map(|group| {
            format!(
                "{} ({})",
                group.label,
                severity_summary(&group.severity_counts)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn rule_summary(findings: &[&Finding]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        *counts.entry(&finding.rule_id).or_default() += 1;
    }

    let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
    ranked.sort_by(|(left_rule, left_count), (right_rule, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_rule.cmp(right_rule))
    });

    ranked
        .into_iter()
        .take(MAX_ITEMS)
        .map(|(rule_id, count)| format!("{rule_id} ({count})"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn group_label(finding: &Finding, scan_root: &Path, grouping_mode: GroupingMode) -> String {
    let Some(location) = &finding.location else {
        return "unknown location".into();
    };
    let relative = relative_path(scan_root, &location.file);

    match grouping_mode {
        GroupingMode::RuntimeDirectory => directory_label(&relative),
        GroupingMode::SupplyChainFile => relative,
    }
}

fn directory_label(relative_path: &str) -> String {
    let path = Path::new(relative_path);
    if let Some(first_component) = path.components().find_map(|component| match component {
        std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
        std::path::Component::CurDir
        | std::path::Component::ParentDir
        | std::path::Component::RootDir
        | std::path::Component::Prefix(_) => None,
    }) {
        if path
            .components()
            .filter(|component| matches!(component, std::path::Component::Normal(_)))
            .count()
            > 1
        {
            return format!("{first_component}/");
        }
    }

    let Some(parent) = path.parent() else {
        return relative_path.into();
    };
    if parent.as_os_str().is_empty() {
        relative_path.into()
    } else {
        format!("{}/", parent.to_string_lossy().replace('\\', "/"))
    }
}

fn severity_summary(counts: &BTreeMap<Severity, usize>) -> String {
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

fn mostly_outside_tool_sources(report: &ScanReport, blocking_findings: &[&Finding]) -> bool {
    let tool_files = tool_source_files(report);
    if tool_files.is_empty() {
        return false;
    }

    let outside_count = blocking_findings
        .iter()
        .filter(|finding| {
            finding
                .location
                .as_ref()
                .is_none_or(|location| !tool_files.contains(&normalized_path(&location.file)))
        })
        .count();

    outside_count > blocking_findings.len().saturating_sub(outside_count)
}

fn tool_source_files(report: &ScanReport) -> BTreeSet<PathBuf> {
    report
        .targets
        .iter()
        .flat_map(|target| target.tools.iter())
        .filter_map(|tool| tool.defined_at.as_ref())
        .map(|location| normalized_path(&location.file))
        .collect()
}

fn relative_path(root: &Path, path: &Path) -> String {
    let normalized_root = normalized_path(root);
    let normalized_path = normalized_path(path);
    let relative = normalized_path
        .strip_prefix(&normalized_root)
        .unwrap_or(&normalized_path);

    relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            std::path::Component::CurDir => None,
            std::path::Component::ParentDir => Some("..".to_string()),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => None,
        })
        .collect::<Vec<String>>()
        .join("/")
}

fn normalized_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
