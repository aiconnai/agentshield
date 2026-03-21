use std::path::Path;

use crate::rules::policy::PolicyVerdict;
use crate::rules::{Finding, Severity};

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";

/// Render findings as colored console output, grouped by severity then file path.
///
/// Each finding includes a truncated fingerprint (first 12 hex chars) for quick
/// cross-referencing with JSON/SARIF/HTML outputs.
pub fn render(findings: &[Finding], verdict: &PolicyVerdict, scan_root: &Path) -> String {
    let use_color = std::env::var("NO_COLOR").is_err();
    let mut output = String::new();

    if findings.is_empty() {
        if use_color {
            output.push_str(&format!(
                "\n  {GREEN}{BOLD}No security findings detected.{RESET}\n\n"
            ));
        } else {
            output.push_str("\n  No security findings detected.\n\n");
        }
        return output;
    }

    // Sort by severity (critical first), then by file path
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then_with(|| {
            let a_file = a.location.as_ref().map(|l| &l.file);
            let b_file = b.location.as_ref().map(|l| &l.file);
            a_file.cmp(&b_file)
        })
    });

    output.push_str(&format!(
        "\n  {bold}{} finding(s) detected:{reset}\n\n",
        findings.len(),
        bold = if use_color { BOLD } else { "" },
        reset = if use_color { RESET } else { "" },
    ));

    for finding in &sorted {
        let severity_tag = if use_color {
            match finding.severity {
                Severity::Critical => format!("{RED}{BOLD}[CRITICAL]{RESET}"),
                Severity::High => format!("{MAGENTA}{BOLD}[HIGH]    {RESET}"),
                Severity::Medium => format!("{YELLOW}{BOLD}[MEDIUM]  {RESET}"),
                Severity::Low => format!("{BLUE}[LOW]     {RESET}"),
                Severity::Info => format!("{DIM}[INFO]    {RESET}"),
            }
        } else {
            match finding.severity {
                Severity::Critical => "[CRITICAL]".into(),
                Severity::High => "[HIGH]    ".into(),
                Severity::Medium => "[MEDIUM]  ".into(),
                Severity::Low => "[LOW]     ".into(),
                Severity::Info => "[INFO]    ".into(),
            }
        };

        let location = finding
            .location
            .as_ref()
            .map(|l| format!("{}:{}", l.file.display(), l.line))
            .unwrap_or_else(|| "-".into());

        output.push_str(&format!(
            "  {} {bold}{}{reset} {}\n",
            severity_tag,
            finding.rule_id,
            finding.message,
            bold = if use_color { BOLD } else { "" },
            reset = if use_color { RESET } else { "" },
        ));
        output.push_str(&format!(
            "           {dim}at {}{reset}\n",
            location,
            dim = if use_color { DIM } else { "" },
            reset = if use_color { RESET } else { "" },
        ));
        let fp = finding.fingerprint(scan_root);
        output.push_str(&format!(
            "           {dim}fp {}{reset}\n",
            &fp[..12],
            dim = if use_color { DIM } else { "" },
            reset = if use_color { RESET } else { "" },
        ));
        if let Some(remediation) = &finding.remediation {
            output.push_str(&format!(
                "           {cyan}fix: {}{reset}\n",
                remediation,
                cyan = if use_color { CYAN } else { "" },
                reset = if use_color { RESET } else { "" },
            ));
        }
        output.push('\n');
    }

    // Verdict
    let (status, status_color) = if verdict.pass {
        ("PASS", if use_color { GREEN } else { "" })
    } else {
        ("FAIL", if use_color { RED } else { "" })
    };
    output.push_str(&format!(
        "  Result: {sc}{bold}{}{reset} (threshold: {}, highest: {})\n\n",
        status,
        verdict.fail_threshold,
        verdict
            .highest_severity
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into()),
        sc = status_color,
        bold = if use_color { BOLD } else { "" },
        reset = if use_color { RESET } else { "" },
    ));

    output
}
