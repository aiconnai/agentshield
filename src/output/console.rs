use std::borrow::Cow;
use std::path::Path;

use crate::rules::policy::PolicyVerdict;
use crate::rules::{AttackCategory, Finding, Severity};

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
    let fingerprints = crate::rules::fingerprint::compute_fingerprints(findings, scan_root);
    render_fingerprinted(findings, &fingerprints, verdict)
}

/// Render findings with precomputed fingerprints aligned with `findings`.
pub(crate) fn render_fingerprinted(
    findings: &[Finding],
    fingerprints: &[String],
    verdict: &PolicyVerdict,
) -> String {
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
    let mut sorted: Vec<(&Finding, &String)> = findings.iter().zip(fingerprints).collect();
    sorted.sort_by(|(a, _), (b, _)| {
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
    output.push_str(&format!(
        "  Runtime-risk findings: {}\n",
        grouped_count(findings, false)
    ));
    output.push_str(&format!(
        "  Supply-chain hygiene: {}\n\n",
        grouped_count(findings, true)
    ));

    for &(finding, fp) in &sorted {
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
            .map(|l| {
                format!(
                    "{}:{}",
                    terminal_safe(&l.file.display().to_string()),
                    l.line
                )
            })
            .unwrap_or_else(|| "-".into());

        output.push_str(&format!(
            "  {} {bold}{}{reset} {}\n",
            severity_tag,
            terminal_safe(&finding.rule_id),
            terminal_safe(&finding.message),
            bold = if use_color { BOLD } else { "" },
            reset = if use_color { RESET } else { "" },
        ));
        output.push_str(&format!(
            "           {dim}at {}{reset}\n",
            location,
            dim = if use_color { DIM } else { "" },
            reset = if use_color { RESET } else { "" },
        ));
        output.push_str(&format!(
            "           {dim}fp {}{reset}\n",
            &fp[..12],
            dim = if use_color { DIM } else { "" },
            reset = if use_color { RESET } else { "" },
        ));
        if let Some(remediation) = &finding.remediation {
            output.push_str(&format!(
                "           {cyan}fix: {}{reset}\n",
                terminal_safe(remediation),
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

/// Make single-line text from scanned sources or rule files safe for a terminal.
///
/// Every control character (C0, DEL, C1, including newline) is replaced with
/// its `\u{..}` escape so scanned content cannot inject ANSI/OSC sequences or
/// forge extra report lines.
pub(crate) fn terminal_safe(text: &str) -> Cow<'_, str> {
    escape_controls(text, |_| false)
}

/// Like [`terminal_safe`] but keeps `\n` and `\t`, for already-laid-out
/// multi-line output that contains no intentional escape sequences.
pub(crate) fn terminal_block_safe(text: &str) -> Cow<'_, str> {
    escape_controls(text, |c| c == '\n' || c == '\t')
}

fn escape_controls(text: &str, keep: impl Fn(char) -> bool) -> Cow<'_, str> {
    let needs_escape = |c: char| c.is_control() && !keep(c);
    if !text.chars().any(needs_escape) {
        return Cow::Borrowed(text);
    }
    let mut escaped = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if needs_escape(c) {
            escaped.extend(c.escape_unicode());
        } else {
            escaped.push(c);
        }
    }
    Cow::Owned(escaped)
}

fn grouped_count(findings: &[Finding], supply_chain: bool) -> String {
    let count = findings
        .iter()
        .filter(|finding| (finding.attack_category == AttackCategory::SupplyChain) == supply_chain)
        .count();

    if count == 0 {
        "none".into()
    } else if supply_chain {
        format!("{count} recommendation(s)")
    } else {
        format!("{count} finding(s)")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::ir::SourceLocation;
    use crate::rules::policy::PolicyVerdict;
    use crate::rules::{Confidence, Evidence};

    use super::*;

    fn finding(rule_id: &str, category: AttackCategory, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            rule_name: "Rule".into(),
            severity,
            confidence: Confidence::High,
            attack_category: category,
            message: "message".into(),
            location: Some(SourceLocation {
                file: PathBuf::from("server.py"),
                line: 1,
                column: 0,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: "evidence".into(),
                location: None,
                snippet: None,
            }],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    #[test]
    fn console_groups_runtime_and_supply_chain_findings() {
        let output = render(
            &[
                finding(
                    "SHIELD-001",
                    AttackCategory::CommandInjection,
                    Severity::Critical,
                ),
                finding("SHIELD-009", AttackCategory::SupplyChain, Severity::Medium),
            ],
            &PolicyVerdict {
                pass: false,
                total_findings: 2,
                effective_findings: 2,
                highest_severity: Some(Severity::Critical),
                fail_threshold: Severity::High,
            },
            std::path::Path::new("."),
        );

        assert!(output.contains("Runtime-risk findings: 1 finding(s)"));
        assert!(output.contains("Supply-chain hygiene: 1 recommendation(s)"));
    }

    #[test]
    fn console_neutralizes_control_characters_from_scanned_text() {
        // Clear screen, OSC 8 hyperlink, C1 CSI and a forged verdict line.
        let hostile = "\x1b[2J\x1b]8;;https://evil\x07click\u{9b}31m\nResult: PASS";
        let mut f = finding(
            &format!("CUSTOM{hostile}"),
            AttackCategory::CommandInjection,
            Severity::Critical,
        );
        f.message = format!("message {hostile}");
        f.remediation = Some(format!("fix {hostile}"));
        f.location.as_mut().unwrap().file = PathBuf::from(format!("src/{hostile}.py"));

        let output = render(
            &[f],
            &PolicyVerdict {
                pass: false,
                total_findings: 1,
                effective_findings: 1,
                highest_severity: Some(Severity::Critical),
                fail_threshold: Severity::High,
            },
            std::path::Path::new("."),
        );

        assert!(!output.contains("\x1b[2J"), "{output:?}");
        assert!(!output.contains("\x1b]8"), "{output:?}");
        assert!(!output.contains('\x07'), "{output:?}");
        assert!(!output.contains('\u{9b}'), "{output:?}");
        assert!(!output.contains("\nResult: PASS"), "{output:?}");
        assert!(output.contains("message \\u{1b}[2J"), "{output:?}");
        assert!(output.contains("fix \\u{1b}[2J"), "{output:?}");
        assert!(output.contains("src/\\u{1b}[2J"), "{output:?}");
        assert!(output.contains("CUSTOM\\u{1b}[2J"), "{output:?}");
    }

    #[test]
    fn terminal_safe_keeps_plain_text_borrowed() {
        assert!(matches!(
            terminal_safe("plain text: ok"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(terminal_safe("a\tb\nc\x1b"), "a\\u{9}b\\u{a}c\\u{1b}");
        assert_eq!(terminal_block_safe("a\tb\nc\x1b"), "a\tb\nc\\u{1b}");
    }
}
