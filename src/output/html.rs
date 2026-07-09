use std::path::Path;

use crate::error::Result;
use crate::rules::policy::PolicyVerdict;
use crate::rules::{Finding, Severity};

/// Render findings as a self-contained HTML report.
///
/// `scan_root` is used to compute stable fingerprints shown in each finding's
/// detail panel.
pub fn render(
    findings: &[Finding],
    verdict: &PolicyVerdict,
    target_name: &str,
    scan_root: &Path,
) -> Result<String> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let severity_counts = SeverityCounts::from_findings(findings);
    let status_class = if verdict.pass { "pass" } else { "fail" };
    let status_text = if verdict.pass { "PASS" } else { "FAIL" };

    let finding_rows: String = sorted
        .iter()
        .map(|f| {
            let sev_class = severity_class(f.severity);
            let location = f
                .location
                .as_ref()
                .map(|l| format!("{}:{}", l.file.display(), l.line))
                .unwrap_or_else(|| "-".into());
            let cwe = f
                .cwe_id
                .as_ref()
                .map(|c| {
                    format!(
                        "<a href=\"https://cwe.mitre.org/data/definitions/{}.html\">{}</a>",
                        c.trim_start_matches("CWE-"),
                        c
                    )
                })
                .unwrap_or_else(|| "-".into());
            let remediation = f.remediation.as_deref().unwrap_or("-");
            let fingerprint = f.fingerprint(scan_root);
            let evidence_html: String = f
                .evidence
                .iter()
                .map(|e| {
                    let mut s = format!("<li>{}", html_escape(&e.description));
                    if let Some(snippet) = &e.snippet {
                        s.push_str(&format!("<pre><code>{}</code></pre>", html_escape(snippet)));
                    }
                    s.push_str("</li>");
                    s
                })
                .collect();

            format!(
                r#"<tr class="{sev_class}">
  <td><span class="badge {sev_class}">{severity}</span></td>
  <td><code>{rule_id}</code></td>
  <td>{rule_name}</td>
  <td class="msg">{message}</td>
  <td><code>{location}</code></td>
  <td>{cwe}</td>
  <td>{confidence}</td>
</tr>
<tr class="detail-row {sev_class}">
  <td colspan="7">
    <details>
      <summary>Evidence &amp; Remediation</summary>
      <ul>{evidence}</ul>
      <p><strong>Fix:</strong> {remediation}</p>
      <p><strong>Fingerprint:</strong> <code class="fingerprint">{fingerprint}</code></p>
    </details>
  </td>
</tr>"#,
                sev_class = sev_class,
                severity = f.severity.to_string().to_uppercase(),
                rule_id = f.rule_id,
                rule_name = html_escape(&f.rule_name),
                message = html_escape(&f.message),
                location = html_escape(&location),
                cwe = cwe,
                confidence = f.confidence,
                evidence = evidence_html,
                remediation = html_escape(remediation),
                fingerprint = fingerprint,
            )
        })
        .collect();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentShield Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --fg: #c9d1d9; --border: #30363d;
    --card: #161b22; --badge-crit: #f85149; --badge-high: #f0883e;
    --badge-med: #d29922; --badge-low: #58a6ff; --badge-info: #8b949e;
    --pass: #3fb950; --fail: #f85149;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--fg); line-height: 1.5; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{ display: flex; align-items: center; justify-content: space-between;
    padding: 1.5rem; background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 1.5rem; }}
  header h1 {{ font-size: 1.4rem; }}
  header h1 span {{ color: var(--badge-low); font-weight: 400; }}
  .verdict {{ font-size: 1.2rem; font-weight: 700; padding: 0.4rem 1.2rem;
    border-radius: 6px; }}
  .verdict.pass {{ background: var(--pass); color: #000; }}
  .verdict.fail {{ background: var(--fail); color: #fff; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem; margin-bottom: 1.5rem; }}
  .stat {{ background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .count {{ font-size: 2rem; font-weight: 700; }}
  .stat .label {{ font-size: 0.85rem; color: var(--badge-info); }}
  .stat.critical .count {{ color: var(--badge-crit); }}
  .stat.high .count {{ color: var(--badge-high); }}
  .stat.medium .count {{ color: var(--badge-med); }}
  .stat.low .count {{ color: var(--badge-low); }}
  .stat.info .count {{ color: var(--badge-info); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ text-align: left; padding: 0.75rem 1rem; border-bottom: 2px solid var(--border);
    font-size: 0.8rem; text-transform: uppercase; color: var(--badge-info); }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border);
    font-size: 0.9rem; vertical-align: top; }}
  .msg {{ max-width: 350px; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .badge.critical {{ background: var(--badge-crit); }}
  .badge.high {{ background: var(--badge-high); }}
  .badge.medium {{ background: var(--badge-med); color: #000; }}
  .badge.low {{ background: var(--badge-low); color: #000; }}
  .badge.info {{ background: var(--badge-info); color: #000; }}
  .detail-row td {{ padding: 0.25rem 1rem 0.75rem; }}
  details {{ cursor: pointer; }}
  details summary {{ color: var(--badge-low); font-size: 0.85rem; }}
  details ul {{ margin: 0.5rem 0 0.5rem 1.5rem; }}
  details li {{ margin-bottom: 0.3rem; font-size: 0.85rem; }}
  details pre {{ background: var(--bg); padding: 0.5rem; border-radius: 4px;
    margin-top: 0.3rem; overflow-x: auto; font-size: 0.8rem; }}
  details p {{ font-size: 0.85rem; margin-top: 0.5rem; }}
  .fingerprint {{ font-size: 0.75rem; color: var(--badge-info); letter-spacing: 0.02em; }}
  footer {{ margin-top: 1.5rem; text-align: center; font-size: 0.8rem;
    color: var(--badge-info); }}
  footer a {{ color: var(--badge-low); }}
  .empty {{ text-align: center; padding: 3rem; color: var(--pass); font-size: 1.2rem; }}
  @media (max-width: 768px) {{
    .summary {{ grid-template-columns: repeat(3, 1fr); }}
    .msg {{ max-width: 200px; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>AgentShield <span>v{version}</span></h1>
    <div class="verdict {status_class}">{status_text}</div>
  </header>

  <div class="summary">
    <div class="stat"><div class="count">{total}</div><div class="label">Total</div></div>
    <div class="stat critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="count">{high}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="count">{low}</div><div class="label">Low</div></div>
    <div class="stat info"><div class="count">{info_count}</div><div class="label">Info</div></div>
  </div>

  {content}

  <footer>
    Scanned <strong>{target}</strong> with
    <a href="https://github.com/aiconnai/agentshield">AgentShield</a> {version}
    — threshold: {threshold}
  </footer>
</div>
</body>
</html>"##,
        target = html_escape(target_name),
        version = env!("CARGO_PKG_VERSION"),
        status_class = status_class,
        status_text = status_text,
        total = findings.len(),
        critical = severity_counts.critical,
        high = severity_counts.high,
        medium = severity_counts.medium,
        low = severity_counts.low,
        info_count = severity_counts.info,
        threshold = verdict.fail_threshold,
        content = if findings.is_empty() {
            "<div class=\"empty\">No security findings detected.</div>".to_string()
        } else {
            format!(
                r#"<table>
  <thead>
    <tr>
      <th>Severity</th><th>Rule</th><th>Name</th><th>Finding</th>
      <th>Location</th><th>CWE</th><th>Confidence</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>"#,
                rows = finding_rows
            )
        },
    );

    Ok(html)
}

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
