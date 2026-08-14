use std::path::PathBuf;

use agentshield::ScanOptions;
use agentshield::baseline::{BaselineEntry, BaselineFile};
use agentshield::config::{Config, ScanPathFilter};
use agentshield::egress::policy::EgressPolicy;
use agentshield::output::OutputFormat;
use agentshield::rules::Severity;
use agentshield::ux::ExplainOptions;

pub(super) struct ScanArgs {
    pub(super) path: PathBuf,
    pub(super) config: Option<PathBuf>,
    pub(super) format_str: String,
    pub(super) fail_on_str: Option<String>,
    pub(super) output_path: Option<PathBuf>,
    pub(super) ignore_tests: bool,
    pub(super) baseline_path: Option<PathBuf>,
    pub(super) include_patterns: Vec<String>,
    pub(super) exclude_patterns: Vec<String>,
    pub(super) write_baseline_path: Option<PathBuf>,
    pub(super) emit_egress_policy_path: Option<PathBuf>,
    pub(super) explain: bool,
    pub(super) experimental_risk: bool,
    pub(super) rules_dir: Option<PathBuf>,
}

pub(super) fn cmd_scan(args: ScanArgs) -> Result<i32, agentshield::error::ShieldError> {
    let ScanArgs {
        path,
        config,
        format_str,
        fail_on_str,
        output_path,
        ignore_tests,
        baseline_path,
        include_patterns,
        exclude_patterns,
        write_baseline_path,
        emit_egress_policy_path,
        explain,
        experimental_risk,
        rules_dir,
    } = args;
    let format = OutputFormat::from_str_lenient(&format_str).unwrap_or_else(|| {
        eprintln!("Warning: unknown format '{}', using console", format_str);
        OutputFormat::Console
    });

    if explain && format != OutputFormat::Console {
        return Err(agentshield::error::ShieldError::Config(
            "`scan --explain` is console-only; remove --format or use --format console".into(),
        ));
    }
    if explain && experimental_risk {
        return Err(agentshield::error::ShieldError::Config(
            "`scan --explain` and `--experimental-risk` are separate output modes".into(),
        ));
    }
    if experimental_risk && !matches!(format, OutputFormat::Console | OutputFormat::Json) {
        return Err(agentshield::error::ShieldError::Config(
            "`--experimental-risk` supports only console and JSON output".into(),
        ));
    }

    let config_path = config
        .clone()
        .unwrap_or_else(|| path.join(".agentshield.toml"));
    let mut cfg = Config::load(&config_path)?;
    let fail_on = parse_optional_severity(fail_on_str.as_deref())?;

    let effective_ignore_tests = ignore_tests || cfg.scan.ignore_tests;
    let mut effective_scan_config = cfg.scan.clone();
    effective_scan_config
        .include
        .extend(include_patterns.iter().cloned());
    effective_scan_config
        .exclude
        .extend(exclude_patterns.iter().cloned());
    let path_filter_summary =
        ScanPathFilter::from_scan_config(&effective_scan_config, effective_ignore_tests)?.summary();

    let options = ScanOptions {
        config_path: config,
        format,
        fail_on_override: fail_on,
        ignore_tests,
        custom_rules_dir: rules_dir,
    };

    let mut report = match agentshield::scan_with_path_filter_overrides(
        &path,
        &options,
        &include_patterns,
        &exclude_patterns,
    ) {
        Ok(report) => report,
        Err(err) if explain && agentshield::ux::is_no_adapter(&err) => {
            let rendered = agentshield::ux::render_no_adapter_explain(
                &path,
                effective_ignore_tests,
                &path_filter_summary,
            );
            write_rendered(output_path.as_ref(), &rendered)?;
            return Ok(2);
        }
        Err(err) => return Err(err),
    };

    if let Some(ref bl_path) = baseline_path {
        let baseline = BaselineFile::load(bl_path)?;
        report.findings.retain(|f| {
            let fp = f.fingerprint(&report.scan_root);
            !baseline.contains(&fp)
        });
        if let Some(fail_on_sev) = fail_on {
            cfg.policy.fail_on = fail_on_sev;
        }
        // Re-apply policy (ignore rules, overrides, suppressions) to the
        // baseline-filtered findings before re-evaluating the verdict, so the
        // verdict stays consistent with the rendered findings (issue #34).
        let effective = cfg.policy.apply(&report.findings, &report.scan_root);
        report.verdict = cfg.policy.evaluate(&effective);
    }

    if let Some(ref wb_path) = write_baseline_path {
        let now = chrono::Utc::now().to_rfc3339();
        let entries: Vec<BaselineEntry> = report
            .findings
            .iter()
            .map(|f| BaselineEntry {
                fingerprint: f.fingerprint(&report.scan_root),
                rule_id: f.rule_id.clone(),
                first_seen: now.clone(),
            })
            .collect();
        let baseline = BaselineFile::new(entries);
        baseline.save(wb_path)?;
        eprintln!(
            "Wrote {} findings to baseline: {}",
            report.findings.len(),
            wb_path.display()
        );
    }

    if let Some(ref egress_path) = emit_egress_policy_path {
        let policy = EgressPolicy::from_scan_targets(&report.targets);
        policy.save(egress_path)?;
        eprintln!(
            "Wrote egress policy with {} allowed domain(s) to {}",
            policy.domains.allow.len(),
            egress_path.display()
        );
    }

    let rendered = if explain {
        agentshield::ux::render_explain(
            &report,
            &ExplainOptions {
                ignore_tests: effective_ignore_tests,
            },
        )
    } else if experimental_risk {
        agentshield::render_report_with_experimental_risk(&report, format)?
    } else {
        agentshield::render_report(&report, format)?
    };

    write_rendered(output_path.as_ref(), &rendered)?;

    Ok(if report.verdict.pass { 0 } else { 1 })
}

fn parse_optional_severity(
    value: Option<&str>,
) -> Result<Option<Severity>, agentshield::error::ShieldError> {
    match value {
        Some(raw) => {
            let sev = Severity::from_str_lenient(raw).ok_or_else(|| {
                agentshield::error::ShieldError::Config(format!(
                    "unknown severity '{raw}' (expected info, low, medium, high, or critical)"
                ))
            })?;
            Ok(Some(sev))
        }
        None => Ok(None),
    }
}

fn write_rendered(
    output_path: Option<&PathBuf>,
    rendered: &str,
) -> Result<(), agentshield::error::ShieldError> {
    match output_path {
        Some(out) => std::fs::write(out, rendered)?,
        None => print!("{rendered}"),
    }
    Ok(())
}
