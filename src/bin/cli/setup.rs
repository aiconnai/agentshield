use std::path::PathBuf;

use agentshield::config::{Config, ScanPathFilterSummary};
use agentshield::doctor::DoctorReport;
use agentshield::output::OutputFormat;
use agentshield::rules::Severity;
use agentshield::ux::{CiInstallOptions, ExplainOptions};
use agentshield::ScanOptions;

pub(super) struct CiInstallRequest {
    pub output: PathBuf,
    pub force: bool,
    pub scan_path: String,
    pub fail_on: String,
    pub include_tests: bool,
    pub baseline: Option<String>,
    pub upload_sarif: bool,
    pub suite: bool,
}

pub(super) fn cmd_quickstart(
    path: PathBuf,
    force: bool,
    fail_on_str: String,
    include_tests: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    let fail_on = require_severity(&fail_on_str)?;
    let ignore_tests = !include_tests;
    let config_path = path.join(".agentshield.toml");

    println!("AgentShield quickstart");
    println!("Project: {}", path.display());

    if config_path.exists() && !force {
        println!(
            "Config: {} already exists; left unchanged",
            config_path.display()
        );
    } else {
        if let Some(parent) = non_empty_parent(&config_path) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &config_path,
            agentshield::ux::quickstart_config_toml(fail_on, ignore_tests),
        )?;
        println!("Config: created {}", config_path.display());
    }

    println!(
        "CI: run `agentshield ci install --scan-path {}` to add GitHub Actions",
        shell_display_path(&path)
    );
    println!();

    let options = ScanOptions {
        config_path: Some(config_path),
        format: OutputFormat::Console,
        fail_on_override: Some(fail_on),
        ignore_tests,
    };

    match agentshield::scan(&path, &options) {
        Ok(report) => {
            let rendered =
                agentshield::ux::render_explain(&report, &ExplainOptions { ignore_tests });
            print!("{rendered}");
            Ok(if report.verdict.pass { 0 } else { 1 })
        }
        Err(err) if agentshield::ux::is_no_adapter(&err) => {
            print!(
                "{}",
                agentshield::ux::render_no_adapter_explain(
                    &path,
                    ignore_tests,
                    &ScanPathFilterSummary::default(),
                )
            );
            Ok(0)
        }
        Err(err) => Err(err),
    }
}

pub(super) fn cmd_ci_install(
    request: CiInstallRequest,
) -> Result<i32, agentshield::error::ShieldError> {
    let fail_on = require_severity(&request.fail_on)?;
    let fail_on = fail_on.to_string();

    if request.output.exists() && !request.force {
        eprintln!(
            "{} already exists. Use --force to overwrite.",
            request.output.display()
        );
        return Ok(1);
    }

    if let Some(parent) = non_empty_parent(&request.output) {
        std::fs::create_dir_all(parent)?;
    }

    let options = CiInstallOptions {
        fail_on: &fail_on,
        ignore_tests: !request.include_tests,
        scan_path: &request.scan_path,
        baseline_path: request.baseline.as_deref(),
        upload_sarif: request.upload_sarif,
    };
    let workflow = if request.suite {
        agentshield::ux::github_actions_security_suite_workflow(&options)
    } else {
        agentshield::ux::github_actions_workflow(&options)
    };
    std::fs::write(&request.output, workflow)?;
    println!("Created {}", request.output.display());
    if request.suite {
        println!("Security suite: runs CodeQL, Gitleaks, Semgrep CE, and AgentShield.");
    }
    println!(
        "AgentShield gate: scans `{}` and fails on `{fail_on}` findings or higher.",
        request.scan_path
    );
    if request.upload_sarif {
        println!("SARIF upload: enabled for GitHub Code Scanning.");
    }
    if let Some(baseline) = request.baseline {
        println!("Baseline: filters known findings from `{baseline}`.");
    }
    Ok(0)
}

pub(super) fn cmd_doctor(
    path: PathBuf,
    config: Option<PathBuf>,
    json: bool,
    ignore_tests: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    let report = agentshield::doctor::run_doctor(&path, config, ignore_tests)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_doctor_console(&report);
    }

    Ok(0)
}

pub(super) fn cmd_init(force: bool) -> Result<i32, agentshield::error::ShieldError> {
    let path = PathBuf::from(".agentshield.toml");

    if path.exists() && !force {
        eprintln!(".agentshield.toml already exists. Use --force to overwrite.");
        return Ok(1);
    }

    std::fs::write(&path, Config::starter_toml())?;
    println!("Created .agentshield.toml");

    Ok(0)
}

fn require_severity(value: &str) -> Result<Severity, agentshield::error::ShieldError> {
    Severity::from_str_lenient(value).ok_or_else(|| {
        agentshield::error::ShieldError::Config(format!(
            "unknown severity '{value}' (expected info, low, medium, high, or critical)"
        ))
    })
}

fn non_empty_parent(path: &std::path::Path) -> Option<&std::path::Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn shell_display_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    if text.contains(' ') {
        format!("'{}'", text.replace('\'', "'\\''"))
    } else {
        text
    }
}

fn print_doctor_console(report: &DoctorReport) {
    println!("AgentShield doctor");
    println!("Version: {}", report.version);
    println!("Target: {}", report.target.display());
    println!(
        "Config: {} ({})",
        report.config_path.display(),
        if report.config_found {
            "found"
        } else {
            "not found, using defaults"
        }
    );
    println!("Fail on: {}", report.fail_on);
    println!("Ignore tests: {}", report.ignore_tests);
    println!(
        "Features: python={}, typescript={}, runtime={}",
        report.enabled_features.python,
        report.enabled_features.typescript,
        report.enabled_features.runtime
    );
    println!(
        "Adapters: detected [{}], available [{}]",
        report.detected_adapters.join(", "),
        report.available_adapters.join(", ")
    );
    println!(
        "Runtime wrap: {}",
        if report.runtime_wrap_available {
            "available"
        } else {
            "not available"
        }
    );
}
