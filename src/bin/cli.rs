use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use agentshield::baseline::{BaselineEntry, BaselineFile};
use agentshield::config::Config;
use agentshield::output::OutputFormat;
use agentshield::rules::{RuleEngine, Severity};
use agentshield::ScanOptions;

#[derive(Parser)]
#[command(
    name = "agentshield",
    about = "Security scanner for AI agent extensions (MCP, OpenClaw, LangChain)",
    long_about = "AgentShield scans AI agent extensions for security vulnerabilities.\n\n\
                  It detects command injection, credential exfiltration, SSRF, arbitrary \
                  file access, supply chain issues, and more. Results can be output as \
                  console text, JSON, SARIF (GitHub Code Scanning), or HTML reports.",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an agent extension for security issues
    Scan {
        /// Path to the extension directory
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Config file path
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Output format (console, json, sarif, html)
        #[arg(long, short = 'f', default_value = "console")]
        format: String,

        /// Minimum severity to fail (info, low, medium, high, critical)
        #[arg(long)]
        fail_on: Option<String>,

        /// Write output to file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Skip test files (test/, tests/, __tests__/, *.test.ts, *.spec.ts, etc.)
        #[arg(long)]
        ignore_tests: bool,

        /// Filter out findings that match a previously written baseline file
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,

        /// Write all current findings as a baseline file
        #[arg(long, value_name = "PATH")]
        write_baseline: Option<PathBuf>,
    },

    /// List all available detection rules
    ListRules {
        /// Output format (table, json)
        #[arg(long, short = 'f', default_value = "table")]
        format: String,
    },

    /// Generate a starter .agentshield.toml config file
    Init {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,
    },

    /// Add a suppression entry to .agentshield.toml for a specific finding
    Suppress {
        /// SHA-256 fingerprint of the finding to suppress (from --format json output)
        fingerprint: String,

        /// Mandatory reason explaining why this finding is suppressed
        #[arg(long, short = 'r')]
        reason: String,

        /// Optional expiry date in YYYY-MM-DD format
        #[arg(long, short = 'e')]
        expires: Option<String>,

        /// Config file path (defaults to .agentshield.toml in the current directory)
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },

    /// List all suppressions in .agentshield.toml
    ListSuppressions {
        /// Config file path (defaults to .agentshield.toml in the current directory)
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan {
            path,
            config,
            format,
            fail_on,
            output,
            ignore_tests,
            baseline,
            write_baseline,
        } => cmd_scan(ScanArgs {
            path,
            config,
            format_str: format,
            fail_on_str: fail_on,
            output_path: output,
            ignore_tests,
            baseline_path: baseline,
            write_baseline_path: write_baseline,
        }),
        Commands::ListRules { format } => cmd_list_rules(format),
        Commands::Init { force } => cmd_init(force),
        Commands::Suppress {
            fingerprint,
            reason,
            expires,
            config,
        } => cmd_suppress(fingerprint, reason, expires, config),
        Commands::ListSuppressions { config } => cmd_list_suppressions(config),
    };

    match result {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(e.exit_code());
        }
    }
}

/// Arguments for the scan subcommand, extracted to avoid too-many-arguments.
struct ScanArgs {
    path: PathBuf,
    config: Option<PathBuf>,
    format_str: String,
    fail_on_str: Option<String>,
    output_path: Option<PathBuf>,
    ignore_tests: bool,
    baseline_path: Option<PathBuf>,
    write_baseline_path: Option<PathBuf>,
}

fn cmd_scan(args: ScanArgs) -> Result<i32, agentshield::error::ShieldError> {
    let ScanArgs {
        path,
        config,
        format_str,
        fail_on_str,
        output_path,
        ignore_tests,
        baseline_path,
        write_baseline_path,
    } = args;
    let format = OutputFormat::from_str_lenient(&format_str).unwrap_or_else(|| {
        eprintln!("Warning: unknown format '{}', using console", format_str);
        OutputFormat::Console
    });

    let fail_on = fail_on_str.and_then(|s| {
        let sev = Severity::from_str_lenient(&s);
        if sev.is_none() {
            eprintln!("Warning: unknown severity '{}', using config default", s);
        }
        sev
    });

    let options = ScanOptions {
        config_path: config,
        format,
        fail_on_override: fail_on,
        ignore_tests,
    };

    let mut report = agentshield::scan(&path, &options)?;

    // Filter out baseline findings if --baseline is provided
    if let Some(ref bl_path) = baseline_path {
        let baseline = BaselineFile::load(bl_path)?;
        report.findings.retain(|f| {
            let fp = f.fingerprint(&report.scan_root);
            !baseline.contains(&fp)
        });
        // Re-evaluate verdict with filtered findings
        let config_path = options
            .config_path
            .clone()
            .unwrap_or_else(|| path.join(".agentshield.toml"));
        let mut cfg = agentshield::config::Config::load(&config_path)?;
        if let Some(fail_on_sev) = fail_on {
            cfg.policy.fail_on = fail_on_sev;
        }
        report.verdict = cfg.policy.evaluate(&report.findings);
    }

    // Write baseline if --write-baseline is provided
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

    let rendered = agentshield::render_report(&report, format)?;

    match output_path {
        Some(out) => std::fs::write(&out, &rendered)?,
        None => print!("{}", rendered),
    }

    // Exit code: 0 = pass, 1 = findings above threshold
    Ok(if report.verdict.pass { 0 } else { 1 })
}

fn cmd_list_rules(format_str: String) -> Result<i32, agentshield::error::ShieldError> {
    let engine = RuleEngine::new();
    let rules = engine.list_rules();

    match format_str.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&rules)?;
            println!("{}", json);
        }
        _ => {
            println!(
                "{:<12} {:<28} {:<10} {:<8} CATEGORY",
                "ID", "NAME", "SEVERITY", "CWE"
            );
            println!("{}", "-".repeat(80));
            for rule in &rules {
                println!(
                    "{:<12} {:<28} {:<10} {:<8} {}",
                    rule.id,
                    rule.name,
                    rule.default_severity.to_string(),
                    rule.cwe_id.as_deref().unwrap_or("-"),
                    rule.attack_category,
                );
            }
        }
    }

    Ok(0)
}

fn cmd_init(force: bool) -> Result<i32, agentshield::error::ShieldError> {
    let path = PathBuf::from(".agentshield.toml");

    if path.exists() && !force {
        eprintln!(".agentshield.toml already exists. Use --force to overwrite.");
        return Ok(1);
    }

    std::fs::write(&path, Config::starter_toml())?;
    println!("Created .agentshield.toml");

    Ok(0)
}

fn cmd_suppress(
    fingerprint: String,
    reason: String,
    expires: Option<String>,
    config: Option<PathBuf>,
) -> Result<i32, agentshield::error::ShieldError> {
    use agentshield::rules::policy::Suppression;

    if reason.trim().is_empty() {
        eprintln!("Error: --reason must be a non-empty string");
        return Ok(2);
    }

    // Validate the expires date format if provided
    if let Some(ref date_str) = expires {
        if chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d").is_err() {
            eprintln!(
                "Error: --expires '{}' is not a valid date (expected YYYY-MM-DD)",
                date_str
            );
            return Ok(2);
        }
    }

    let config_path = config.unwrap_or_else(|| PathBuf::from(".agentshield.toml"));

    // Load existing config (or default if file doesn't exist)
    let mut cfg = Config::load(&config_path)?;

    let created_at = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let suppression = Suppression {
        fingerprint: fingerprint.clone(),
        reason: reason.clone(),
        expires: expires.clone(),
        created_at: Some(created_at),
    };

    cfg.policy.suppressions.push(suppression);

    // Serialize and write back
    let toml_str = toml::to_string_pretty(&cfg)?;
    std::fs::write(&config_path, &toml_str)?;

    let expires_display = expires
        .as_deref()
        .map(|d| format!(" (expires: {})", d))
        .unwrap_or_default();
    println!(
        "Suppressed finding {} : {}{}",
        &fingerprint[..fingerprint.len().min(12)],
        reason,
        expires_display
    );

    Ok(0)
}

fn cmd_list_suppressions(
    config: Option<PathBuf>,
) -> Result<i32, agentshield::error::ShieldError> {
    let config_path = config.unwrap_or_else(|| PathBuf::from(".agentshield.toml"));
    let cfg = Config::load(&config_path)?;
    let suppressions = &cfg.policy.suppressions;

    if suppressions.is_empty() {
        println!("No suppressions configured.");
        return Ok(0);
    }

    println!(
        "{:<16}  {:<40}  {:<10}  STATUS",
        "FINGERPRINT", "REASON", "EXPIRES"
    );
    println!("{}", "-".repeat(80));

    for s in suppressions {
        let fp_short = &s.fingerprint[..s.fingerprint.len().min(16)];
        let reason_truncated = if s.reason.len() > 40 {
            format!("{}...", &s.reason[..37])
        } else {
            s.reason.clone()
        };
        let expires_display = s.expires.as_deref().unwrap_or("-");
        let status = if s.is_expired() { "expired" } else { "active" };

        println!(
            "{:<16}  {:<40}  {:<10}  {}",
            fp_short, reason_truncated, expires_display, status
        );
    }

    Ok(0)
}
