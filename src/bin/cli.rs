use std::path::PathBuf;
use std::process;

#[path = "cli/reporting.rs"]
mod reporting;
#[path = "cli/rules.rs"]
mod rules;
#[path = "cli/runtime.rs"]
mod runtime;
#[path = "cli/scan.rs"]
mod scan;
#[path = "cli/setup.rs"]
mod setup;

use clap::{Parser, Subcommand};

use reporting::{cmd_certify, cmd_list_suppressions, cmd_suppress};
use rules::cmd_list_rules;
#[cfg(feature = "runtime")]
use runtime::cmd_wrap;
#[cfg(feature = "runtime-guard")]
use runtime::{cmd_guard, cmd_mcp_proxy, cmd_mcp_proxy_transport};
use scan::{cmd_scan, ScanArgs};
use setup::{cmd_ci_install, cmd_doctor, cmd_init, cmd_quickstart, CiInstallRequest};

#[derive(Parser)]
#[command(
    name = "agentshield",
    about = "Security scanner for AI agent extensions (MCP, OpenClaw, Hermes Agent, CrewAI, LangChain, GPT Actions, Cursor Rules)",
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

        /// Analyze scan results and emit a starter egress policy to the given path
        #[arg(long, value_name = "PATH")]
        emit_egress_policy: Option<PathBuf>,

        /// Explain the gate, coverage, confidence, grouped findings, and next actions.
        ///
        /// This is console-only so JSON, SARIF, and HTML output contracts stay stable.
        #[arg(long)]
        explain: bool,
    },

    /// First-run setup: create config, inspect coverage, and run an explained scan
    Quickstart {
        /// Project directory to initialize and scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Overwrite an existing .agentshield.toml
        #[arg(long)]
        force: bool,

        /// Minimum severity to fail (info, low, medium, high, critical)
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Include test files in the first scan and generated config
        #[arg(long)]
        include_tests: bool,
    },

    /// Install CI integration helpers
    Ci {
        #[command(subcommand)]
        command: CiCommand,
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

    /// Print environment and configuration diagnostics
    Doctor {
        /// Path to inspect
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Config file path
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Emit diagnostics as JSON
        #[arg(long)]
        json: bool,

        /// Skip test files in effective scan settings
        #[arg(long)]
        ignore_tests: bool,
    },

    /// Evaluate one runtime event from stdin as JSON
    #[cfg(feature = "runtime-guard")]
    Guard {
        /// Read a RuntimeEvent JSON document from stdin
        #[arg(long)]
        stdin: bool,

        /// EXPERIMENTAL: run an MCP JSON-RPC proxy guard. Reads JSON-RPC
        /// messages (one per line) on stdin, evaluates `tools/call` against
        /// runtime policy, and emits a forward marker or a block error.
        #[arg(long)]
        mcp_proxy: bool,

        /// Path to .agentshield.toml for the `[runtime.proxy]` policy
        /// (defaults to ./.agentshield.toml).
        #[arg(long)]
        config: Option<std::path::PathBuf>,

        /// EXPERIMENTAL: with --mcp-proxy, the command after `--` is spawned as
        /// the downstream MCP server and stdio is bridged both ways. Forwarded
        /// `tools/call` requests reach the server and its real response is
        /// returned; blocked ones are not forwarded. With no command, the proxy
        /// runs in line mode (emits `{"forward": ...}` envelopes).
        #[arg(last = true)]
        server: Vec<String>,
    },

    /// Generate a DSSE attestation envelope for scan results
    Certify {
        /// Path to the extension directory
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Path to Ed25519 private key file (32 bytes, raw binary)
        #[arg(long)]
        sign_key: Option<PathBuf>,

        /// Write output to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Config file path
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Skip test files
        #[arg(long)]
        ignore_tests: bool,
    },

    /// Enforce egress policy on a command via a local HTTP proxy
    #[cfg(feature = "runtime")]
    Wrap {
        /// Path to egress policy file (agentshield.egress.toml)
        #[arg(long, value_name = "PATH")]
        policy: PathBuf,

        /// Path to an operator override policy (same format). Can only restrict, never expand.
        #[arg(long = "override-policy", value_name = "PATH")]
        override_policy: Option<PathBuf>,

        /// Audit log output path (overrides policy config)
        #[arg(long, value_name = "PATH")]
        audit_log: Option<PathBuf>,

        /// The command to wrap (use -- before the command)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CiCommand {
    /// Generate a GitHub Actions workflow for AgentShield
    Install {
        /// Workflow output path
        #[arg(long, short = 'o', default_value = ".github/workflows/agentshield.yml")]
        output: PathBuf,

        /// Overwrite an existing workflow file
        #[arg(long)]
        force: bool,

        /// Repository path to scan in CI
        #[arg(long, default_value = ".")]
        scan_path: String,

        /// Minimum severity to fail (info, low, medium, high, critical)
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Include test files in CI scans
        #[arg(long)]
        include_tests: bool,

        /// Baseline file to filter existing findings in CI
        #[arg(long, value_name = "PATH")]
        baseline: Option<String>,

        /// Disable AgentShield SARIF upload in the generated workflow
        #[arg(long)]
        no_sarif: bool,

        /// Generate a broader security suite with CodeQL, Gitleaks, Semgrep CE, and AgentShield
        #[arg(long)]
        suite: bool,
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
            emit_egress_policy,
            explain,
        } => cmd_scan(ScanArgs {
            path,
            config,
            format_str: format,
            fail_on_str: fail_on,
            output_path: output,
            ignore_tests,
            baseline_path: baseline,
            write_baseline_path: write_baseline,
            emit_egress_policy_path: emit_egress_policy,
            explain,
        }),
        Commands::Quickstart {
            path,
            force,
            fail_on,
            include_tests,
        } => cmd_quickstart(path, force, fail_on, include_tests),
        Commands::Ci { command } => match command {
            CiCommand::Install {
                output,
                force,
                scan_path,
                fail_on,
                include_tests,
                baseline,
                no_sarif,
                suite,
            } => cmd_ci_install(CiInstallRequest {
                output,
                force,
                scan_path,
                fail_on,
                include_tests,
                baseline,
                upload_sarif: !no_sarif,
                suite,
            }),
        },
        Commands::ListRules { format } => cmd_list_rules(format),
        Commands::Init { force } => cmd_init(force),
        Commands::Suppress {
            fingerprint,
            reason,
            expires,
            config,
        } => cmd_suppress(fingerprint, reason, expires, config),
        Commands::ListSuppressions { config } => cmd_list_suppressions(config),
        Commands::Doctor {
            path,
            config,
            json,
            ignore_tests,
        } => cmd_doctor(path, config, json, ignore_tests),
        #[cfg(feature = "runtime-guard")]
        Commands::Guard {
            stdin,
            mcp_proxy,
            config,
            server,
        } => {
            if mcp_proxy {
                if server.is_empty() {
                    cmd_mcp_proxy(config)
                } else {
                    cmd_mcp_proxy_transport(config, server)
                }
            } else {
                cmd_guard(stdin)
            }
        }
        Commands::Certify {
            path,
            sign_key,
            output,
            config,
            ignore_tests,
        } => cmd_certify(path, sign_key, output, config, ignore_tests),
        #[cfg(feature = "runtime")]
        Commands::Wrap {
            policy,
            override_policy,
            audit_log,
            command,
        } => cmd_wrap(policy, override_policy, audit_log, command),
    };

    match result {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(e.exit_code());
        }
    }
}
