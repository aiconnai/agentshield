#[cfg(feature = "runtime-guard")]
use std::io::Read;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use agentshield::baseline::{BaselineEntry, BaselineFile};
use agentshield::config::Config;
use agentshield::doctor::DoctorReport;
use agentshield::egress::policy::EgressPolicy;
#[cfg(feature = "runtime")]
use agentshield::egress::proxy::EgressProxy;
use agentshield::output::OutputFormat;
use agentshield::rules::{RuleEngine, Severity};
#[cfg(feature = "runtime-guard")]
use agentshield::runtime::{
    evaluate_runtime_event, invalid_runtime_guard_input, RuntimeEvent, RuntimeVerdict,
};
use agentshield::ux::{CiInstallOptions, ExplainOptions};
use agentshield::ScanOptions;

#[cfg(feature = "runtime-guard")]
const GUARD_STDIN_MAX_BYTES: usize = 1024 * 1024;

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

        /// Disable SARIF upload in the generated workflow
        #[arg(long)]
        no_sarif: bool,
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
            } => cmd_ci_install(
                output,
                force,
                scan_path,
                fail_on,
                include_tests,
                baseline,
                no_sarif,
            ),
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

#[cfg(feature = "runtime-guard")]
fn cmd_guard(read_stdin: bool) -> agentshield::error::Result<i32> {
    if !read_stdin {
        return emit_invalid_guard_input("unsupported runtime guard invocation", false);
    }

    let mut input = Vec::new();
    let read_result = std::io::stdin()
        .lock()
        .take((GUARD_STDIN_MAX_BYTES + 1) as u64)
        .read_to_end(&mut input);

    if read_result.is_err() {
        return emit_invalid_guard_input("runtime guard stdin read failed", true);
    }

    if input.len() > GUARD_STDIN_MAX_BYTES {
        return emit_invalid_guard_input("runtime guard stdin exceeds 1048576 byte limit", true);
    }

    let input = match String::from_utf8(input) {
        Ok(input) => input,
        Err(_) => return emit_invalid_guard_input("non-UTF-8 runtime guard input", true),
    };

    let event: RuntimeEvent = match serde_json::from_str(&input) {
        Ok(event) => event,
        Err(err) => {
            let reason = match err.classify() {
                serde_json::error::Category::Eof => "truncated JSON runtime guard input",
                serde_json::error::Category::Syntax | serde_json::error::Category::Data => {
                    "malformed JSON runtime guard input"
                }
                serde_json::error::Category::Io => "runtime guard JSON read failed",
            };
            return emit_invalid_guard_input(reason, true);
        }
    };

    let result = evaluate_runtime_event(event);
    let verdict = result.verdict;
    // Emit without `?`: a serialization or broken-pipe error must not propagate
    // to the generic exit code (2) and read as "not blocked". The guard fails
    // closed — any output failure maps to the block code.
    if emit_guard_result(&result).is_err() {
        return Ok(GUARD_BLOCK_EXIT);
    }

    match verdict {
        RuntimeVerdict::Allow | RuntimeVerdict::Warn => Ok(0),
        RuntimeVerdict::Block => Ok(GUARD_BLOCK_EXIT),
    }
}

/// Exit code signalling a fail-closed block from the runtime guard.
#[cfg(feature = "runtime-guard")]
const GUARD_BLOCK_EXIT: i32 = 3;

/// Run the experimental MCP JSON-RPC proxy guard.
///
/// Reads JSON-RPC messages one per line from stdin. Each is evaluated by the
/// shared decision core: `tools/call` requests are checked against
/// `[runtime.proxy]` policy and either forwarded or blocked; everything else
/// passes through. For a forwarded message the proxy emits a `{"forward": ...}`
/// envelope carrying the original request (a downstream MCP server transport
/// would consume this); for a blocked message it emits the JSON-RPC error.
/// Fails closed: a line that is not valid JSON is blocked.
#[cfg(feature = "runtime-guard")]
fn cmd_mcp_proxy(config_path: Option<std::path::PathBuf>) -> agentshield::error::Result<i32> {
    use agentshield::runtime::{decide_tool_call, ProxyDecision};
    use std::io::{BufRead, Write};

    let policy = load_proxy_policy(config_path);
    let mut blocked_any = false;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut reader = stdin.lock();
    let mut raw = Vec::new();
    loop {
        // Read one line with a hard byte cap so a single huge line cannot
        // exhaust memory (mirrors the stdin guard's 1 MiB limit). A line that
        // exceeds the cap is treated as malformed and blocked (fail closed).
        raw.clear();
        let read = (&mut reader)
            .take((GUARD_STDIN_MAX_BYTES + 1) as u64)
            .read_until(b'\n', &mut raw);
        let n = match read {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(_) => break,
        };
        let over_limit = n > GUARD_STDIN_MAX_BYTES;
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches(['\n', '\r']);
        if !over_limit && line.trim().is_empty() {
            continue;
        }

        let parsed = if over_limit {
            // Force the fail-closed branch below without parsing a truncated line.
            Err(())
        } else {
            serde_json::from_str::<serde_json::Value>(line).map_err(|_| ())
        };

        let response = match parsed {
            Ok(request) => {
                match decide_tool_call(&request, &policy) {
                    ProxyDecision::Forward => serde_json::json!({ "forward": request }),
                    ProxyDecision::ForwardSuppressed { rule_id } => {
                        // Audit: a block was suppressed by a `never` override.
                        eprintln!("agentshield: forwarded a {rule_id} block suppressed by a 'never' override");
                        serde_json::json!({ "forward": request })
                    }
                    ProxyDecision::Block(error) => {
                        blocked_any = true;
                        error
                    }
                }
            }
            // Fail closed: an unparseable line is blocked with a synthetic error.
            Err(_) => {
                blocked_any = true;
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": {
                        "code": agentshield::runtime::mcp_proxy::BLOCKED_ERROR_CODE,
                        "message": "Blocked by AgentShield runtime guard",
                        "data": { "verdict": "block", "rule_id": "AGENTSHIELD-RUNTIME-INVALID-INPUT", "schema_version": "v1" }
                    }
                })
            }
        };

        // Best-effort line-delimited output; a write failure ends the loop.
        match serde_json::to_string(&response) {
            Ok(rendered) => {
                if writeln!(out, "{rendered}").is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Non-zero exit if any call was blocked, so a wrapper can detect it.
    Ok(if blocked_any { GUARD_BLOCK_EXIT } else { 0 })
}

/// Build a `ProxyPolicy` from the `[runtime.proxy]` config section.
#[cfg(feature = "runtime-guard")]
fn load_proxy_policy(config_path: Option<std::path::PathBuf>) -> agentshield::runtime::ProxyPolicy {
    use agentshield::config::{Config, ProxyFailOn};
    use agentshield::runtime::{FailOn, ProxyPolicy};

    fn map_fail_on(value: ProxyFailOn) -> FailOn {
        match value {
            ProxyFailOn::Block => FailOn::Block,
            ProxyFailOn::Warn => FailOn::Warn,
            ProxyFailOn::Never => FailOn::Never,
        }
    }

    let path = config_path.unwrap_or_else(|| std::path::PathBuf::from(".agentshield.toml"));
    // A missing/invalid config falls back to defaults (block-on-block).
    let config = Config::load(&path).unwrap_or_default();

    ProxyPolicy {
        fail_on: map_fail_on(config.runtime.proxy.fail_on),
        tool_overrides: config
            .runtime
            .proxy
            .tool_overrides
            .into_iter()
            .map(|override_entry| (override_entry.name, map_fail_on(override_entry.fail_on)))
            .collect(),
    }
}

/// Run the MCP proxy with a real bidirectional stdio bridge to a downstream
/// server. Spawns `server` (argv), forwards pass-through / allowed `tools/call`
/// requests to it and streams its responses back to the client, and answers a
/// blocked `tools/call` itself (the server never sees it).
///
/// Fails closed: if the server cannot be spawned, every call is blocked. A
/// malformed or oversized client line is blocked without forwarding.
#[cfg(feature = "runtime-guard")]
fn cmd_mcp_proxy_transport(
    config_path: Option<std::path::PathBuf>,
    server: Vec<String>,
) -> agentshield::error::Result<i32> {
    use agentshield::runtime::{decide_tool_call, ProxyDecision};
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    use std::thread;

    let policy = load_proxy_policy(config_path);

    let (program, args) = match server.split_first() {
        Some(parts) => parts,
        None => return cmd_mcp_proxy(None), // no command → line mode
    };

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        // Fail closed: cannot spawn the server → block everything.
        Err(_) => {
            eprintln!("agentshield: failed to spawn MCP server; blocking all calls");
            return Ok(GUARD_BLOCK_EXIT);
        }
    };

    let mut server_stdin = child.stdin.take().expect("server stdin piped");
    let server_stdout = child.stdout.take().expect("server stdout piped");

    // Pump the server's stdout straight to the client's stdout (responses).
    // Lock stdout per-line (not for the thread's lifetime) so the main loop can
    // also write block errors without deadlocking on the stdout lock.
    let pump = thread::spawn(move || {
        let mut reader = std::io::BufReader::new(server_stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // server closed
                Ok(_) => {
                    let stdout = std::io::stdout();
                    let mut out = stdout.lock();
                    if out.write_all(line.as_bytes()).is_err() || out.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut blocked_any = false;
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut raw = Vec::new();

    loop {
        raw.clear();
        let n = match (&mut reader)
            .take((GUARD_STDIN_MAX_BYTES + 1) as u64)
            .read_until(b'\n', &mut raw)
        {
            Ok(0) => break, // client EOF
            Ok(n) => n,
            Err(_) => break,
        };
        let over_limit = n > GUARD_STDIN_MAX_BYTES;
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches(['\n', '\r']);
        if !over_limit && line.trim().is_empty() {
            continue;
        }

        let parsed = if over_limit {
            Err(())
        } else {
            serde_json::from_str::<serde_json::Value>(line).map_err(|_| ())
        };

        match parsed {
            Ok(request) => match decide_tool_call(&request, &policy) {
                ProxyDecision::Forward => {
                    // Forward the original request bytes to the server. If the
                    // server is gone, tell the client instead of dropping the
                    // request silently, then stop.
                    if server_stdin.write_all(raw.as_slice()).is_err() {
                        let _ = write_client_line(&downstream_unavailable_error(&request));
                        break;
                    }
                    let _ = server_stdin.flush();
                }
                ProxyDecision::ForwardSuppressed { rule_id } => {
                    eprintln!(
                        "agentshield: forwarded a {rule_id} block suppressed by a 'never' override"
                    );
                    if server_stdin.write_all(raw.as_slice()).is_err() {
                        let _ = write_client_line(&downstream_unavailable_error(&request));
                        break;
                    }
                    let _ = server_stdin.flush();
                }
                ProxyDecision::Block(error) => {
                    // The server never sees a blocked call; the proxy answers.
                    blocked_any = true;
                    if write_client_line(&error).is_err() {
                        break;
                    }
                }
            },
            Err(()) => {
                blocked_any = true;
                let error = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": {
                        "code": agentshield::runtime::mcp_proxy::BLOCKED_ERROR_CODE,
                        "message": "Blocked by AgentShield runtime guard",
                        "data": { "verdict": "block", "rule_id": "AGENTSHIELD-RUNTIME-INVALID-INPUT", "schema_version": "v1" }
                    }
                });
                if write_client_line(&error).is_err() {
                    break;
                }
            }
        }
    }

    // Close the server's stdin so it can finish, then drain its output.
    drop(server_stdin);
    let _ = pump.join();
    let _ = child.wait();

    Ok(if blocked_any { GUARD_BLOCK_EXIT } else { 0 })
}

/// JSON-RPC error returned to the client when the downstream MCP server is no
/// longer writable, so an allowed request is not dropped silently.
#[cfg(feature = "runtime-guard")]
fn downstream_unavailable_error(request: &serde_json::Value) -> serde_json::Value {
    let id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32002,
            "message": "Downstream MCP server unavailable"
        }
    })
}

/// Write one JSON line to the client's stdout. Returns Err on a write failure.
#[cfg(feature = "runtime-guard")]
fn write_client_line(value: &serde_json::Value) -> std::io::Result<()> {
    use std::io::Write;
    let rendered = serde_json::to_string(value).map_err(std::io::Error::other)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{rendered}")?;
    out.flush()
}

/// Serialize and print a guard result. Returns Err only on a serialization or
/// stdout-write failure, which the caller maps to a fail-closed block.
#[cfg(feature = "runtime-guard")]
fn emit_guard_result(
    result: &agentshield::runtime::RuntimeGuardResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let rendered = serde_json::to_string_pretty(result)?;
    use std::io::Write;
    writeln!(std::io::stdout(), "{rendered}")?;
    Ok(())
}

#[cfg(feature = "runtime-guard")]
fn emit_invalid_guard_input(reason: &str, redacted: bool) -> agentshield::error::Result<i32> {
    let result = invalid_runtime_guard_input(reason, redacted);
    // Ignore output errors: the verdict is already block, and a write failure
    // must not downgrade the exit code away from the fail-closed block.
    let _ = emit_guard_result(&result);
    Ok(GUARD_BLOCK_EXIT)
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
    emit_egress_policy_path: Option<PathBuf>,
    explain: bool,
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
        emit_egress_policy_path,
        explain,
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

    let fail_on = parse_optional_severity(fail_on_str.as_deref());
    let effective_ignore_tests = effective_ignore_tests(&path, config.as_ref(), ignore_tests)?;

    let options = ScanOptions {
        config_path: config.clone(),
        format,
        fail_on_override: fail_on,
        ignore_tests,
    };

    let mut report = match agentshield::scan(&path, &options) {
        Ok(report) => report,
        Err(err) if explain && agentshield::ux::is_no_adapter(&err) => {
            let rendered =
                agentshield::ux::render_no_adapter_explain(&path, effective_ignore_tests);
            write_rendered(output_path.as_ref(), &rendered)?;
            return Ok(2);
        }
        Err(err) => return Err(err),
    };

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

    // Emit egress policy if --emit-egress-policy is provided
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
    } else {
        agentshield::render_report(&report, format)?
    };

    write_rendered(output_path.as_ref(), &rendered)?;

    // Exit code: 0 = pass, 1 = findings above threshold
    Ok(if report.verdict.pass { 0 } else { 1 })
}

fn cmd_quickstart(
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
                agentshield::ux::render_no_adapter_explain(&path, ignore_tests)
            );
            Ok(0)
        }
        Err(err) => Err(err),
    }
}

fn cmd_ci_install(
    output: PathBuf,
    force: bool,
    scan_path: String,
    fail_on_str: String,
    include_tests: bool,
    baseline: Option<String>,
    no_sarif: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    let fail_on = require_severity(&fail_on_str)?;
    let fail_on = fail_on.to_string();

    if output.exists() && !force {
        eprintln!(
            "{} already exists. Use --force to overwrite.",
            output.display()
        );
        return Ok(1);
    }

    if let Some(parent) = non_empty_parent(&output) {
        std::fs::create_dir_all(parent)?;
    }

    let workflow = agentshield::ux::github_actions_workflow(&CiInstallOptions {
        fail_on: &fail_on,
        ignore_tests: !include_tests,
        scan_path: &scan_path,
        baseline_path: baseline.as_deref(),
        upload_sarif: !no_sarif,
    });
    std::fs::write(&output, workflow)?;
    println!("Created {}", output.display());
    println!("CI gate: scans `{scan_path}` and fails on `{fail_on}` findings or higher.");
    if !no_sarif {
        println!("SARIF upload: enabled for GitHub Code Scanning.");
    }
    if let Some(baseline) = baseline {
        println!("Baseline: filters known findings from `{baseline}`.");
    }
    Ok(0)
}

fn parse_optional_severity(value: Option<&str>) -> Option<Severity> {
    value.and_then(|s| {
        let sev = Severity::from_str_lenient(s);
        if sev.is_none() {
            eprintln!("Warning: unknown severity '{}', using config default", s);
        }
        sev
    })
}

fn require_severity(value: &str) -> Result<Severity, agentshield::error::ShieldError> {
    Severity::from_str_lenient(value).ok_or_else(|| {
        agentshield::error::ShieldError::Config(format!(
            "unknown severity '{value}' (expected info, low, medium, high, or critical)"
        ))
    })
}

fn effective_ignore_tests(
    path: &std::path::Path,
    config_path: Option<&PathBuf>,
    cli_ignore_tests: bool,
) -> Result<bool, agentshield::error::ShieldError> {
    let resolved_config_path = config_path
        .cloned()
        .unwrap_or_else(|| path.join(".agentshield.toml"));
    let config = Config::load(&resolved_config_path)?;
    Ok(cli_ignore_tests || config.scan.ignore_tests)
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

fn cmd_doctor(
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

fn cmd_list_suppressions(config: Option<PathBuf>) -> Result<i32, agentshield::error::ShieldError> {
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

fn cmd_certify(
    path: PathBuf,
    sign_key: Option<PathBuf>,
    output: Option<PathBuf>,
    config: Option<PathBuf>,
    ignore_tests: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    use agentshield::certify::envelope::{build_attestation, DsseEnvelope};

    let options = ScanOptions {
        config_path: config.clone(),
        format: OutputFormat::Console,
        fail_on_override: None,
        ignore_tests,
    };

    let report = agentshield::scan(&path, &options)?;

    // Load suppressions from config
    let config_path = config.unwrap_or_else(|| path.join(".agentshield.toml"));
    let cfg = Config::load(&config_path)?;
    let suppressions = &cfg.policy.suppressions;

    let payload = build_attestation(
        &report.scan_root,
        &report.findings,
        suppressions,
        &report.targets,
        None,
    );

    let mut envelope = DsseEnvelope::new(&payload)?;

    // Optionally sign with Ed25519 key
    if let Some(key_path) = sign_key {
        let key_bytes = std::fs::read(&key_path).map_err(|e| {
            agentshield::error::ShieldError::Internal(format!(
                "Failed to read signing key '{}': {}",
                key_path.display(),
                e
            ))
        })?;
        envelope.sign(&key_bytes)?;
        eprintln!("Signed attestation with key: {}", key_path.display());
    }

    let json = serde_json::to_string_pretty(&envelope)?;

    match output {
        Some(out) => {
            std::fs::write(&out, &json)?;
            eprintln!(
                "Wrote attestation to: {} ({} findings)",
                out.display(),
                report.findings.len()
            );
        }
        None => print!("{}", json),
    }

    Ok(0)
}

#[cfg(feature = "runtime")]
fn cmd_wrap(
    policy_path: PathBuf,
    override_policy_path: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    command: Vec<String>,
) -> Result<i32, agentshield::error::ShieldError> {
    use std::sync::Arc;

    if command.is_empty() {
        return Err(agentshield::error::ShieldError::Internal(
            "No command provided to wrap".to_string(),
        ));
    }

    let base = EgressPolicy::load(&policy_path)?;

    // Apply operator override (restricts, never expands)
    let mut policy = if let Some(ref override_path) = override_policy_path {
        let operator = EgressPolicy::load(override_path).map_err(|e| {
            agentshield::error::ShieldError::Internal(format!(
                "Failed to load override policy '{}': {}",
                override_path.display(),
                e
            ))
        })?;
        eprintln!(
            "agentshield: applying operator override policy: {}",
            override_path.display()
        );
        base.merge_override(&operator)
    } else {
        base
    };

    if let Some(log_path) = audit_log {
        policy.audit.log_path = Some(log_path);
    }

    let proxy = Arc::new(EgressProxy::new(policy)?);

    // Build a tokio runtime to run the proxy
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| agentshield::error::ShieldError::Internal(format!("tokio runtime: {}", e)))?;

    let exit_code = rt.block_on(async {
        let (listener, addr) = proxy.bind().await?;

        // Spawn proxy loop in background
        let proxy_clone = Arc::clone(&proxy);
        let proxy_handle = tokio::spawn(async move {
            proxy_clone.run(listener).await;
        });

        let proxy_url = format!("http://{}", addr);

        eprintln!("agentshield: proxy listening on {}", addr);
        eprintln!("agentshield: wrapping command: {}", command.join(" "));

        // Launch child process with proxy env vars
        let mut child = std::process::Command::new(&command[0])
            .args(&command[1..])
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .spawn()
            .map_err(|e| {
                agentshield::error::ShieldError::Internal(format!(
                    "Failed to start command '{}': {}",
                    command[0], e
                ))
            })?;

        let status = child.wait().map_err(|e| {
            agentshield::error::ShieldError::Internal(format!("Failed to wait for command: {}", e))
        })?;

        // Shutdown proxy
        proxy_handle.abort();

        Ok::<i32, agentshield::error::ShieldError>(status.code().unwrap_or(1))
    })?;

    process::exit(exit_code);
}
