#[cfg(any(feature = "runtime-guard", feature = "runtime"))]
use std::path::PathBuf;

#[cfg(feature = "runtime-guard")]
use std::io::Read;

#[cfg(feature = "runtime-guard")]
use agentshield::runtime::{
    evaluate_runtime_event, invalid_runtime_guard_input, RuntimeEvent, RuntimeVerdict,
};

#[cfg(feature = "runtime-guard")]
const GUARD_STDIN_MAX_BYTES: usize = 1024 * 1024;

#[cfg(feature = "runtime-guard")]
const GUARD_BLOCK_EXIT: i32 = 3;

#[cfg(feature = "runtime-guard")]
pub(super) fn cmd_guard(read_stdin: bool) -> agentshield::error::Result<i32> {
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
    if emit_guard_result(&result).is_err() {
        return Ok(GUARD_BLOCK_EXIT);
    }

    match verdict {
        RuntimeVerdict::Allow | RuntimeVerdict::Warn => Ok(0),
        RuntimeVerdict::Block => Ok(GUARD_BLOCK_EXIT),
    }
}

#[cfg(feature = "runtime-guard")]
pub(super) fn cmd_mcp_proxy(config_path: Option<PathBuf>) -> agentshield::error::Result<i32> {
    let policy = load_proxy_policy(config_path);
    agentshield::runtime::mcp_proxy_stdio::run_line_mode(
        &policy,
        GUARD_STDIN_MAX_BYTES,
        GUARD_BLOCK_EXIT,
    )
    .map_err(agentshield::error::ShieldError::Io)
}

#[cfg(feature = "runtime-guard")]
pub(super) fn cmd_mcp_proxy_transport(
    config_path: Option<PathBuf>,
    server: Vec<String>,
) -> agentshield::error::Result<i32> {
    let policy = load_proxy_policy(config_path);
    agentshield::runtime::mcp_proxy_stdio::run_transport(
        &policy,
        &server,
        GUARD_STDIN_MAX_BYTES,
        GUARD_BLOCK_EXIT,
    )
    .map_err(agentshield::error::ShieldError::Io)
}

#[cfg(feature = "runtime")]
pub(super) fn cmd_wrap(
    policy_path: PathBuf,
    override_policy_path: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    command: Vec<String>,
) -> Result<i32, agentshield::error::ShieldError> {
    use std::sync::Arc;

    use agentshield::egress::policy::EgressPolicy;
    use agentshield::egress::proxy::EgressProxy;

    if command.is_empty() {
        return Err(agentshield::error::ShieldError::Internal(
            "No command provided to wrap".to_string(),
        ));
    }

    let base = EgressPolicy::load(&policy_path)?;

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

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| agentshield::error::ShieldError::Internal(format!("tokio runtime: {}", e)))?;

    let exit_code = rt.block_on(async {
        let (listener, addr) = proxy.bind().await?;

        let proxy_clone = Arc::clone(&proxy);
        let proxy_handle = tokio::spawn(async move {
            proxy_clone.run(listener).await;
        });

        let proxy_url = format!("http://{}", addr);

        eprintln!("agentshield: proxy listening on {}", addr);
        eprintln!("agentshield: wrapping command: {}", command.join(" "));

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

        proxy_handle.abort();

        Ok::<i32, agentshield::error::ShieldError>(status.code().unwrap_or(1))
    })?;

    std::process::exit(exit_code);
}

#[cfg(feature = "runtime-guard")]
fn load_proxy_policy(config_path: Option<PathBuf>) -> agentshield::runtime::ProxyPolicy {
    use agentshield::config::{Config, ProxyFailOn};
    use agentshield::runtime::{FailOn, ProxyPolicy};

    fn map_fail_on(value: ProxyFailOn) -> FailOn {
        match value {
            ProxyFailOn::Block => FailOn::Block,
            ProxyFailOn::Warn => FailOn::Warn,
            ProxyFailOn::Never => FailOn::Never,
        }
    }

    let path = config_path.unwrap_or_else(|| PathBuf::from(".agentshield.toml"));
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
    let _ = emit_guard_result(&result);
    Ok(GUARD_BLOCK_EXIT)
}
