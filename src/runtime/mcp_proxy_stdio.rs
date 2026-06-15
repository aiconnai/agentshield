use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::runtime::mcp_proxy::{self, decide, ProxyDecision};
use crate::runtime::ProxyPolicy;

const DOWNSTREAM_UNAVAILABLE_ERROR_CODE: i64 = -32002;
const DOWNSTREAM_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

enum ReadLine {
    Eof,
    Empty,
    Parsed(Result<Value, ()>),
}

pub fn run_line_mode(
    policy: &ProxyPolicy,
    max_line_bytes: usize,
    block_exit_code: i32,
) -> std::io::Result<i32> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut blocked_any = false;
    let mut raw = Vec::new();

    loop {
        raw.clear();
        let parsed = match read_json_line(&mut reader, &mut raw, max_line_bytes)? {
            ReadLine::Eof => break,
            ReadLine::Empty => continue,
            ReadLine::Parsed(parsed) => parsed,
        };
        let response = match parsed {
            Ok(request) => match decide(&request, policy) {
                ProxyDecision::Forward => serde_json::json!({ "forward": request }),
                ProxyDecision::ForwardSuppressed { rule_id } => {
                    eprintln!(
                        "agentshield: forwarded a {rule_id} block suppressed by a 'never' override"
                    );
                    serde_json::json!({ "forward": request })
                }
                ProxyDecision::Block(error) => {
                    blocked_any = true;
                    error
                }
            },
            Err(()) => {
                blocked_any = true;
                invalid_input_error()
            }
        };

        write_json_line_to(&mut out, &response)?;
    }

    Ok(if blocked_any { block_exit_code } else { 0 })
}

pub fn run_transport(
    policy: &ProxyPolicy,
    server: &[String],
    max_line_bytes: usize,
    block_exit_code: i32,
) -> std::io::Result<i32> {
    let Some((program, args)) = server.split_first() else {
        return run_line_mode(policy, max_line_bytes, block_exit_code);
    };

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            eprintln!("agentshield: failed to spawn MCP server; blocking all calls");
            return Ok(block_exit_code);
        }
    };

    let Some(mut server_stdin) = child.stdin.take() else {
        eprintln!("agentshield: MCP server stdin unavailable; blocking all calls");
        return Ok(block_exit_code);
    };
    let Some(server_stdout) = child.stdout.take() else {
        eprintln!("agentshield: MCP server stdout unavailable; blocking all calls");
        return Ok(block_exit_code);
    };

    let pump = spawn_stdout_pump(server_stdout);
    let mut blocked_any = false;
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut raw = Vec::new();

    loop {
        raw.clear();
        let parsed = match read_json_line(&mut reader, &mut raw, max_line_bytes)? {
            ReadLine::Eof => break,
            ReadLine::Empty => continue,
            ReadLine::Parsed(parsed) => parsed,
        };

        match parsed {
            Ok(request) => match decide(&request, policy) {
                ProxyDecision::Forward => {
                    if forward_to_server(&mut server_stdin, &raw, &request)? {
                        break;
                    }
                }
                ProxyDecision::ForwardSuppressed { rule_id } => {
                    eprintln!(
                        "agentshield: forwarded a {rule_id} block suppressed by a 'never' override"
                    );
                    if forward_to_server(&mut server_stdin, &raw, &request)? {
                        break;
                    }
                }
                ProxyDecision::Block(error) => {
                    blocked_any = true;
                    write_client_line(&error)?;
                }
            },
            Err(()) => {
                blocked_any = true;
                write_client_line(&invalid_input_error())?;
            }
        }
    }

    drop(server_stdin);
    let status = wait_for_child(&mut child, DOWNSTREAM_EXIT_TIMEOUT, block_exit_code)?;
    let _ = pump.join();

    if blocked_any {
        Ok(block_exit_code)
    } else {
        Ok(status)
    }
}

fn read_json_line<R: BufRead>(
    reader: &mut R,
    raw: &mut Vec<u8>,
    max_line_bytes: usize,
) -> std::io::Result<ReadLine> {
    let n = reader
        .by_ref()
        .take((max_line_bytes + 1) as u64)
        .read_until(b'\n', raw)?;
    if n == 0 {
        return Ok(ReadLine::Eof);
    }
    let over_limit = n > max_line_bytes;
    let line = String::from_utf8_lossy(raw);
    let line = line.trim_end_matches(['\n', '\r']);
    if !over_limit && line.trim().is_empty() {
        return Ok(ReadLine::Empty);
    }
    let parsed = if over_limit {
        Err(())
    } else {
        serde_json::from_str::<Value>(line).map_err(|_| ())
    };
    Ok(ReadLine::Parsed(parsed))
}

fn spawn_stdout_pump<R>(server_stdout: R) -> thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = std::io::BufReader::new(server_stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
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
    })
}

fn forward_to_server(
    server_stdin: &mut impl Write,
    raw: &[u8],
    request: &Value,
) -> std::io::Result<bool> {
    if server_stdin.write_all(raw).is_err() {
        write_client_line(&downstream_unavailable_error(request))?;
        return Ok(true);
    }
    let _ = server_stdin.flush();
    Ok(false)
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
    block_exit_code: i32,
) -> std::io::Result<i32> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.code().unwrap_or(block_exit_code));
        }
        if started.elapsed() >= timeout {
            eprintln!("agentshield: downstream MCP server did not exit before timeout; killing it");
            let _ = child.kill();
            let _ = child.wait();
            return Ok(block_exit_code);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn invalid_input_error() -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": mcp_proxy::BLOCKED_ERROR_CODE,
            "message": "Blocked by AgentShield runtime guard",
            "data": {
                "verdict": "block",
                "rule_id": "AGENTSHIELD-RUNTIME-INVALID-INPUT",
                "schema_version": "v1"
            }
        }
    })
}

fn downstream_unavailable_error(request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": DOWNSTREAM_UNAVAILABLE_ERROR_CODE,
            "message": "Downstream MCP server unavailable"
        }
    })
}

fn write_client_line(value: &Value) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    write_json_line_to(&mut out, value)
}

fn write_json_line_to(out: &mut impl Write, value: &Value) -> std::io::Result<()> {
    let rendered = serde_json::to_string(value).map_err(std::io::Error::other)?;
    writeln!(out, "{rendered}")?;
    out.flush()
}
