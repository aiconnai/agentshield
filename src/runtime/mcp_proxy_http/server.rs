use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::forward::{forward_http_request, log_audit, send_http_response};
use super::sse::handle_sse_tunnel;
use super::types::{AtomicMetrics, HttpSseProxyConfig, MAX_HTTP_BODY_BYTES};
use crate::error::ShieldError;
use crate::runtime::mcp_proxy::{ProxyDecision, decide};

/// JSON-RPC 2.0 "Parse error" code.
const PARSE_ERROR_CODE: i64 = -32700;

/// Maximum number of HTTP header lines accepted per request.
const MAX_HTTP_HEADERS: usize = 128;

/// Fallback byte cap drained when rejecting requests with unknown or oversized framing.
const REJECT_DRAIN_FALLBACK_BYTES: usize = 64 * 1024;

/// Bounded wait when draining unread client body bytes after half-closing the write side.
const REJECT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// Run the MCP HTTP / SSE proxy server.
pub async fn run_http_sse_proxy(config: HttpSseProxyConfig) -> Result<(), ShieldError> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(ShieldError::Io)?;

    let metrics = Arc::new(AtomicMetrics::new());
    let config = Arc::new(config);

    tracing::info!(
        "MCP HTTP/SSE proxy listening on {} -> target {}",
        config.listen_addr,
        config.target_url
    );

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!("Failed to accept incoming TCP connection: {}", err);
                continue;
            }
        };

        let cfg = Arc::clone(&config);
        let met = Arc::clone(&metrics);

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr, cfg, met).await {
                tracing::debug!("Connection error with {}: {}", peer_addr, err);
            }
        });
    }
}

pub(crate) async fn handle_connection(
    mut client_stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<HttpSseProxyConfig>,
    metrics: Arc<AtomicMetrics>,
) -> Result<(), ShieldError> {
    let (client_read, mut client_write) = client_stream.split();
    let mut reader = BufReader::new(client_read);

    let mut request_line = String::new();
    if reader
        .read_line(&mut request_line)
        .await
        .map_err(ShieldError::Io)?
        == 0
    {
        return Ok(());
    }

    metrics.total_requests.fetch_add(1, Ordering::Relaxed);

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return send_http_response(
            &mut client_write,
            400,
            "Bad Request",
            "text/plain",
            b"Malformed request line\n",
        )
        .await;
    }

    let method = parts[0];
    let path = parts[1];

    // Read and validate HTTP/1.1 headers strictly (RFC 9112 §§5.1, 6.1, 6.3).
    let mut headers = Vec::new();
    let mut parsed_content_length: Option<u64> = None;
    let mut invalid_content_length = false;
    let mut has_transfer_encoding = false;
    let mut invalid_header = false;
    let mut too_many_headers = false;
    let mut is_sse_request = false;

    loop {
        let mut header_line = String::new();
        if reader
            .read_line(&mut header_line)
            .await
            .map_err(ShieldError::Io)?
            == 0
        {
            break;
        }
        let line = header_line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        if headers.len() >= MAX_HTTP_HEADERS {
            too_many_headers = true;
            break;
        }

        let Some((raw_name, raw_val)) = line.split_once(':') else {
            invalid_header = true;
            continue;
        };
        if raw_name.is_empty() || raw_name.bytes().any(|b| b.is_ascii_whitespace()) {
            invalid_header = true;
            continue;
        }

        let key = raw_name.to_ascii_lowercase();
        let val = raw_val.trim();
        if key == "transfer-encoding" {
            has_transfer_encoding = true;
        } else if key == "content-length" {
            match parse_content_length_value(val) {
                Some(len) => {
                    if let Some(prev) = parsed_content_length {
                        if prev != len {
                            invalid_content_length = true;
                        }
                    } else {
                        parsed_content_length = Some(len);
                    }
                }
                None => {
                    invalid_content_length = true;
                }
            }
        } else if key == "accept" && val.to_ascii_lowercase().contains("text/event-stream") {
            is_sse_request = true;
        }
        headers.push(header_line);
    }

    if too_many_headers || invalid_header {
        metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
        log_audit(
            &config.audit_log,
            &peer_addr,
            method,
            path,
            "rejected_malformed_header",
            None,
            None,
        );
        let res = send_http_response(
            &mut client_write,
            400,
            "Bad Request",
            "text/plain",
            b"Malformed HTTP header\n",
        )
        .await;
        drain_request_body(&mut reader, REJECT_DRAIN_FALLBACK_BYTES).await;
        return res;
    }

    if has_transfer_encoding {
        metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
        log_audit(
            &config.audit_log,
            &peer_addr,
            method,
            path,
            "rejected_transfer_encoding",
            None,
            None,
        );
        let res = send_http_response(
            &mut client_write,
            400,
            "Bad Request",
            "text/plain",
            b"Transfer-Encoding is not supported; provide an explicit Content-Length\n",
        )
        .await;
        drain_request_body(&mut reader, REJECT_DRAIN_FALLBACK_BYTES).await;
        return res;
    }

    if invalid_content_length {
        metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
        log_audit(
            &config.audit_log,
            &peer_addr,
            method,
            path,
            "rejected_invalid_content_length",
            None,
            None,
        );
        let res = send_http_response(
            &mut client_write,
            400,
            "Bad Request",
            "text/plain",
            b"Invalid or conflicting Content-Length header\n",
        )
        .await;
        drain_request_body(&mut reader, REJECT_DRAIN_FALLBACK_BYTES).await;
        return res;
    }

    let raw_content_length = parsed_content_length.unwrap_or(0);
    if raw_content_length > MAX_HTTP_BODY_BYTES as u64 {
        let res = send_http_response(
            &mut client_write,
            413,
            "Payload Too Large",
            "text/plain",
            b"HTTP request body exceeds maximum allowed size (10MB)\n",
        )
        .await;
        drain_request_body(&mut reader, REJECT_DRAIN_FALLBACK_BYTES).await;
        return res;
    }
    let content_length = raw_content_length as usize;

    // MCP Streamable HTTP uses GET (SSE), POST (JSON-RPC) and DELETE (session
    // termination), plus HEAD/OPTIONS. Any other method (for instance PUT or
    // PATCH) cannot pass through the JSON-RPC inspector, so reject it before
    // routing and drain any bounded request body so TCP closes with FIN, not RST.
    if method != "POST" {
        if !matches!(method, "GET" | "HEAD" | "DELETE" | "OPTIONS") {
            metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            log_audit(
                &config.audit_log,
                &peer_addr,
                method,
                path,
                "rejected_method",
                None,
                None,
            );
            let res = send_http_response(
                &mut client_write,
                405,
                "Method Not Allowed",
                "text/plain",
                b"Method Not Allowed: MCP proxy only permits GET, POST, HEAD, DELETE, OPTIONS\n",
            )
            .await;
            drain_request_body(&mut reader, content_length).await;
            return res;
        }

        if content_length > 0 {
            metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            log_audit(
                &config.audit_log,
                &peer_addr,
                method,
                path,
                "rejected_unexpected_body",
                None,
                None,
            );
            let res = send_http_response(
                &mut client_write,
                400,
                "Bad Request",
                "text/plain",
                b"Request body is only allowed on POST requests\n",
            )
            .await;
            drain_request_body(&mut reader, content_length).await;
            return res;
        }
    }

    // Handle health endpoint
    if method == "GET" && path == "/health" {
        let resp = json!({
            "status": "ok",
            "proxy": "agentshield-sse",
            "target": config.target_url.to_string()
        });
        let bytes = serde_json::to_vec_pretty(&resp).unwrap_or_default();
        return send_http_response(&mut client_write, 200, "OK", "application/json", &bytes).await;
    }

    // Handle metrics endpoint
    if method == "GET" && path == "/metrics" {
        let snapshot = metrics.snapshot();
        let bytes = serde_json::to_vec_pretty(&snapshot).unwrap_or_default();
        return send_http_response(&mut client_write, 200, "OK", "application/json", &bytes).await;
    }

    // Handle SSE streams
    if method == "GET" && (is_sse_request || path.starts_with("/sse")) {
        metrics
            .active_sse_connections
            .fetch_add(1, Ordering::Relaxed);
        let res = handle_sse_tunnel(reader, client_write, path, &config, &metrics).await;
        metrics
            .active_sse_connections
            .fetch_sub(1, Ordering::Relaxed);
        return res;
    }

    // Handle POST tool call requests
    if method == "POST" {
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader
                .read_exact(&mut body)
                .await
                .map_err(ShieldError::Io)?;
        }

        // Fail closed: a body that is not JSON cannot be inspected, so it is
        // answered with a JSON-RPC parse error instead of being forwarded.
        let Ok(json_req) = serde_json::from_slice::<Value>(&body) else {
            metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            log_audit(
                &config.audit_log,
                &peer_addr,
                method,
                path,
                "rejected_invalid_json",
                None,
                None,
            );
            let resp_body = serde_json::to_vec(&parse_error_response()).unwrap_or_default();
            return send_http_response(
                &mut client_write,
                400,
                "Bad Request",
                "application/json",
                &resp_body,
            )
            .await;
        };

        match decide(&json_req, &config.policy) {
            ProxyDecision::Block(err_val) => {
                metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
                log_audit(
                    &config.audit_log,
                    &peer_addr,
                    method,
                    path,
                    "blocked",
                    None,
                    None,
                );

                // A blocked batch of notifications has no response
                // objects: acknowledge it without a body, as MCP
                // Streamable HTTP does for notifications.
                if matches!(&err_val, Value::Array(items) if items.is_empty()) {
                    return send_http_response(
                        &mut client_write,
                        202,
                        "Accepted",
                        "application/json",
                        b"",
                    )
                    .await;
                }

                let resp_body = serde_json::to_vec(&err_val).unwrap_or_default();
                return send_http_response(
                    &mut client_write,
                    200,
                    "OK",
                    "application/json",
                    &resp_body,
                )
                .await;
            }
            ProxyDecision::Forward => {
                metrics.allowed_requests.fetch_add(1, Ordering::Relaxed);
                log_audit(
                    &config.audit_log,
                    &peer_addr,
                    method,
                    path,
                    "allowed",
                    None,
                    None,
                );
            }
            ProxyDecision::ForwardSuppressed { rule_id } => {
                metrics.allowed_requests.fetch_add(1, Ordering::Relaxed);
                log_audit(
                    &config.audit_log,
                    &peer_addr,
                    method,
                    path,
                    "allowed_suppressed",
                    Some(&rule_id),
                    None,
                );
            }
        }

        // Forward to upstream
        return forward_http_request(
            &config.target_url,
            method,
            path,
            &headers,
            &body,
            &mut client_write,
        )
        .await;
    }

    // Forward bodyless GET/HEAD/DELETE/OPTIONS requests.
    forward_http_request(
        &config.target_url,
        method,
        path,
        &headers,
        &[],
        &mut client_write,
    )
    .await
}

/// Parse an HTTP `Content-Length` field value strictly according to RFC 9112 §6.3.
///
/// Accepts `1*DIGIT` (or a comma-separated list of identical `1*DIGIT` values)
/// and rejects empty tokens, signs (`+`/`-`), non-digits, u64 overflow, and
/// conflicting values.
fn parse_content_length_value(val: &str) -> Option<u64> {
    let mut agreed: Option<u64> = None;
    for part in val.split(',') {
        let token = part.trim();
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let parsed = token.parse::<u64>().ok()?;
        if let Some(prev) = agreed {
            if prev != parsed {
                return None;
            }
        } else {
            agreed = Some(parsed);
        }
    }
    agreed
}

/// Drain up to `max_bytes` from `reader` with a short timeout after sending an
/// error response and half-closing the write side, preventing unread client
/// body bytes in `SO_RCVBUF` from triggering a TCP `RST` (`ECONNRESET`) on close.
async fn drain_request_body<R: AsyncReadExt + Unpin>(reader: &mut R, max_bytes: usize) {
    if max_bytes == 0 {
        return;
    }
    let mut limited = reader.take(max_bytes as u64);
    let _ = tokio::time::timeout(
        REJECT_DRAIN_TIMEOUT,
        tokio::io::copy(&mut limited, &mut tokio::io::sink()),
    )
    .await;
}

/// JSON-RPC 2.0 parse error (`-32700`) returned for a POST body that is not
/// valid JSON.
fn parse_error_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": PARSE_ERROR_CODE,
            "message": "Parse error: request body is not valid JSON",
            "data": {
                "verdict": "block",
                "rule_id": "AGENTSHIELD-RUNTIME-INVALID-INPUT",
                "schema_version": "v1"
            }
        }
    })
}
