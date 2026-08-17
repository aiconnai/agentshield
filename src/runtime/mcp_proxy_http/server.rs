use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::forward::{forward_http_request, log_audit, send_http_response};
use super::sse::handle_sse_tunnel;
use super::types::{AtomicMetrics, HttpSseProxyConfig, MAX_HTTP_BODY_BYTES};
use crate::error::ShieldError;
use crate::runtime::mcp_proxy::{ProxyDecision, decide};

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

    // Read headers
    let mut headers = Vec::new();
    let mut content_length: usize = 0;
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
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            break;
        }

        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().to_lowercase();
            let val = trimmed[colon + 1..].trim();
            if key == "content-length" {
                if let Ok(len) = val.parse::<usize>() {
                    content_length = len;
                }
            } else if key == "accept" && val.contains("text/event-stream") {
                is_sse_request = true;
            }
        }
        headers.push(header_line);
    }

    if content_length > MAX_HTTP_BODY_BYTES {
        return send_http_response(
            &mut client_write,
            413,
            "Payload Too Large",
            "text/plain",
            b"HTTP request body exceeds maximum allowed size (10MB)\n",
        )
        .await;
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

        if let Ok(json_req) = serde_json::from_slice::<Value>(&body) {
            let decision = decide(&json_req, &config.policy);
            match decision {
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

    // Forward any other HTTP requests
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .await
            .map_err(ShieldError::Io)?;
    }
    forward_http_request(
        &config.target_url,
        method,
        path,
        &headers,
        &body,
        &mut client_write,
    )
    .await
}
