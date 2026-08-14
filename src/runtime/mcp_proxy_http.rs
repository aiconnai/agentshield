//! HTTP / SSE MCP proxy guard mode (AGENT-21, milestone v0.9.3).
//!
//! An HTTP reverse-proxy that intercepts MCP JSON-RPC requests over HTTP/SSE,
//! inspecting tool calls (`tools/call`) against runtime policies, blocking
//! unauthorized operations, and sanitizing sensitive secrets from outgoing
//! Server-Sent Event (SSE) streams in real time.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::error::ShieldError;
use crate::runtime::ProxyPolicy;
use crate::runtime::mcp_proxy::{ProxyDecision, decide};
use crate::runtime::redaction::redact_text;

/// Telemetry metrics for the HTTP / SSE proxy.
#[derive(Debug, Default, Serialize)]
pub struct ProxyMetrics {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub redacted_events: u64,
    pub active_sse_connections: u64,
}

struct AtomicMetrics {
    total_requests: AtomicU64,
    allowed_requests: AtomicU64,
    blocked_requests: AtomicU64,
    redacted_events: AtomicU64,
    active_sse_connections: AtomicU64,
}

impl AtomicMetrics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            allowed_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            redacted_events: AtomicU64::new(0),
            active_sse_connections: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> ProxyMetrics {
        ProxyMetrics {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            allowed_requests: self.allowed_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            redacted_events: self.redacted_events.load(Ordering::Relaxed),
            active_sse_connections: self.active_sse_connections.load(Ordering::Relaxed),
        }
    }
}

/// Audit event for blocked or allowed MCP HTTP requests.
#[derive(Debug, Serialize)]
pub struct HttpAuditEvent {
    pub timestamp: String,
    pub client_addr: String,
    pub method: String,
    pub path: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

/// Configuration for running the MCP HTTP / SSE proxy.
#[derive(Debug, Clone)]
pub struct HttpSseProxyConfig {
    pub listen_addr: SocketAddr,
    pub target_url: Url,
    pub policy: ProxyPolicy,
    pub audit_log: Option<PathBuf>,
}

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

async fn handle_connection(
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

async fn handle_sse_tunnel<R: AsyncReadExt + Unpin>(
    _client_reader: R,
    mut client_write: tokio::net::tcp::WriteHalf<'_>,
    path: &str,
    config: &HttpSseProxyConfig,
    metrics: &AtomicMetrics,
) -> Result<(), ShieldError> {
    let upstream_host = config.target_url.host_str().unwrap_or("127.0.0.1");
    let upstream_port = config.target_url.port().unwrap_or(80);

    let upstream_addr = format!("{}:{}", upstream_host, upstream_port);
    let mut upstream = TcpStream::connect(&upstream_addr)
        .await
        .map_err(ShieldError::Io)?;

    // Send upstream request
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
        path, upstream_host
    );
    upstream
        .write_all(req.as_bytes())
        .await
        .map_err(ShieldError::Io)?;

    let (upstream_read, _) = upstream.split();
    let mut reader = BufReader::new(upstream_read);

    // Read upstream status line & headers
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.map_err(ShieldError::Io)? == 0 {
            break;
        }
        client_write
            .write_all(line.as_bytes())
            .await
            .map_err(ShieldError::Io)?;
        if line.trim().is_empty() {
            break;
        }
    }
    client_write.flush().await.map_err(ShieldError::Io)?;

    // Stream and sanitize SSE events
    loop {
        line.clear();
        if reader.read_line(&mut line).await.map_err(ShieldError::Io)? == 0 {
            break;
        }

        if let Some(data_payload) = line.strip_prefix("data: ") {
            let report = redact_text(data_payload);
            if !report.redactions.is_empty() {
                metrics
                    .redacted_events
                    .fetch_add(report.redactions.len() as u64, Ordering::Relaxed);
            }
            let sanitized_line = format!("data: {}", report.redacted_text);
            client_write
                .write_all(sanitized_line.as_bytes())
                .await
                .map_err(ShieldError::Io)?;
        } else {
            client_write
                .write_all(line.as_bytes())
                .await
                .map_err(ShieldError::Io)?;
        }

        client_write.flush().await.map_err(ShieldError::Io)?;
    }

    Ok(())
}

async fn forward_http_request(
    target_url: &Url,
    method: &str,
    path: &str,
    headers: &[String],
    body: &[u8],
    client_write: &mut tokio::net::tcp::WriteHalf<'_>,
) -> Result<(), ShieldError> {
    let upstream_host = target_url.host_str().unwrap_or("127.0.0.1");
    let upstream_port = target_url.port().unwrap_or(80);

    let upstream_addr = format!("{}:{}", upstream_host, upstream_port);
    let mut upstream = TcpStream::connect(&upstream_addr)
        .await
        .map_err(ShieldError::Io)?;

    let mut req_header = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, path, upstream_host
    );
    for h in headers {
        let trimmed = h.trim();
        if !trimmed.is_empty()
            && !trimmed.to_lowercase().starts_with("host:")
            && !trimmed.to_lowercase().starts_with("connection:")
        {
            req_header.push_str(trimmed);
            req_header.push_str("\r\n");
        }
    }
    req_header.push_str("\r\n");

    upstream
        .write_all(req_header.as_bytes())
        .await
        .map_err(ShieldError::Io)?;
    if !body.is_empty() {
        upstream.write_all(body).await.map_err(ShieldError::Io)?;
    }
    upstream.flush().await.map_err(ShieldError::Io)?;

    let (mut upstream_read, _) = upstream.split();
    let mut buf = vec![0u8; 8192];
    loop {
        let n = upstream_read
            .read(&mut buf)
            .await
            .map_err(ShieldError::Io)?;
        if n == 0 {
            break;
        }
        client_write
            .write_all(&buf[..n])
            .await
            .map_err(ShieldError::Io)?;
    }
    client_write.flush().await.map_err(ShieldError::Io)?;
    Ok(())
}

async fn send_http_response(
    client_write: &mut tokio::net::tcp::WriteHalf<'_>,
    status_code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), ShieldError> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_code,
        reason,
        content_type,
        body.len()
    );
    client_write
        .write_all(header.as_bytes())
        .await
        .map_err(ShieldError::Io)?;
    if !body.is_empty() {
        client_write
            .write_all(body)
            .await
            .map_err(ShieldError::Io)?;
    }
    client_write.flush().await.map_err(ShieldError::Io)?;
    Ok(())
}

fn log_audit(
    audit_path: &Option<PathBuf>,
    client_addr: &SocketAddr,
    method: &str,
    path: &str,
    decision: &str,
    rule_id: Option<&str>,
    tool_name: Option<&str>,
) {
    if let Some(path_buf) = audit_path {
        let event = HttpAuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_addr: client_addr.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            decision: decision.to_string(),
            rule_id: rule_id.map(String::from),
            tool_name: tool_name.map(String::from),
        };
        if let Ok(json_line) = serde_json::to_string(&event) {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path_buf)
            {
                let _ = writeln!(file, "{}", json_line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_snapshot() {
        let metrics = AtomicMetrics::new();
        metrics.total_requests.fetch_add(5, Ordering::Relaxed);
        metrics.blocked_requests.fetch_add(2, Ordering::Relaxed);
        metrics.redacted_events.fetch_add(1, Ordering::Relaxed);

        let snap = metrics.snapshot();
        assert_eq!(snap.total_requests, 5);
        assert_eq!(snap.blocked_requests, 2);
        assert_eq!(snap.redacted_events, 1);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let config = Arc::new(HttpSseProxyConfig {
            listen_addr,
            target_url: Url::parse("http://127.0.0.1:9999").unwrap(),
            policy: ProxyPolicy::default(),
            audit_log: None,
        });
        let metrics = Arc::new(AtomicMetrics::new());

        let cfg_clone = Arc::clone(&config);
        let met_clone = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                let _ = handle_connection(stream, peer, cfg_clone, met_clone).await;
            }
        });

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut resp = String::new();
        let (read_half, _) = client.split();
        let mut reader = BufReader::new(read_half);
        reader.read_to_string(&mut resp).await.unwrap();

        assert!(resp.contains("HTTP/1.1 200 OK"));
        assert!(resp.contains(r#""status": "ok""#));
        assert!(resp.contains(r#""proxy": "agentshield-sse""#));
    }
}
