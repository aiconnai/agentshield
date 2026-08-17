use std::sync::atomic::Ordering;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::types::{AtomicMetrics, HttpSseProxyConfig};
use crate::error::ShieldError;
use crate::runtime::redaction::redact_text;

pub(crate) async fn handle_sse_tunnel<R: AsyncReadExt + Unpin>(
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
