use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use super::types::HttpAuditEvent;
use crate::error::ShieldError;

pub(crate) async fn forward_http_request(
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

pub(crate) async fn send_http_response(
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

pub(crate) fn log_audit(
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
