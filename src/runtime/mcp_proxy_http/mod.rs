//! HTTP / SSE MCP proxy guard mode (AGENT-21, milestone v0.9.3).
//!
//! An HTTP reverse-proxy that intercepts MCP JSON-RPC requests over HTTP/SSE,
//! inspecting tool calls (`tools/call`) against runtime policies, blocking
//! unauthorized operations, and sanitizing sensitive secrets from outgoing
//! Server-Sent Event (SSE) streams in real time.

pub(crate) mod forward;
pub(crate) mod server;
pub(crate) mod sse;
pub(crate) mod types;

pub use server::run_http_sse_proxy;
pub use types::{HttpAuditEvent, HttpSseProxyConfig, ProxyMetrics};

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use url::Url;

    use super::server::handle_connection;
    use super::types::{AtomicMetrics, HttpSseProxyConfig};
    use crate::runtime::ProxyPolicy;

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

    #[tokio::test]
    async fn test_payload_too_large() {
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
            .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20000000\r\n\r\n")
            .await
            .unwrap();

        let mut resp = String::new();
        let (read_half, _) = client.split();
        let mut reader = BufReader::new(read_half);
        reader.read_to_string(&mut resp).await.unwrap();

        assert!(resp.contains("HTTP/1.1 413 Payload Too Large"));
    }
}
