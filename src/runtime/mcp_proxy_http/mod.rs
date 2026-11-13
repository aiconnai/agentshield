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

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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

        let mut raw = Vec::new();
        let (read_half, _) = client.split();
        let mut reader = BufReader::new(read_half);
        match reader.read_to_end(&mut raw).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset && !raw.is_empty() => {}
            Err(err) => panic!("reading proxy response failed: {err}"),
        }
        let resp = String::from_utf8_lossy(&raw).into_owned();

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

        let mut raw = Vec::new();
        let (read_half, _) = client.split();
        let mut reader = BufReader::new(read_half);
        match reader.read_to_end(&mut raw).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset && !raw.is_empty() => {}
            Err(err) => panic!("reading proxy response failed: {err}"),
        }
        let resp = String::from_utf8_lossy(&raw).into_owned();

        assert!(resp.contains("HTTP/1.1 413 Payload Too Large"));
    }

    /// Send one HTTP request through a proxy whose upstream records whether it
    /// was contacted. Returns the raw HTTP response and the upstream flag.
    async fn send_through_proxy(method: &str, body: &[u8]) -> (String, bool) {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let contacted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let contacted_flag = Arc::clone(&contacted);
        tokio::spawn(async move {
            if let Ok((stream, _)) = upstream.accept().await {
                contacted_flag.store(true, Ordering::SeqCst);
                let (read_half, mut write_half) = stream.into_split();
                let mut req_reader = BufReader::new(read_half);
                let mut req_content_length: usize = 0;
                loop {
                    let mut line = String::new();
                    match req_reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = trimmed.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    if let Ok(len) = v.trim().parse::<usize>() {
                                        req_content_length = len;
                                    }
                                }
                            }
                        }
                    }
                }
                if req_content_length > 0 {
                    let mut req_body = vec![0u8; req_content_length];
                    let _ = req_reader.read_exact(&mut req_body).await;
                }
                let _ = write_half
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .await;
                let _ = write_half.flush().await;
                let _ = write_half.shutdown().await;
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let config = Arc::new(HttpSseProxyConfig {
            listen_addr,
            target_url: Url::parse(&format!("http://{upstream_addr}")).unwrap(),
            policy: ProxyPolicy::default(),
            audit_log: None,
        });
        let metrics = Arc::new(AtomicMetrics::new());
        tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                let _ = handle_connection(stream, peer, config, metrics).await;
            }
        });

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        let head = if body.is_empty() && method != "POST" {
            format!("{method} /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n")
        } else {
            format!(
                "{method} /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
        };
        client.write_all(head.as_bytes()).await.unwrap();
        if !body.is_empty() {
            client.write_all(body).await.unwrap();
        }

        let mut raw = Vec::new();
        let (read_half, _) = client.split();
        let mut reader = BufReader::new(read_half);
        match reader.read_to_end(&mut raw).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset && !raw.is_empty() => {}
            Err(err) => panic!("reading proxy response failed: {err}"),
        }
        let resp = String::from_utf8_lossy(&raw).into_owned();
        (resp, contacted.load(Ordering::SeqCst))
    }

    async fn post_through_proxy(body: &[u8]) -> (String, bool) {
        send_through_proxy("POST", body).await
    }

    #[tokio::test]
    async fn invalid_json_body_is_rejected_not_forwarded() {
        let (resp, contacted) = post_through_proxy(b"{not json").await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "{resp}");
        assert!(resp.contains("-32700"), "JSON-RPC parse error: {resp}");
        assert!(!contacted, "invalid JSON must not reach the upstream");
    }

    #[tokio::test]
    async fn batch_hiding_blocked_call_is_rejected_not_forwarded() {
        let body = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"http.get","arguments":{"url":"http://169.254.169.254/"}}}]"#;
        let (resp, contacted) = post_through_proxy(body).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("AGENTSHIELD-RUNTIME-METADATA-SSRF"), "{resp}");
        assert!(
            resp.contains("AGENTSHIELD-RUNTIME-BATCH-REJECTED"),
            "{resp}"
        );
        assert!(!contacted, "blocked batch must not reach the upstream");
    }

    #[tokio::test]
    async fn blocked_notification_only_batch_is_accepted_without_body() {
        let body = br#"[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"http.get","arguments":{"url":"http://169.254.169.254/"}}}]"#;
        let (resp, contacted) = post_through_proxy(body).await;
        assert!(resp.starts_with("HTTP/1.1 202 Accepted"), "{resp}");
        assert!(!contacted);
    }

    #[tokio::test]
    async fn valid_benign_request_is_still_forwarded() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let (resp, contacted) = post_through_proxy(body).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(contacted, "benign request must reach the upstream: {resp}");
    }

    #[tokio::test]
    async fn disallowed_http_method_with_body_is_rejected_not_forwarded() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http.get","arguments":{"url":"http://169.254.169.254/"}}}"#;
        let (resp, contacted) = send_through_proxy("PUT", body).await;
        assert!(
            resp.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{resp}"
        );
        assert!(!contacted, "PUT must not bypass inspection to upstream");
    }

    #[tokio::test]
    async fn non_post_method_with_body_is_rejected_and_bodyless_delete_forwards() {
        let (resp, contacted) = send_through_proxy("DELETE", b"{}").await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "{resp}");
        assert!(!contacted, "DELETE with body must not reach upstream");

        let (resp, contacted) = send_through_proxy("DELETE", b"").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(contacted, "bodyless DELETE must forward to upstream");
    }
}
