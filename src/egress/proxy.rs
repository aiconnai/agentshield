//! Minimal HTTP CONNECT proxy for egress policy enforcement.
//!
//! Listens on a random local port, intercepts HTTP CONNECT requests
//! (for HTTPS tunneling) and plain HTTP requests, checks the target
//! host against the loaded [`EgressPolicy`], and either tunnels/forwards
//! or rejects with HTTP 403.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::policy::EgressPolicy;

/// Decision returned by policy evaluation for a single request.
#[derive(Debug, Clone)]
pub enum ProxyDecision {
    Allow,
    BlockedByDomain(String),
    BlockedByNetwork(String),
    BlockedByRateLimit { domain: String, limit: u32 },
}

impl ProxyDecision {
    /// Human-readable reason string for audit logging.
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Allow => None,
            Self::BlockedByDomain(d) => Some(format!("domain not allowed: {}", d)),
            Self::BlockedByNetwork(ip) => Some(format!("blocked IP range: {}", ip)),
            Self::BlockedByRateLimit { domain, limit } => Some(format!(
                "rate limit exceeded for {}: {} req/min",
                domain, limit
            )),
        }
    }

    /// Short label for the decision.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allowed",
            Self::BlockedByDomain(_) => "blocked_domain",
            Self::BlockedByNetwork(_) => "blocked_network",
            Self::BlockedByRateLimit { .. } => "blocked_rate_limit",
        }
    }
}

/// A single audit log entry written as JSON lines.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub host: String,
    pub port: u16,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Per-domain rate tracking window.
#[derive(Debug, Clone)]
struct RateWindow {
    count: u32,
    window_start: Instant,
}

/// Egress proxy that enforces an [`EgressPolicy`] on outbound connections.
///
/// Designed to be started before the child process and shut down after it exits.
pub struct EgressProxy {
    policy: EgressPolicy,
    rate_tracker: Arc<Mutex<HashMap<String, RateWindow>>>,
    audit_writer: Option<Arc<Mutex<std::fs::File>>>,
    log_allowed: bool,
}

impl EgressProxy {
    /// Create a new proxy from the given policy.
    ///
    /// If the policy has an audit log path configured, the file is opened
    /// (append mode) eagerly so errors surface before the child is spawned.
    pub fn new(policy: EgressPolicy) -> Result<Self, crate::error::ShieldError> {
        let audit_writer = if let Some(ref log_path) = policy.audit.log_path {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .map_err(crate::error::ShieldError::Io)?;
            Some(Arc::new(Mutex::new(file)))
        } else {
            None
        };
        let log_allowed = policy.audit.log_allowed;

        Ok(Self {
            policy,
            rate_tracker: Arc::new(Mutex::new(HashMap::new())),
            audit_writer,
            log_allowed,
        })
    }

    /// Bind to a random local port and return `(listener, addr)`.
    pub async fn bind(&self) -> Result<(TcpListener, SocketAddr), crate::error::ShieldError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(crate::error::ShieldError::Io)?;
        let addr = listener
            .local_addr()
            .map_err(crate::error::ShieldError::Io)?;
        Ok((listener, addr))
    }

    /// Accept connections in a loop until the task is cancelled.
    pub async fn run(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        proxy.handle_connection(stream).await;
                    });
                }
                Err(e) => {
                    eprintln!("agentshield proxy: accept error: {}", e);
                }
            }
        }
    }

    /// Handle a single inbound proxy connection.
    async fn handle_connection(&self, mut stream: TcpStream) {
        let mut buf = vec![0u8; 8192];
        let n = match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };

        let request = String::from_utf8_lossy(&buf[..n]);

        if let Some((host, port)) = parse_connect_request(&request) {
            self.handle_connect(stream, &host, port).await;
        } else if let Some((host, port, _path)) = parse_http_request(&request) {
            self.handle_http_forward(stream, &host, port, &buf[..n])
                .await;
        } else {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        }
    }

    /// Handle an HTTP CONNECT tunnel request (used for HTTPS).
    async fn handle_connect(&self, mut client: TcpStream, host: &str, port: u16) {
        let decision = self.check_request(host, port);
        self.write_audit(host, port, &decision);

        match decision {
            ProxyDecision::Allow => {
                // Try to connect to the upstream
                let upstream_addr = format!("{}:{}", host, port);
                match TcpStream::connect(&upstream_addr).await {
                    Ok(mut upstream) => {
                        let _ = client
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        // Bidirectional copy
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                    Err(_) => {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    }
                }
            }
            _ => {
                let body = rejection_body(host, port, &decision);
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = client.write_all(response.as_bytes()).await;
            }
        }
    }

    /// Handle a plain HTTP request by forwarding to the upstream.
    async fn handle_http_forward(
        &self,
        mut client: TcpStream,
        host: &str,
        port: u16,
        original_request: &[u8],
    ) {
        let decision = self.check_request(host, port);
        self.write_audit(host, port, &decision);

        match decision {
            ProxyDecision::Allow => {
                let upstream_addr = format!("{}:{}", host, port);
                match TcpStream::connect(&upstream_addr).await {
                    Ok(mut upstream) => {
                        let _ = upstream.write_all(original_request).await;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                    Err(_) => {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    }
                }
            }
            _ => {
                let body = rejection_body(host, port, &decision);
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = client.write_all(response.as_bytes()).await;
            }
        }
    }

    /// Evaluate the egress policy for a target host:port.
    pub fn check_request(&self, host: &str, port: u16) -> ProxyDecision {
        // Check IP blocking first
        if self.policy.is_ip_blocked(host) {
            return ProxyDecision::BlockedByNetwork(host.to_string());
        }

        // Check domain allow/deny
        if !self.policy.is_domain_allowed(host) {
            return ProxyDecision::BlockedByDomain(host.to_string());
        }

        // Check rate limit
        let limit = self.policy.rate_limit_for(host);
        if limit > 0 {
            let mut tracker = self.rate_tracker.lock();
            let now = Instant::now();
            let window = tracker.entry(host.to_string()).or_insert(RateWindow {
                count: 0,
                window_start: now,
            });

            // Reset window if more than 60 seconds have passed
            if now.duration_since(window.window_start).as_secs() >= 60 {
                *window = RateWindow {
                    count: 1,
                    window_start: now,
                };
            } else {
                window.count += 1;
                if window.count > limit {
                    return ProxyDecision::BlockedByRateLimit {
                        domain: host.to_string(),
                        limit,
                    };
                }
            }
            // Port is informational only for rate limiting; the key is the host.
            let _ = port;
        }

        ProxyDecision::Allow
    }

    /// Write an audit entry to the log file (if configured).
    fn write_audit(&self, host: &str, port: u16, decision: &ProxyDecision) {
        let writer = match &self.audit_writer {
            Some(w) => w,
            None => return,
        };

        // Skip allowed requests unless log_allowed is set
        if matches!(decision, ProxyDecision::Allow) && !self.log_allowed {
            return;
        }

        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            host: host.to_string(),
            port,
            decision: decision.label().to_string(),
            reason: decision.reason(),
        };

        if let Ok(line) = serde_json::to_string(&entry) {
            let mut file = writer.lock();
            let _ = writeln!(file, "{}", line);
        }
    }
}

/// Parse an HTTP CONNECT request, returning `(host, port)`.
fn parse_connect_request(request: &str) -> Option<(String, u16)> {
    let first_line = request.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return None;
    }
    parse_host_port(parts[1])
}

/// Parse a regular HTTP request (GET, POST, etc.), returning `(host, port, path)`.
fn parse_http_request(request: &str) -> Option<(String, u16, String)> {
    let first_line = request.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0];
    // CONNECT is handled separately
    if method == "CONNECT" {
        return None;
    }

    let url_str = parts[1];

    // Absolute URL (http://host:port/path)
    if let Ok(url) = url::Url::parse(url_str) {
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(match url.scheme() {
            "https" => 443,
            _ => 80,
        });
        let path = url.path().to_string();
        return Some((host, port, path));
    }

    // Relative URL — look for Host header
    let host_header = request
        .lines()
        .find(|line| line.to_lowercase().starts_with("host:"))?;
    // "Host: example.com" or "Host: example.com:8080"
    let host_value = host_header.split_once(':')?.1.trim();
    // For Host header values, default port is 80 for plain HTTP
    let (host, port) = if let Some((h, p_str)) = host_value.rsplit_once(':') {
        if let Ok(p) = p_str.parse::<u16>() {
            (h.to_string(), p)
        } else {
            (host_value.to_string(), 80)
        }
    } else {
        (host_value.to_string(), 80)
    };
    Some((host, port, url_str.to_string()))
}

/// Parse `host:port` or just `host` (defaults to port 443 for CONNECT).
fn parse_host_port(addr: &str) -> Option<(String, u16)> {
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str.parse::<u16>().ok()?;
        Some((host.to_string(), port))
    } else {
        Some((addr.to_string(), 443))
    }
}

/// Build a JSON rejection body for a blocked request.
fn rejection_body(host: &str, port: u16, decision: &ProxyDecision) -> String {
    let reason = decision.reason().unwrap_or_default();
    serde_json::json!({
        "blocked": true,
        "host": host,
        "port": port,
        "reason": reason,
        "enforcer": "agentshield"
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::policy::{AuditPolicy, DomainPolicy, NetworkPolicy, RateLimitPolicy};

    fn test_policy() -> EgressPolicy {
        EgressPolicy {
            schema_version: 1,
            domains: DomainPolicy {
                allow: vec!["*.github.com".into(), "api.openai.com".into()],
                deny: vec!["evil.github.com".into()],
            },
            networks: NetworkPolicy::default(),
            rate_limits: RateLimitPolicy {
                max_requests_per_minute: 5,
                per_domain: {
                    let mut m = HashMap::new();
                    m.insert("api.openai.com".into(), 3);
                    m
                },
            },
            audit: AuditPolicy::default(),
        }
    }

    #[test]
    fn test_check_request_domain_allowed() {
        let proxy = EgressProxy::new(test_policy()).unwrap();
        let decision = proxy.check_request("api.github.com", 443);
        assert!(matches!(decision, ProxyDecision::Allow));
    }

    #[test]
    fn test_check_request_domain_blocked() {
        let proxy = EgressProxy::new(test_policy()).unwrap();
        let decision = proxy.check_request("random.org", 443);
        assert!(matches!(decision, ProxyDecision::BlockedByDomain(_)));
    }

    #[test]
    fn test_check_request_denied_domain() {
        let proxy = EgressProxy::new(test_policy()).unwrap();
        let decision = proxy.check_request("evil.github.com", 443);
        // evil.github.com is in the deny list, so domain check should reject it
        assert!(matches!(decision, ProxyDecision::BlockedByDomain(_)));
    }

    #[test]
    fn test_check_request_private_ip_blocked() {
        let proxy = EgressProxy::new(test_policy()).unwrap();

        let decision = proxy.check_request("192.168.1.1", 80);
        assert!(matches!(decision, ProxyDecision::BlockedByNetwork(_)));

        let decision = proxy.check_request("10.0.0.1", 80);
        assert!(matches!(decision, ProxyDecision::BlockedByNetwork(_)));

        let decision = proxy.check_request("127.0.0.1", 80);
        assert!(matches!(decision, ProxyDecision::BlockedByNetwork(_)));

        let decision = proxy.check_request("169.254.169.254", 80);
        assert!(matches!(decision, ProxyDecision::BlockedByNetwork(_)));
    }

    #[test]
    fn test_check_request_rate_limited() {
        let proxy = EgressProxy::new(test_policy()).unwrap();

        // api.openai.com has a limit of 3 per minute
        for _ in 0..3 {
            let d = proxy.check_request("api.openai.com", 443);
            assert!(
                matches!(d, ProxyDecision::Allow),
                "First 3 should be allowed"
            );
        }
        // 4th request should be rate limited
        let d = proxy.check_request("api.openai.com", 443);
        assert!(
            matches!(d, ProxyDecision::BlockedByRateLimit { .. }),
            "4th request should be rate limited"
        );
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: "2026-03-21T12:00:00Z".to_string(),
            host: "api.github.com".to_string(),
            port: 443,
            decision: "allowed".to_string(),
            reason: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("api.github.com"));
        assert!(json.contains("443"));
        assert!(json.contains("allowed"));
        // reason should be absent (skip_serializing_if)
        assert!(!json.contains("reason"));

        let blocked_entry = AuditEntry {
            timestamp: "2026-03-21T12:00:00Z".to_string(),
            host: "evil.com".to_string(),
            port: 80,
            decision: "blocked_domain".to_string(),
            reason: Some("domain not allowed: evil.com".to_string()),
        };
        let json2 = serde_json::to_string(&blocked_entry).unwrap();
        assert!(json2.contains("reason"));
        assert!(json2.contains("domain not allowed"));
    }

    #[test]
    fn test_parse_connect_request() {
        let req = "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let (host, port) = parse_connect_request(req).unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_request_no_port() {
        let req = "CONNECT example.com HTTP/1.1\r\n\r\n";
        let (host, port) = parse_connect_request(req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_http_request_absolute() {
        let req = "GET http://example.com:8080/path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let (host, port, path) = parse_http_request(req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_http_request_relative_with_host_header() {
        let req = "GET /api/v1/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let (host, port, _path) = parse_http_request(req).unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_http_request_connect_returns_none() {
        let req = "CONNECT api.github.com:443 HTTP/1.1\r\n\r\n";
        assert!(parse_http_request(req).is_none());
    }

    #[test]
    fn test_rejection_body() {
        let decision = ProxyDecision::BlockedByDomain("evil.com".to_string());
        let body = rejection_body("evil.com", 443, &decision);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["blocked"], true);
        assert_eq!(parsed["host"], "evil.com");
        assert_eq!(parsed["port"], 443);
        assert_eq!(parsed["enforcer"], "agentshield");
        assert!(parsed["reason"]
            .as_str()
            .unwrap()
            .contains("domain not allowed"));
    }
}
