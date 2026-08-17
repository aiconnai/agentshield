use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use url::Url;

use crate::runtime::ProxyPolicy;

pub(crate) const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Telemetry metrics for the HTTP / SSE proxy.
#[derive(Debug, Default, Serialize)]
pub struct ProxyMetrics {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub redacted_events: u64,
    pub active_sse_connections: u64,
}

pub(crate) struct AtomicMetrics {
    pub(crate) total_requests: AtomicU64,
    pub(crate) allowed_requests: AtomicU64,
    pub(crate) blocked_requests: AtomicU64,
    pub(crate) redacted_events: AtomicU64,
    pub(crate) active_sse_connections: AtomicU64,
}

impl AtomicMetrics {
    pub(crate) fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            allowed_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            redacted_events: AtomicU64::new(0),
            active_sse_connections: AtomicU64::new(0),
        }
    }

    pub(crate) fn snapshot(&self) -> ProxyMetrics {
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
