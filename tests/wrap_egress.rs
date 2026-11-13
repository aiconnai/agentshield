//! End-to-end tests for `agentshield wrap` and the egress proxy.
//!
//! Everything stays on loopback with ephemeral ports (`127.0.0.1:0`): no
//! external network and no fixed ports. The "upstream" is a throwaway local
//! listener that counts connections, so a test can prove a blocked request
//! never reached it.

#![cfg(feature = "runtime")]

#[cfg(unix)]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentshield::egress::policy::EgressPolicy;
use agentshield::egress::proxy::EgressProxy;
use tempfile::TempDir;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_BODY: &str = "hello-from-upstream";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A local HTTP-ish server that answers every connection and counts them.
struct Upstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Upstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        // Detached: it ends with the test process.
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                answer(stream);
            }
        });
        Self { addr, hits }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn answer(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut buf = [0u8; 2048];
    let _ = stream.read(&mut buf);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{UPSTREAM_BODY}",
        UPSTREAM_BODY.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Build a policy from TOML text through the same loader `wrap` uses.
fn load_policy(toml: &str) -> EgressPolicy {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("egress.toml");
    std::fs::write(&path, toml).unwrap();
    EgressPolicy::load(&path).expect("policy loads")
}

/// Start the proxy for `policy` on an ephemeral loopback port.
async fn start_proxy(policy: EgressPolicy) -> SocketAddr {
    let proxy = Arc::new(EgressProxy::new(policy).expect("proxy starts"));
    let (listener, addr) = proxy.bind().await.expect("bind proxy");
    assert!(addr.ip().is_loopback(), "proxy must bind to loopback only");
    tokio::spawn(async move { proxy.run(listener).await });
    addr
}

/// Send one raw request to the proxy and return everything it sends back.
///
/// Runs on a blocking thread so a small runtime cannot deadlock against the
/// proxy task.
async fn send_raw(proxy: SocketAddr, request: String) -> String {
    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        // A read timeout still leaves what arrived in `response`.
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    })
    .await
    .expect("client thread")
}

/// Open a CONNECT tunnel through the proxy, send a request through it, and
/// return the proxy's reply followed by whatever the upstream answered.
async fn tunnel_through(proxy: SocketAddr, host: &str, port: u16) -> String {
    let connect = connect_request(host, port);
    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.write_all(connect.as_bytes()).unwrap();

        // Read the proxy's reply up to the blank line that ends it.
        let mut reply = Vec::new();
        let mut byte = [0u8; 1];
        while !reply.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => reply.push(byte[0]),
                _ => break,
            }
        }
        if reply.starts_with(b"HTTP/1.1 200") {
            stream.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        }
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        reply.extend(rest);
        String::from_utf8_lossy(&reply).into_owned()
    })
    .await
    .expect("client thread")
}

fn connect_request(host: &str, port: u16) -> String {
    format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
}

fn get_request(host: &str, port: u16) -> String {
    format!("GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
}

/// Same as [`get_request`] but in origin form, so the proxy reads the `Host` header.
fn host_header_request(host: &str, port: u16) -> String {
    format!("GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
}

fn assert_forbidden(response: &str, context: &str) {
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden"),
        "{context}: expected 403, got {response:?}"
    );
    assert!(
        response.contains("\"blocked\":true"),
        "{context}: {response:?}"
    );
}

fn assert_reached_upstream(response: &str, context: &str) {
    assert!(
        response.contains(UPSTREAM_BODY),
        "{context}: expected the upstream body, got {response:?}"
    );
    assert!(
        !response.contains("403 Forbidden"),
        "{context}: {response:?}"
    );
}

const DEFAULT_NETWORK_POLICY: &str = "schema_version = 1\n[domains]\n";

// ---------------------------------------------------------------------------
// Proxy enforcement
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alternate_spellings_of_loopback_are_blocked() {
    let upstream = Upstream::start();
    let proxy = start_proxy(load_policy(DEFAULT_NETWORK_POLICY)).await;

    // IPv4-mapped loopback, the whole 0.0.0.0/8 block, NAT64 loopback and
    // metadata, and IPv4-compatible loopback.
    for host in [
        "[::ffff:127.0.0.1]",
        "0.0.0.0",
        "0.0.0.1",
        "[64:ff9b::7f00:1]",
        "[64:ff9b::a9fe:a9fe]",
        "[::127.0.0.1]",
        "[2002:7f00:1::]",
    ] {
        let port = upstream.port();
        for (form, request) in [
            ("CONNECT", connect_request(host, port)),
            ("absolute-form GET", get_request(host, port)),
            ("Host header GET", host_header_request(host, port)),
        ] {
            let response = send_raw(proxy, request).await;
            assert_forbidden(&response, &format!("{form} to {host}"));
        }
    }
    assert_eq!(
        upstream.hits(),
        0,
        "a blocked request must never reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowed_ip_passes_in_every_spelling_the_policy_covers() {
    let upstream = Upstream::start();
    let proxy = start_proxy(load_policy(
        "schema_version = 1\n[domains]\nallow = [\"127.0.0.1\"]\n[networks]\nblock_localhost = false\n",
    ))
    .await;
    let port = upstream.port();

    let response = send_raw(proxy, get_request("127.0.0.1", port)).await;
    assert_reached_upstream(&response, "plain HTTP to the allowed IP");

    let response = tunnel_through(proxy, "127.0.0.1", port).await;
    assert!(
        response.starts_with("HTTP/1.1 200 Connection Established"),
        "CONNECT to the allowed IP: {response:?}"
    );
    assert_reached_upstream(&response, "CONNECT tunnel to the allowed IP");

    // The same address written as IPv4-mapped IPv6 is the same host.
    let response = send_raw(proxy, get_request("[::ffff:127.0.0.1]", port)).await;
    assert_reached_upstream(&response, "IPv4-mapped spelling of the allowed IP");

    // An address that is not in the allow list is refused by domain rule.
    let response = send_raw(proxy, get_request("127.0.0.2", port)).await;
    assert_forbidden(&response, "unlisted IP");
    assert!(response.contains("domain not allowed"), "{response:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowed_domain_passes_and_other_hosts_are_refused() {
    let upstream = Upstream::start();
    let proxy = start_proxy(load_policy(
        "schema_version = 1\n[domains]\nallow = [\"localhost\"]\n[networks]\nblock_localhost = false\n",
    ))
    .await;
    let port = upstream.port();

    let response = send_raw(proxy, get_request("localhost", port)).await;
    assert_reached_upstream(&response, "plain HTTP to the allowed name");

    let response = tunnel_through(proxy, "localhost", port).await;
    assert_reached_upstream(&response, "CONNECT tunnel to the allowed name");

    // Case and a trailing root dot do not change the host.
    let response = send_raw(proxy, get_request("LocalHost.", port)).await;
    assert_reached_upstream(&response, "respelled allowed name");

    let response = send_raw(proxy, get_request("127.0.0.1", port)).await;
    assert_forbidden(&response, "IP not named in the allow list");

    // Invalid internationalized names fail closed instead of being guessed at.
    let response = send_raw(proxy, get_request("xn--.localhost", port)).await;
    assert_forbidden(&response, "invalid IDNA host");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disjoint_override_merge_blocks_everything() {
    let upstream = Upstream::start();
    let base = load_policy(
        "schema_version = 1\n[domains]\nallow = [\"127.0.0.1\"]\n[networks]\nblock_localhost = false\n",
    );
    let operator = load_policy(
        "schema_version = 1\n[domains]\nallow = [\"localhost\"]\n[networks]\nblock_localhost = false\n",
    );
    let port = upstream.port();

    // Each policy alone would let its own host through.
    let alone = start_proxy(base.clone()).await;
    assert_reached_upstream(
        &send_raw(alone, get_request("127.0.0.1", port)).await,
        "base policy alone",
    );

    // Merged, nothing is allowed: not either host, and not an unrelated one.
    let merged = start_proxy(base.merge_override(&operator)).await;
    for host in ["127.0.0.1", "localhost", "example.com"] {
        let response = send_raw(merged, get_request(host, port)).await;
        assert_forbidden(&response, &format!("merged policy, {host}"));
        assert!(
            response.contains("domain not allowed"),
            "{host}: {response:?}"
        );
    }
    assert_eq!(
        upstream.hits(),
        1,
        "only the base-policy request may reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_override_merge_keeps_only_the_shared_host() {
    let upstream = Upstream::start();
    let base = load_policy(
        "schema_version = 1\n[domains]\nallow = [\"127.0.0.1\", \"localhost\"]\n[networks]\nblock_localhost = false\n",
    );
    let operator = load_policy(
        "schema_version = 1\n[domains]\nallow = [\"localhost\"]\n[networks]\nblock_localhost = true\n",
    );
    let port = upstream.port();

    // The operator re-enables the localhost block, which wins the merge, so
    // even the host both policies allow is refused by the network rule.
    let merged = start_proxy(base.merge_override(&operator)).await;
    let response = send_raw(merged, get_request("localhost", port)).await;
    assert_forbidden(&response, "network block restored by the operator");
    let response = send_raw(merged, get_request("127.0.0.1", port)).await;
    assert_forbidden(&response, "host outside the intersection");
    assert_eq!(upstream.hits(), 0);
}

// ---------------------------------------------------------------------------
// `agentshield wrap` binary
// ---------------------------------------------------------------------------

/// Run `agentshield wrap` around `env` and return the environment the child saw.
#[cfg(unix)]
fn child_environment(inherited: &[(&str, &str)]) -> HashMap<String, String> {
    let dir = TempDir::new().unwrap();
    let policy = dir.path().join("egress.toml");
    std::fs::write(&policy, "schema_version = 1\n[domains]\n").unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_agentshield"));
    command
        .args(["wrap", "--policy"])
        .arg(&policy)
        .args(["--", "env"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, value) in inherited {
        command.env(key, value);
    }
    let output = command.output().expect("run agentshield wrap");
    assert!(
        output.status.success(),
        "wrap exited with {}",
        output.status
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[cfg(unix)]
#[test]
fn wrap_routes_every_proxy_aware_client_through_the_proxy() {
    // Stale values from the operator's shell must not win, and a bypass list
    // must not let the child skip the proxy.
    let env = child_environment(&[
        ("HTTP_PROXY", "http://stale.invalid:1"),
        ("all_proxy", "socks5://stale.invalid:1"),
        ("NO_PROXY", "internal.example,localhost"),
        ("no_proxy", "10.0.0.0/8"),
    ]);

    let proxy_url = env.get("HTTP_PROXY").expect("HTTP_PROXY is set").clone();
    assert!(
        proxy_url.starts_with("http://127.0.0.1:"),
        "unexpected proxy URL {proxy_url}"
    );
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        assert_eq!(
            env.get(name),
            Some(&proxy_url),
            "{name} must point at the proxy"
        );
    }
    assert!(!env.contains_key("NO_PROXY"), "NO_PROXY must be cleared");
    assert!(!env.contains_key("no_proxy"), "no_proxy must be cleared");
}

#[cfg(unix)]
#[test]
fn wrap_refuses_a_policy_with_an_empty_label_pattern() {
    let dir = TempDir::new().unwrap();
    let policy = dir.path().join("egress.toml");
    std::fs::write(&policy, "schema_version = 1\n[domains]\ndeny = [\"*.\"]\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args(["wrap", "--policy"])
        .arg(&policy)
        .args(["--", "env"])
        .output()
        .expect("run agentshield wrap");

    assert!(
        !output.status.success(),
        "an invalid policy must not run the command"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("domains.deny"), "{stderr}");
    assert!(stderr.contains("empty label"), "{stderr}");
}
