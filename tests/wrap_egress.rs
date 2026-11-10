//! End-to-end tests for `agentshield wrap` and the egress proxy.
//!
//! Everything stays on loopback with ephemeral ports: no external network,
//! no fixed ports.

#![cfg(feature = "runtime")]

use std::collections::HashMap;
use std::process::{Command, Stdio};

use tempfile::TempDir;

const PERMISSIVE_POLICY: &str = "schema_version = 1\n[domains]\nallow = []\ndeny = []\n";

/// Run `agentshield wrap` around `env` and return the environment the child saw.
#[cfg(unix)]
fn child_environment(inherited: &[(&str, &str)]) -> HashMap<String, String> {
    let dir = TempDir::new().unwrap();
    let policy = dir.path().join("egress.toml");
    std::fs::write(&policy, PERMISSIVE_POLICY).unwrap();

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
