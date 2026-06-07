//! MCP proxy guard mode (AGENT-20, design in docs/RUNTIME_GUARD.md).
//!
//! A local JSON-RPC proxy that sits between an MCP client and server. It is a
//! pass-through for all traffic except `tools/call`, which it evaluates against
//! runtime policy via [`crate::runtime::evaluate_runtime_event`] before
//! forwarding. This module holds the pure, I/O-free decision core; the CLI owns
//! the stdio loop.

use serde_json::{json, Value};

use crate::runtime::{evaluate_runtime_event, RuntimeEvent, RuntimeVerdict};

/// JSON-RPC error code returned for a guard-blocked tool call. Within the
/// implementation-defined range (-32000..-32099).
pub const BLOCKED_ERROR_CODE: i64 = -32001;

/// What the proxy should do with an inbound JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyDecision {
    /// Forward the original request unchanged (pass-through, allow, or warn).
    Forward,
    /// Forward, but a block was suppressed by a `never` override. Carries the
    /// rule id that would have blocked, so the caller can audit it.
    ForwardSuppressed { rule_id: String },
    /// Do not forward; return this JSON-RPC error response to the client.
    Block(Value),
}

/// The blocking threshold for a tool, mirrored from `[runtime.proxy]` config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailOn {
    /// Block only `block` verdicts (default).
    #[default]
    Block,
    /// Block `warn` and `block` verdicts (strict).
    Warn,
    /// Never block; still evaluated/audited.
    Never,
}

/// Proxy policy: a default threshold plus per-tool overrides.
#[derive(Debug, Clone, Default)]
pub struct ProxyPolicy {
    pub fail_on: FailOn,
    /// Per-tool overrides keyed by MCP tool name.
    pub tool_overrides: Vec<(String, FailOn)>,
}

impl ProxyPolicy {
    fn fail_on_for(&self, tool_name: &str) -> FailOn {
        self.tool_overrides
            .iter()
            .find(|(name, _)| name == tool_name)
            .map(|(_, fail_on)| *fail_on)
            .unwrap_or(self.fail_on)
    }
}

/// Decide what to do with one inbound JSON-RPC message.
///
/// Non-`tools/call` messages always [`ProxyDecision::Forward`] (pass-through).
/// A `tools/call` is turned into a [`RuntimeEvent`], evaluated, and either
/// forwarded or blocked per `policy`. Fails closed: a `tools/call` whose params
/// cannot be parsed is blocked.
pub fn decide(request: &Value, policy: &ProxyPolicy) -> ProxyDecision {
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return ProxyDecision::Forward;
    }

    let id = request.get("id").cloned().unwrap_or(Value::Null);

    let event = match tool_call_to_event(request) {
        Some(event) => event,
        // Fail closed: unparseable tools/call params are blocked.
        None => {
            return ProxyDecision::Block(blocked_error(
                &id,
                "block",
                "AGENTSHIELD-RUNTIME-INVALID-INPUT",
            ))
        }
    };

    let tool_name = event.tool_name.clone().unwrap_or_default();
    let result = evaluate_runtime_event(event);
    let fail_on = policy.fail_on_for(&tool_name);

    let rule_id = || {
        result
            .findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .next_back()
            .unwrap_or_else(|| "AGENTSHIELD-RUNTIME-BLOCK".to_string())
    };

    // Would this verdict block if `fail_on` were not `never`?
    let would_block = matches!(result.verdict, RuntimeVerdict::Block)
        || matches!(
            (result.verdict, fail_on),
            (RuntimeVerdict::Warn, FailOn::Warn)
        );

    match (would_block, fail_on) {
        // A `never` override suppresses an otherwise-blocking verdict: forward,
        // but surface the suppressed rule id so the caller can audit it.
        (true, FailOn::Never) => ProxyDecision::ForwardSuppressed { rule_id: rule_id() },
        (true, _) => {
            let verdict = match result.verdict {
                RuntimeVerdict::Block => "block",
                RuntimeVerdict::Warn => "warn",
                RuntimeVerdict::Allow => "allow",
            };
            ProxyDecision::Block(blocked_error(&id, verdict, &rule_id()))
        }
        (false, _) => ProxyDecision::Forward,
    }
}

/// Build a `RuntimeEvent` from a JSON-RPC `tools/call` request. Returns `None`
/// if the params are missing or malformed (caller treats this as fail-closed).
fn tool_call_to_event(request: &Value) -> Option<RuntimeEvent> {
    use crate::runtime::{RuntimeAction, RuntimeEventSource, RuntimeSchemaVersion};

    let params = request.get("params")?;
    let name = params.get("name")?.as_str()?.to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Surface common request-target fields so the SSRF / command checks see them.
    let string_arg = |key: &str| {
        arguments
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
    };

    // The metadata-SSRF check inspects only `url`/`command`. An attacker can
    // hide a metadata endpoint in a nested argument or pass `arguments` as a
    // bare string, which top-level hoisting misses. Walk the whole arguments
    // subtree and, if any string references a metadata endpoint, hoist it into
    // `url` so the guard blocks it. Fail-closed against nested/odd shapes.
    let url = string_arg("url").or_else(|| first_metadata_string(&arguments));

    Some(RuntimeEvent {
        schema_version: RuntimeSchemaVersion::V1,
        source: RuntimeEventSource::Mcp,
        action: RuntimeAction::ToolCall,
        tool_name: Some(name),
        command: string_arg("command"),
        url,
        path: string_arg("path"),
        arguments,
        redacted: false,
    })
}

/// Walk a JSON value (iteratively, so a deeply nested payload cannot overflow
/// the stack) and return the first string that references a cloud metadata
/// endpoint, anywhere in the tree.
fn first_metadata_string(value: &Value) -> Option<String> {
    use crate::rules::builtin::metadata_ssrf::references_metadata_endpoint;

    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::String(text) => {
                if references_metadata_endpoint(text) {
                    return Some(text.clone());
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(entries) => stack.extend(entries.values()),
            _ => {}
        }
    }
    None
}

/// Build the safe JSON-RPC error response for a blocked call. Carries only the
/// verdict and rule id — never the raw arguments or an un-redacted secret.
fn blocked_error(id: &Value, verdict: &str, rule_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": BLOCKED_ERROR_CODE,
            "message": "Blocked by AgentShield runtime guard",
            "data": {
                "verdict": verdict,
                "rule_id": rule_id,
                "schema_version": "v1"
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools_call(name: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        })
    }

    #[test]
    fn non_tool_call_is_passed_through() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        assert_eq!(
            decide(&req, &ProxyPolicy::default()),
            ProxyDecision::Forward
        );
    }

    #[test]
    fn benign_tool_call_is_forwarded() {
        let req = tools_call("calculator.add", json!({"a": 1, "b": 2}));
        assert_eq!(
            decide(&req, &ProxyPolicy::default()),
            ProxyDecision::Forward
        );
    }

    #[test]
    fn metadata_ssrf_tool_call_is_blocked() {
        let req = tools_call(
            "http.get",
            json!({"url": "http://169.254.169.254/latest/meta-data/"}),
        );
        let decision = decide(&req, &ProxyPolicy::default());
        match decision {
            ProxyDecision::Block(err) => {
                assert_eq!(err["error"]["code"], BLOCKED_ERROR_CODE);
                assert_eq!(err["id"], 7); // echoes original id
                assert_eq!(err["error"]["data"]["verdict"], "block");
                assert_eq!(
                    err["error"]["data"]["rule_id"],
                    "AGENTSHIELD-RUNTIME-METADATA-SSRF"
                );
                // Must not leak the raw argument.
                assert!(!err.to_string().contains("169.254.169.254"));
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn malformed_tool_call_fails_closed() {
        // tools/call with no params → blocked.
        let req = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call"});
        match decide(&req, &ProxyPolicy::default()) {
            ProxyDecision::Block(err) => {
                assert_eq!(err["id"], 9);
                assert_eq!(
                    err["error"]["data"]["rule_id"],
                    "AGENTSHIELD-RUNTIME-INVALID-INPUT"
                );
            }
            other => panic!("expected fail-closed block, got {other:?}"),
        }
    }

    #[test]
    fn warn_verdict_forwards_by_default_but_blocks_under_strict_override() {
        // A secret in arguments produces a Warn verdict (not Block).
        let req = tools_call(
            "log.write",
            json!({"token": "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE00"}),
        );

        // Default: warn is forwarded.
        assert_eq!(
            decide(&req, &ProxyPolicy::default()),
            ProxyDecision::Forward
        );

        // Strict per-tool override: warn blocks for this tool.
        let strict = ProxyPolicy {
            fail_on: FailOn::Block,
            tool_overrides: vec![("log.write".to_string(), FailOn::Warn)],
        };
        match decide(&req, &strict) {
            ProxyDecision::Block(err) => assert_eq!(err["error"]["data"]["verdict"], "warn"),
            other => panic!("expected warn-block under strict override, got {other:?}"),
        }
    }

    #[test]
    fn never_override_forwards_but_audits_suppressed_block() {
        let req = tools_call("trusted.fetch", json!({"url": "http://169.254.169.254/"}));
        let policy = ProxyPolicy {
            fail_on: FailOn::Block,
            tool_overrides: vec![("trusted.fetch".to_string(), FailOn::Never)],
        };
        match decide(&req, &policy) {
            ProxyDecision::ForwardSuppressed { rule_id } => {
                assert_eq!(rule_id, "AGENTSHIELD-RUNTIME-METADATA-SSRF");
            }
            other => panic!("expected forward-suppressed, got {other:?}"),
        }
    }

    #[test]
    fn metadata_endpoint_in_nested_argument_is_blocked() {
        // The endpoint is hidden in a nested object, not a top-level url string.
        let req = tools_call(
            "http.get",
            json!({"req": {"target": {"url": "http://169.254.169.254/latest/meta-data/"}}}),
        );
        match decide(&req, &ProxyPolicy::default()) {
            ProxyDecision::Block(err) => {
                assert_eq!(
                    err["error"]["data"]["rule_id"],
                    "AGENTSHIELD-RUNTIME-METADATA-SSRF"
                );
                assert!(!err.to_string().contains("169.254.169.254"));
            }
            other => panic!("expected nested metadata to block, got {other:?}"),
        }
    }

    #[test]
    fn metadata_endpoint_in_string_arguments_is_blocked() {
        // `arguments` is a bare string, not an object — must still block.
        let req = json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "fetch", "arguments": "http://169.254.169.254/" }
        });
        match decide(&req, &ProxyPolicy::default()) {
            ProxyDecision::Block(_) => {}
            other => panic!("expected string-arguments metadata to block, got {other:?}"),
        }
    }

    #[test]
    fn metadata_in_array_argument_is_blocked() {
        let req = tools_call(
            "batch",
            json!({"urls": ["https://ok.example.com", "http://169.254.169.254/"]}),
        );
        match decide(&req, &ProxyPolicy::default()) {
            ProxyDecision::Block(_) => {}
            other => panic!("expected array metadata to block, got {other:?}"),
        }
    }
}
