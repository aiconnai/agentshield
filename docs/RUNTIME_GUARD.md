# Runtime Guard

## Status

Runtime guard support is experimental. AgentShield's stable contract remains offline static scanning and policy evaluation for AI agent extensions before they run.

The current scanner analyzes MCP servers, OpenClaw skills, CrewAI tools, LangChain tools, and related agent extension surfaces, then reports findings through console, JSON, SARIF, and HTML outputs. Runtime guard work extends that model incrementally; it does not redefine AgentShield as a hosted monitoring service, marketplace, or runtime sandbox.

## Shared policy event model

Runtime guard work uses one shared JSON event shape that can represent:

- Static scanner findings.
- Runtime guard observations.
- MCP proxy guard decisions.

The event model should carry common policy fields such as rule ID, severity, confidence, target, location or runtime context, evidence summary, remediation, and verdict. Static detection and runtime decisions should use the same policy concepts so users do not need separate mental models for scan-time and run-time enforcement.

Events may include sensitive runtime data, including tool arguments, prompts, paths, URLs, headers, or environment-derived values. Secret redaction must run before events are written to logs or structured output.

## Secret redaction

Runtime guard code must redact secrets before writing events or findings to stdout,
stderr, logs, JSON output, future proxy traces, or any other guard output.

Supported categories include OpenAI API keys, GitHub tokens, AWS access key IDs,
AWS secret access key key/value entries and high-confidence standalone AWS secret
access key values, bearer tokens, JWT-like tokens, PEM private key blocks,
basic-auth URL userinfo, Slack tokens, Google API keys, Stripe secret keys, and
generic `api_key`, `apikey`, `token`, `secret`, and `password` key/value
entries.

Runtime JSON event arguments are redacted with object-key context. Values under
secret-like keys such as `secret`, `password`, `passwd`, `pwd`, `token`,
`api_key`, `apikey`, `access_key`, `secret_access_key`,
`aws_secret_access_key`, `private_key`, `credential`, and `auth` are redacted
even when the value itself is not formatted as `key=value`. Matching is
boundary-aware so benign keys such as `secretary`, `tokenize`, `monkey`, and
`keynote` do not cause ordinary values to be redacted.

JSON redaction recursion is depth-bounded so deeply nested attacker-controlled
arguments cannot stack-overflow the process; the remaining subtree is scrubbed
iteratively at the bound, failing closed.

Secret redaction reports include only the secret kind and byte offsets from the
original field value. Reports must never include raw secret text.

## Feature gate

Runtime guard support is behind the opt-in Cargo feature `runtime-guard`. It is
not enabled by default.

Use `cargo run --features runtime-guard -- guard --stdin` during development, or
build/install AgentShield with `--features runtime-guard` if the guard CLI should
be available. Release builds use `--features full`, which includes
`runtime-guard`.

## CLI

`agentshield guard --stdin` reads one `RuntimeEvent` JSON document from stdin and
writes a pretty-printed `RuntimeGuardResult` JSON document to stdout.

Example:

```bash
printf '%s\n' '{"schema_version":"v1","source":"stdin","action":"network_request","tool_name":null,"command":null,"url":"http://169.254.169.254/latest/meta-data/","path":null,"arguments":{},"redacted":false}' | cargo run --features runtime-guard -- guard --stdin
```

The command exits `0` for `allow` and `warn` verdicts, exits `3` for `block`
verdicts, and exits `3` for fail-closed invalid input blocks.

Invalid input includes unsupported invocation, malformed JSON, truncated JSON,
non-UTF-8 stdin, and stdin larger than 1 MiB. These cases emit a synthetic
`RuntimeGuardResult` with `schema_version: "v1"`, `verdict: "block"`, and an
`AGENTSHIELD-RUNTIME-INVALID-INPUT` finding. Raw invalid stdin is never echoed in
the finding evidence.

This runtime guard CLI is experimental and does not alter AgentShield static
scanner output contracts for console, JSON, SARIF, or HTML reports.

## MCP proxy guard mode

MCP proxy guard mode (`agentshield guard --mcp-proxy`) is a local, offline proxy
that sits between an MCP client (the agent host) and an MCP server (the tool
provider). It observes each tool call, evaluates it against runtime policy, and
forwards or blocks it before the underlying server runs. The design
goal is to make tool-call risk visible at the one boundary where arguments, tool
metadata, and policy can be evaluated together — without hosted telemetry.

> Status: experimental implementation. AgentShield 0.8.5 implements the pure
> decision core and a line-delimited stdio JSON-RPC loop. It intentionally reuses
> the existing `guard --stdin` evaluation core (`evaluate_runtime_event`) so the
> proxy reuses, rather than re-implements, policy and redaction.

### Request/response flow

The proxy speaks the MCP JSON-RPC wire protocol on both sides and is transparent
for everything except `tools/call`:

```
agent host ──tools/call──▶ agentshield proxy ──(allow)──▶ MCP server
                                  │                            │
                                  │ evaluate (policy)          │ result
                                  ▼                            ▼
                            allow / warn / block ◀──forward result──
```

1. The current stdio guard loop reads one JSON-RPC message per line. It forwards
   `initialize`, `tools/list`, `resources/*`, `prompts/*`, and any non-call
   traffic by emitting `{"forward": <request>}` for a downstream transport.
2. On a `tools/call` request it pauses forwarding and builds a `RuntimeEvent`
   from the JSON-RPC `params` (`name` → `tool_name`, `arguments` → `arguments`,
   plus any `command`/`url`/`path` extractable from the arguments).
3. It evaluates the event with the shared `evaluate_runtime_event` core, getting
   a `RuntimeGuardResult` (`allow` / `warn` / `block`) and a redacted event.
4. **Allow / warn**: the original (unmodified) request is emitted as
   `{"forward": <request>}`. A downstream transport can consume that marker and
   forward the request to the MCP server.
5. **Block**: the request is NOT forwarded. The proxy synthesizes a JSON-RPC
   error response (see "Safe error response") and returns it to the host as if
   it came from the server. The server never sees the call.

### Tool-call inspection before forwarding

- Inspection happens on the request, before the byte stream reaches the server,
  so a blocked call has zero side effects on the tool provider.
- The proxy only deserializes the `tools/call` envelope; it never executes tool
  logic. Argument values flow through the same `ArgumentSource` taint model and
  the same secret-redaction layer used elsewhere, so what is logged is already
  redacted.
- Inspection is fail-closed: if the `tools/call` params cannot be parsed into a
  `RuntimeEvent`, the call is blocked (not forwarded), mirroring the stdin
  guard's invalid-input handling.

### Allow / warn / block behavior

| Verdict | Forward marker? | Returned to host | Audit |
|---|---|---|---|
| `allow` | yes | downstream transport handles server response | no stderr audit |
| `warn`  | yes | downstream transport handles server response | no stderr audit |
| `block` | no  | synthetic JSON-RPC error | rule id in safe error data |

`warn` deliberately does not alter the response — it surfaces risk without
breaking a working tool. Only `block` changes observable behavior.

The stdio loop exits `3` if any line is blocked. Malformed JSON lines and lines
larger than 1 MiB fail closed with a safe JSON-RPC block error. A
`fail_on = "never"` override forwards the request but writes the suppressed rule
ID to stderr so the suppression remains auditable.

### Proxy policy config format

Proxy policy extends `.agentshield.toml` with a `[runtime.proxy]` section so
static and runtime policy live in one file:

```toml
[runtime.proxy]
# Verdict that causes the call to be blocked. "block" (default) blocks only
# block verdicts; "warn" also blocks warn verdicts (strict mode).
fail_on = "block"

# Per-tool overrides, matched by MCP tool name.
[[runtime.proxy.tool]]
name = "shell.exec"
fail_on = "warn"        # stricter for a dangerous tool

[[runtime.proxy.tool]]
name = "calculator.add"
fail_on = "never"       # never block this tool, still audited
```

Defaults preserve the stdin guard's behavior (block only on `block`). The config
is optional; with no `[runtime.proxy]` section the proxy uses defaults.

### Safe error response for blocked tool calls

A blocked `tools/call` returns a well-formed JSON-RPC error so the host degrades
gracefully instead of hanging or crashing:

```json
{
  "jsonrpc": "2.0",
  "id": "<original request id>",
  "error": {
    "code": -32001,
    "message": "Blocked by AgentShield runtime guard",
    "data": {
      "verdict": "block",
      "rule_id": "AGENTSHIELD-RUNTIME-METADATA-SSRF",
      "schema_version": "v1"
    }
  }
}
```

- The error echoes the original request `id` so the host correlates it.
- `code` uses the JSON-RPC implementation-defined range (`-32000..-32099`);
  `-32001` is reserved here for a guard block.
- `data` carries only the verdict and the blocking rule id — never the raw tool
  arguments, and never an un-redacted secret. It is the `RuntimeGuardResult`
  contract minus any payload.

Proxy guard mode remains experimental until a full bidirectional downstream
transport, broader compatibility testing, and stable runtime compatibility
guarantees are in place.

## Non-goals

- No hosted telemetry requirement.
- No network dependency for local guard decisions.
- No mutation of SARIF output used by GitHub Code Scanning.
- No bypass of existing static scanner policy controls.
