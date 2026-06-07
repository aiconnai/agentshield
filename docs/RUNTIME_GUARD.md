# Runtime Guard

## Status

Runtime guard support is experimental roadmap work. AgentShield's stable contract remains offline static scanning and policy evaluation for AI agent extensions before they run.

The current scanner analyzes MCP servers, OpenClaw skills, CrewAI tools, LangChain tools, and related agent extension surfaces, then reports findings through console, JSON, SARIF, and HTML outputs. Runtime guard work should extend that model incrementally; it should not redefine AgentShield as a hosted monitoring service, marketplace, or runtime sandbox.

## Shared policy event model

Runtime guard work should start with one shared JSON event shape that can represent:

- Static scanner findings.
- Runtime guard observations.
- Future MCP proxy guard decisions.

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
be available.

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

MCP proxy guard mode should be a local proxy that observes MCP tool calls and applies policy before tool execution. The design goal is to make tool-call risk visible at the boundary where arguments, tool metadata, and policy can be evaluated together.

The proxy should:

- Observe tool calls without requiring hosted telemetry.
- Redact secrets before logging or structured output.
- Apply the same policy concepts used by static scanning.
- Return explicit allow, warn, or block decisions.
- Preserve static scanner output contracts.

Proxy guard mode should remain experimental until stable configuration, integration tests, failure-mode behavior, and compatibility guarantees are in place.

## Non-goals

- No hosted telemetry requirement.
- No network dependency for local guard decisions.
- No mutation of SARIF output used by GitHub Code Scanning.
- No bypass of existing static scanner policy controls.
