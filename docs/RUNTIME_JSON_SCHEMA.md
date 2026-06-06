# Runtime JSON Schema

AgentShield runtime JSON is experimental. It is intended for future runtime guard
and redaction work, and must not change stable scanner JSON, SARIF, HTML, or
console output contracts.

## RuntimeEvent

`RuntimeEvent` describes one observed runtime action.

Required fields:

- `schema_version`: currently `v1`
- `source`: runtime source such as `mcp`, `open_claw`, `crew_ai`, `lang_chain`, `stdin`, or `unknown`
- `action`: observed action such as `tool_call`, `command`, `file_read`, `file_write`, `network_request`, `secret_observed`, or `unknown`
- `arguments`: raw event arguments as JSON
- `redacted`: whether sensitive event data has already been redacted

Optional context fields:

- `tool_name`
- `command`
- `url`
- `path`

## RuntimeGuardResult

`RuntimeGuardResult` describes the decision produced by a runtime guard.

Required fields:

- `schema_version`: currently `v1`
- `verdict`: `allow`, `warn`, or `block`
- `findings`: array of runtime guard findings
- `redacted`: whether sensitive result data has already been redacted

Each finding includes:

- `rule_id`
- `severity`
- `message`
- `evidence`

## Compatibility

Runtime JSON is versioned separately from scanner output. Consumers should check
`schema_version` before interpreting payloads.

The runtime model is experimental and may evolve behind new runtime schema
versions. Changes to this runtime model must not alter the stable scanner JSON,
SARIF, HTML, or console output contracts consumed by users, clients, CI, or
GitHub Code Scanning.
