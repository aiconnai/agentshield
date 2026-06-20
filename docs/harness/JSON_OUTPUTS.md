# Harness JSON Outputs

This document defines the stable JSON contract for harness scripts that expose a
machine-readable mode. Human output remains the default for every script.

## Global Rules

- JSON output is opt-in. Scripts must keep their existing human output unless a
  JSON flag is explicitly provided.
- JSON mode writes exactly one JSON object to stdout.
- Stderr is reserved for fatal setup or usage errors that prevent JSON
  generation.
- Exit codes must match the equivalent human mode.
- Field names use stable `snake_case`.
- Timestamps use UTC RFC 3339 format.
- Paths are repo-relative unless an absolute path is required to diagnose setup.
- Schema-breaking changes require a new `schema_version`.
- JSON output must never include tokens, cookies, auth headers, private keys,
  raw `.env` contents, complete environment dumps, or unredacted secrets.

## Status Vocabulary

| Status | Exit code | Meaning |
|--------|-----------|---------|
| `pass` | `0` | All required checks passed. |
| `warn` | `0` | Required checks passed, but non-blocking warnings exist. |
| `fail` | non-zero | One or more blocking checks failed. |
| `usage_error` | `2` | Invalid arguments or setup prevented normal validation. |

Existing scripts may document a more specific non-zero exit code, but the JSON
`status` value must still use this vocabulary.

## Common Envelope

Every harness JSON mode must return the common envelope below unless the tool
documents a narrower read-only status command. Tool-specific fields may be added,
but the common fields must keep their meaning across scripts.

```json
{
  "schema_version": "harness-json-v1",
  "tool": "doctor",
  "mode": "json",
  "status": "pass",
  "exit_code": 0,
  "summary": "harness doctor pass",
  "failures": [],
  "failure_count": 0
}
```

Required common fields:

- `schema_version`: stable schema identifier.
- `tool`: harness tool name without path, for example `doctor`.
- `mode`: `json`.
- `status`: one of the status vocabulary values.
- `exit_code`: integer exit code the command will return.
- `summary`: short human-readable summary.
- `failures`: array of failure strings.
- `failure_count`: integer count of failures.

Tool-specific fields should be shallow, stable, and non-secret. Prefer:

- scalar identifiers such as `mode` or `sensor`;
- counts such as `failure_count`;
- short status summaries that use the common status vocabulary.

Avoid:

- raw command logs;
- full reviewer output;
- environment variable dumps;
- request or response bodies that could contain credentials;
- provider headers, cookies, bearer tokens, or API keys;
- absolute local paths unless the command cannot diagnose setup without them.

## `doctor.sh --json`

`doctor.sh --json` validates the same read-only harness invariants as the
default human mode and returns one JSON object using this contract.

Required fields:

- `schema_version`
- `tool`
- `mode`
- `status`
- `exit_code`
- `summary`
- `failures`
- `failure_count`

Compatibility requirements:

- `bash docs/harness/bin/doctor.sh` remains human-readable by default.
- `bash docs/harness/bin/doctor.sh --json` exits `0` on `pass`.
- `bash docs/harness/bin/doctor.sh --json` exits `1` when validation fails.
- `bash docs/harness/bin/doctor.sh --json` exits `2` for usage errors or unknown flags.
- Successful JSON output must be parseable with `python3 -c "import json,sys; json.load(sys.stdin)"`.
- JSON mode must remain read-only and must not create or update harness files.

Example passing output:

```json
{
  "schema_version": "harness-json-v1",
  "tool": "doctor",
  "mode": "json",
  "status": "pass",
  "exit_code": 0,
  "summary": "harness doctor pass",
  "failures": [],
  "failure_count": 0
}
```

Example failing output:

```json
{
  "schema_version": "harness-json-v1",
  "tool": "doctor",
  "mode": "json",
  "status": "fail",
  "exit_code": 1,
  "summary": "harness doctor fail",
  "failures": ["missing file: docs/harness/JSON_OUTPUTS.md"],
  "failure_count": 1
}
```

## `sensors.sh` Modes

AgentShield's `sensors.sh` supports the following modes, which may gain JSON
support in a later task:

- `full` (default, no-arg) — complete local gate: doctor + fmt + clippy + tests + fixture smoke + SARIF + action/release static checks
- `quick` — fast subset: harness checks (doctor + shell syntax) + fmt + cargo check --all-features
- `docs` — harness policy references and current CLI/action/release doc references are present
- `mcp` — MCP validation report references the Anthropic reference servers and records current validation evidence
- `fixtures` — supported fixture scans return success or findings, not scan errors
- `sarif` — SARIF file is emitted and has expected top-level shape
- `action` — composite action keeps expected inputs, SARIF upload, and exit-code behavior
- `release` — release workflow keeps 5 targets, --features full, and wrap smoke checks
- `vscode` — npm ci and npm run compile pass in vscode/
- `baseline` — baseline snapshot writes .baseline-last and doctor passes
- `audit` — evidence-only quarterly audit report is generated and doctor passes

When `sensors.sh` gains a `--json` flag, it must use this same envelope with
`tool` set to `sensors` and `mode` set to the selected lane.

## JSON-Only Output vs Artifacts

Use JSON-only stdout when the complete machine-readable result is small and safe
to keep in process output. Examples:

- `doctor.sh --json`
- read-only status or validation commands

Use `artifacts` when output is large, reviewer-authored, log-like, or useful as
durable evidence. In that case, stdout still contains one JSON object and the
large material is written elsewhere.

## Compatibility Rules

- Human output remains the default.
- JSON flags are opt-in and must not weaken existing gates.
- Exit codes must preserve the existing human-mode meaning.
- `--help` may remain human-readable unless a tool documents a JSON help mode.
- Full gate JSON mode must still run the same checks as the human full gate.

## Non-Goals

- JSON output does not replace human diagnostics.
- JSON output does not embed raw logs, review bodies, environment dumps, or
  secrets.
- JSON output does not require network access.
- JSON output does not mutate repository state.
