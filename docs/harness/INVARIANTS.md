# Invariants - AgentShield

Rules in this file do not change without explicit owner decision or an approved ADR.

## Invariants of the harness (meta-rule)

- A detector result is considered valid only if a falsifying case exists and is demonstrated in the harness.
- CI and local `sensors` gates must not accept vacuous success:
  - positive fixture expected to contain `SHIELD-xxx` findings;
  - matching negative fixture expected to suppress those findings;
  - the scanner must still produce those findings for real vulnerabilities.
- The harness can be fast-failing only on true violations of gates, not style debates.
- Any change to fixtures, core invariants, or rule matrices requires evidence via `review-gate` and an update to the progress notes when scope or validation changed.

## Falsificability contract (what must hold)

- `cargo test` and rule-level unit tests are mandatory, but not sufficient alone.
- `sensors.sh full` must include one negative-path check for each `SHIELD-xxx` that is currently shipped.
- `--ignore-tests` behavior must be tested as a matrix: same source should differ between default and test-excluded runs.
- `policy.fail-on` must prove both sides:
  - above threshold with a matching finding must fail CI;
  - below threshold with only lower-severity findings must pass.
- `suppressions` and `baseline` must be demonstrated to suppress exactly intended fingerprints only.
- `--silent` or equivalent optimization flags should not alter finding payload shape or severity ordering.

## Matrix: TP / FP by rule (`SHIELD-xxx`)

| Rule | TP fixture (must fire) | FP fixture/control (must not fire) |
|---|---|---|
| SHIELD-001 | `tests/fixtures/mcp_servers/vuln_cmd_inject` (`server.py`), `tests/fixtures/mcp_servers/vuln_ts_cmd_inject` (`server.ts`) | `tests/fixtures/mcp_servers/safe_calculator` |
| SHIELD-002 | `tests/fixtures/mcp_servers/vuln_cred_exfil` | `tests/fixtures/mcp_servers/safe_redacted_logging` |
| SHIELD-003 | `tests/fixtures/mcp_servers/vuln_ssrf`, `tests/fixtures/mcp_servers/vuln_url_parse_ssrf`, `tests/fixtures/mcp_servers/vuln_ts_cmd_inject` | `tests/fixtures/mcp_servers/safe_calculator` |
| SHIELD-004 | `tests/fixtures/mcp_servers/vuln_ts_cmd_inject`, `tests/fixtures/mcp_servers/vuln_read_exfil_chain` | `tests/fixtures/mcp_servers/safe_filesystem` |
| SHIELD-005 | ⚠️ inline unit tests only (runtime command-invocation analysis) | ⚠️ inline unit tests only (`run` fallback path and non-install commands) |
| SHIELD-006 | ⚠️ inline unit tests only (`fixture tests::` in `src/rules/builtin/self_modification.rs`) | ⚠️ inline unit tests only |
| SHIELD-007 | `tests/fixtures/gpt_actions` | `tests/fixtures/mcp_servers/safe_calculator` |
| SHIELD-008 | `tests/fixtures/mcp_servers/vuln_ts_cmd_inject` (`eval`) | `tests/fixtures/mcp_servers/safe_calculator` |
| SHIELD-009 | `tests/fixtures/mcp_servers/vuln_unpinned_deps` | `tests/fixtures/mcp_servers/safe_calculator` |
| SHIELD-010 | ⚠️ inline unit tests only | ⚠️ inline unit tests only |
| SHIELD-011 | `tests/fixtures/mcp_servers/vuln_coercion_eval` | `tests/fixtures/mcp_servers/safe_redacted_logging` |
| SHIELD-012 | `tests/fixtures/mcp_servers/vuln_unpinned_deps` (no lockfile for manifest+deps) | `tests/fixtures/mcp_servers/safe_calculator` (no deps declared) |
| SHIELD-013 | `tests/fixtures/mcp_servers/vuln_metadata_ssrf` | `tests/fixtures/mcp_servers/safe_filesystem` |
| SHIELD-014 | ⚠️ inline unit tests only (`download_exec` rule tests) | ⚠️ inline unit tests only |
| SHIELD-015 | ⚠️ inline unit tests only (`overbroad_fs` rule tests) | ⚠️ inline unit tests only |
| SHIELD-016 | ⚠️ inline unit tests only (`unsafe_deser_tests`) | ⚠️ inline unit tests only |
| SHIELD-017 | ⚠️ inline unit tests only (`archive_traversal` rule tests) | ⚠️ inline unit tests only |
| SHIELD-018 | `tests/fixtures/mcp_servers/vuln_cred_exfil`, `tests/fixtures/mcp_servers/vuln_cred_exfil/index.ts` | `tests/fixtures/mcp_servers/safe_redacted_logging` |
| SHIELD-019 | `tests/fixtures/mcp_servers/vuln_read_exfil_chain` | `tests/fixtures/mcp_servers/safe_calculator`, `tests/fixtures/mcp_servers/safe_filesystem`, `tests/fixtures/mcp_servers/safe_redacted_logging` |
| SHIELD-020 | `tests/fixtures/mcp_servers/vuln_read_exfil_chain` | `tests/fixtures/mcp_servers/safe_filesystem` |

## Required follow-up (for PR2 completion)

- Keep this matrix aligned with the next scan/fixture edits.
- Every new `SHIELD-xxx` must be added to the table before merge.
- If a rule is moved to fixture-backed coverage, update this table and add/adjust `docs/harness/bin/sensors.sh fixtures` checks accordingly.
- Any matrix cell marked ⚠️ must be converted to fixture-backed evidence in a future hardening pass.
