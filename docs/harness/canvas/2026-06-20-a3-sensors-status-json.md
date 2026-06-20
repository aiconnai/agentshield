# Review Canvas: a3-sensors-status-json

Date: 2026-06-20
Owner: Codex (GPT-5)
Scope: Add a read-only `sensors.sh status --json` snapshot of `.sensors-last` using the `harness-json-v1` envelope.

## Trigger

- Trigger matched: harness behavior change (`sensors.sh` gains a `status --json` subcommand) + `JSON_OUTPUTS.md` documentation addition. Per `docs/harness/GATES.md`, changes to `docs/harness/bin/*` require independent post-review evidence and a Review Canvas.
- Files expected to change: `docs/harness/bin/sensors.sh`, `docs/harness/bin/doctor.sh`, `docs/harness/JSON_OUTPUTS.md`, `docs/harness/canvas/2026-06-20-a3-sensors-status-json.md`, `docs/harness/progress.md`.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Parse `.sensors-last` externally in CI or loop callers | Rejected - duplicates harness internals in every caller and makes the text snapshot format a wider implicit API. |
| Add a `status --json` subcommand that reads `.sensors-last`; keep human `status` as the default | Accepted - additive, read-only, O(1), and keeps existing sensor gates unchanged while giving automation a stable `harness-json-v1` object. |
| Make the full sensor gate emit JSON | Rejected - out of scope for A3; full gate output is command-log-like and would need a broader artifact contract. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `sensors.sh status --json` | O(1) read of one snapshot file | O(1) scalar fields | Reads at most one line from `docs/harness/.sensors-last`; no gate rerun and no temp files. |
| Existing sensor modes (`quick`, `full`, etc.) | No change | No change | `status` is intercepted before the existing mode switch; normal lanes still run the same checks and update `.sensors-last` on success. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| After a sensor run, `sensors.sh status --json` emits one JSON object with `status` mapped from `.sensors-last` (`PASS` -> `pass`, `FAIL` -> `fail`) and exits 0 | `bash docs/harness/bin/sensors.sh quick >/dev/null 2>&1` then `bash docs/harness/bin/sensors.sh status --json \| python3 -c "import sys,json; d=json.load(sys.stdin); assert d['tool']=='sensors' and d['status'] in ('pass','warn','fail'); print('STATUS-JSON-OK', d['status'])"` |
| Missing `docs/harness/.sensors-last` still emits valid JSON with `status:"warn"` and exits 0 | Temporarily move `docs/harness/.sensors-last` aside, run `bash docs/harness/bin/sensors.sh status --json`, parse with `python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='warn' and d['exit_code']==0"`, then restore the file. |
| `sensors.sh status` without `--json` prints one human text line and exits 0 | `bash docs/harness/bin/sensors.sh status` |
| Unknown argument after `status` is a usage error; with `--json` present it emits a `usage_error` envelope, otherwise it prints usage to stderr | `bash docs/harness/bin/sensors.sh status --json --bogus` exits 2 with JSON; `bash docs/harness/bin/sensors.sh status --bogus` exits 2 with human usage text. |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| `.sensors-last` format changes and the parser reads fields incorrectly | JSON status could report the wrong `last_timestamp`, `last_mode`, or status mapping | Parser is intentionally limited to the documented `TIMESTAMP MODE PASS|FAIL` order and treats missing/unknown results as `warn` instead of failing | `git revert this commit`; status subcommand is removed and callers stop consuming it | `cat docs/harness/.sensors-last` confirms current order; `status --json` parse check validates `tool` and vocabulary status |
| Reporting a prior `FAIL` as process exit 1 would make polling loops fail even though no gate was run | Automation could treat a read-only status check as a fresh failing gate | Contract documents that `status --json` is read-only and always exits 0 for valid status snapshots; `.sensors-last` result maps only to JSON `status` | Revert the status subcommand or restore exit-code mapping only after updating `JSON_OUTPUTS.md` and consumers | Missing-file and populated-file checks assert `exit_code:0`; code path exits 0 even when result maps to `fail` |
| `--json` support leaks into regular sensor lanes and weakens existing gates | Existing `quick`/`full` callers might skip checks or get different output | Only the `status` subcommand accepts `--json`; normal lanes keep existing argument validation and gate behavior | Remove the status preflight block from `sensors.sh` | `bash docs/harness/bin/sensors.sh quick` still exits 0 and updates `.sensors-last` |
| Doctor drift misses the new subcommand | Harness self-checks could pass even if status support is accidentally removed later | Add a `require_match` for the `status)` token in `docs/harness/bin/sensors.sh` | Revert the doctor check together with the subcommand if the feature is removed | `bash docs/harness/bin/doctor.sh` exits 0 with the new check present |

## Decision

- Proceed / split / block: Proceed.
- Reason: The change is additive and read-only. It exposes an existing one-line snapshot through the existing `harness-json-v1` vocabulary without rerunning the sensor gate or changing normal sensor modes.
