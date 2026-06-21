# Review Canvas: A5 doctor drift checks

Date: 2026-06-21
Owner: Codex
Scope: Add conservative drift checks to `doctor.sh` for latest review verdicts and `.sensors-last` format.

## Trigger

- Trigger matched: harness behavior change; `doctor.sh` gains validation checks that can affect pass/fail.
- Files expected to change:
  - `docs/harness/bin/doctor.sh`
  - `docs/harness/canvas/2026-06-21-a5-doctor-drift-checks.md`
  - `docs/harness/progress.md`

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Leave `doctor.sh` minimal | Rejected. It would keep missing drift where review artifacts or sensor snapshots become malformed. |
| Add latest-review-verdict and `.sensors-last` format checks using existing `fail`/`ok` helpers | Accepted. It keeps JSON mode intact, adds only local O(1)-style checks, and matches AgentShield's current artifact formats. |
| Port Engram's full SPEC/sprint/active-plan drift checks | Rejected. AgentShield's harness docs do not define the same sprint fields, so those checks would be false-positive prone. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| Latest review verdict check | One sorted listing of `docs/harness/reviews/*.md` plus one `rg` on the latest artifact | Constant shell variables only | Skips successfully when no review artifact exists. |
| `.sensors-last` format check | One `rg` against a single small snapshot file when present | None beyond process state | Skips successfully when the snapshot is absent. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Review artifact exists | `bash docs/harness/bin/doctor.sh` reports `latest review has parseable REVIEW_VERDICT: ...` and exits 0. |
| No review artifact exists | Code trace: empty `find ... -name '*.md'` makes the check call `ok` and return without `fail`. |
| `.sensors-last` exists with current AgentShield format | `bash docs/harness/bin/doctor.sh` reports `.sensors-last has parseable PASS/FAIL result` and exits 0. |
| `.sensors-last` absent | Code trace: missing file makes the check call `ok` and return without `fail`. |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| Latest review check false-positives on a valid artifact | `doctor.sh` blocks a clean harness | Require only a simple `REVIEW_VERDICT: PASS` or `REVIEW_VERDICT: FAIL` marker and skip when no artifact exists | Revert this commit to remove the new check | Run `bash docs/harness/bin/doctor.sh` and `bash docs/harness/bin/doctor.sh --json`. |
| `.sensors-last` format check rejects current AgentShield snapshots | Quick/full sensors fail after a valid run | Match the current `timestamp mode PASS|FAIL` shape by requiring a standalone `PASS` or `FAIL` token | Revert this commit to restore prior doctor behavior | Run `bash docs/harness/bin/sensors.sh quick`. |

## Decision

- Proceed / split / block: Proceed.
- Reason: The checks are conservative, local, and aligned with AgentShield's current review and sensor artifacts.
