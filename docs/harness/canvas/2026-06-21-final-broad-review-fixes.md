# Review Canvas: final broad review fixes

Date: 2026-06-21
Owner: agent
Scope: Fix two MED findings from the final broad AgentShield harness parity review.

## Trigger

- Trigger matched: final broad review found MED issues in `docs/harness/bin/*`.
- Files expected to change: `docs/harness/bin/check-commit-msg.sh`, `docs/harness/bin/review-gate.sh`, `docs/harness/progress.md`, and this canvas.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Add explicit defensive failure for impossible manual post verdict states | Accepted. It removes the latent fallthrough path without changing normal manual PASS/FAIL behavior. |
| Leave manual post as-is because `write_review` already normalizes verdicts | Rejected. The final review correctly identified this as fragile against future refactors. |
| Reject unknown non-file arguments in `check-commit-msg.sh` | Accepted. It keeps hook path support and prevents typo flags from silently succeeding. |
| Warn but continue on unknown non-file arguments | Rejected. A commit-message gate should fail closed on malformed invocation. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `check-commit-msg.sh` arg parse | O(number of args) unchanged | O(1) | Adds a fail-closed branch for unknown non-file args. |
| `review-gate.sh` manual post verdict parse | O(1) unchanged | O(1) | Adds a defensive `case` fallback only. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Valid manual `--message` still passes | `bash docs/harness/bin/check-commit-msg.sh --message "docs(harness): final broad review fixes"` |
| Unknown typo flag now exits 2 | `bash docs/harness/bin/check-commit-msg.sh --message "docs(harness): final broad review fixes" --typo-flag` |
| Commit hook file path remains accepted | temp `COMMIT_EDITMSG` file with a valid message |
| Manual post-gate PASS still passes | use a temp review artifact with `REVIEW_VERDICT: PASS` and `REVIEWER_CLI=manual` |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| Git hook invocation accidentally depends on ignored non-file args | Commit hook could fail if it passes unexpected args | Git commit-msg hooks pass a single existing file path; file path support is preserved | Revert this commit | Temp `COMMIT_EDITMSG` path test passes. |
| Manual post-gate fallback changes normal PASS/FAIL handling | Could block manual reviews | PASS/FAIL arms are unchanged; only impossible verdict state fails closed | Revert this commit | Manual PASS artifact test passes. |

## Decision

- Proceed / split / block: Proceed.
- Reason: Both fixes are small, fail closed, and directly address final broad-review MED findings.
