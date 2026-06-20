# Review Canvas: pr-title-policy

Date: 2026-06-20
Owner: Codex
Scope: Add a harness guard that rejects PR titles containing `[codex]`.

## Trigger

- Trigger matched: harness gate, sensor, and review policy change.
- Files expected to change: `docs/harness/bin/pr-title-policy.sh`, `docs/harness/bin/doctor.sh`, `docs/harness/bin/sensors.sh`, harness docs, and this canvas.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Prompt-only instruction | Rejected because it cannot prevent future automation or human error. |
| Dedicated policy script plus doctor/sensor checks | Accepted because it is deterministic, local, and works without GitHub access when a title is supplied. |
| GitHub workflow enforcement | Rejected for this harness change because the harness is intentionally local and workflows must not execute harness scripts. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `pr-title-policy.sh --title` | O(n) in title length | O(n) title buffer | Runs during harness checks with short strings. |
| `pr-title-policy.sh --current-pr` | One `gh pr view` call | O(n) title buffer | Optional; not used by default sensors. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Clean conventional title is accepted | `bash docs/harness/bin/pr-title-policy.sh --title "fix: clean title"` |
| Bracketed Codex marker is rejected | `bash docs/harness/bin/pr-title-policy.sh --title "[codex] fix: bad title"` |
| Mixed-case marker with spaces is rejected | `bash docs/harness/bin/pr-title-policy.sh --title "[ CoDeX ] fix: bad title"` |

## Breakage Risk

| Risk | Impact | Mitigation | Verification |
|---|---|---|---|
| Sensors become network-dependent | Local gates become flaky | Default sensor path uses `--title`, not `--current-pr` | `bash docs/harness/bin/sensors.sh quick` |
| Guard misses casing or spacing variants | Banned marker can reappear | Case-insensitive bracket regex permits internal spacing | Negative title test |
| Harness script change lacks policy coverage | Future drift | Doctor checks script, docs, and sensor references | `bash docs/harness/bin/doctor.sh` |

## Decision

- Proceed / split / block: Proceed.
- Reason: A small deterministic guard is enough to prevent the banned PR title marker without changing product scanner behavior.
