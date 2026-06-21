# Review Canvas: A6 AGENTS.md reconciliation

Date: 2026-06-21
Owner: Codex
Scope: Reconcile stale `AGENTS.md` project facts with current `CLAUDE.md` without creating a second long-lived source of truth.

## Trigger

- Trigger matched: diff exceeds 200 lines because stale duplicated project-guide content is removed from `AGENTS.md`.
- Files expected to change:
  - `AGENTS.md`
  - `docs/harness/canvas/2026-06-21-a6-agents-md-reconcile.md`
  - `docs/harness/progress.md`

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Fully sync `AGENTS.md` by copying current `CLAUDE.md` project sections | Rejected. It would fix today's drift but preserve the same two-copy maintenance problem. |
| Make `AGENTS.md` a thin pointer to `CLAUDE.md`, keeping only agent-specific Huly and RTK notes | Accepted. It removes stale facts and makes `CLAUDE.md` the canonical project guide. |
| Delete `AGENTS.md` entirely | Rejected. Agents still need repository-scoped guidance and AGENTS-specific Huly/RTK notes. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| Agent instruction loading | No meaningful runtime impact | Smaller `AGENTS.md` payload | Agents read a pointer plus AGENTS-specific notes instead of a stale duplicated project snapshot. |
| Project guide maintenance | Lower future maintenance cost | One canonical long-form project guide | Future project fact changes update `CLAUDE.md` only. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Stale v0.1.0/v0.2.4 facts are removed | `grep -nE "12 detectors|v0\.1\.0|4 adapters" AGENTS.md || echo "no stale version facts"` |
| `AGENTS.md` still points agents to the canonical project guide | `test -f CLAUDE.md && grep -n "Authoritative Project Guide\|CLAUDE.md" AGENTS.md` |
| AGENTS-specific Huly and RTK notes are preserved | `grep -n "Huly Skill\|RTK Usage" AGENTS.md` |
| Harness remains green after docs-only change | `bash docs/harness/bin/doctor.sh` and `bash docs/harness/bin/sensors.sh quick` |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| Agents miss project guidance because they do not follow the pointer | Future agents may have less local context | Put the `CLAUDE.md` pointer at the top and name the covered sections explicitly | Revert this commit to restore the previous duplicated `AGENTS.md` content | Grep for `Authoritative Project Guide` and `CLAUDE.md` in `AGENTS.md`. |
| Removing duplicated sections accidentally drops AGENTS-specific instructions | Huly or RTK workflows regress for agents | Preserve Huly and RTK sections verbatim in the shorter file | Revert this commit or re-add the missing AGENTS-specific section | Grep for `Huly Skill` and `RTK Usage` in `AGENTS.md`. |
| Docs-only reconciliation hides unrelated project changes | Harness parity branch gains scope creep | Modify only `AGENTS.md`, this canvas, and progress evidence | Revert the A6 commits | Inspect `git diff 923d664..HEAD --stat`. |

## Decision

- Proceed / split / block: Proceed.
- Reason: The thin-pointer model fixes the drift root cause while preserving repository-scoped agent instructions.
