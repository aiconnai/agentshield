# Review Canvas: review-gate-stdin-hotfix

Date: 2026-06-20
Owner: Claude (Opus 4.8) + Codex (independent reviewer)
Scope: Change the codex reviewer invocation in `review-gate.sh` from a positional argument to stdin so the post-gate stops returning empty output on codex-cli 0.140.0.

## Trigger

- Trigger matched: harness behavior change (how `review-gate.sh` invokes the reviewer CLI). Done early as the unblocking prerequisite of Task A4 due to a circular dependency — the post-gate was broken and could not gate any harness change, including its own fix.
- Files expected to change: `docs/harness/bin/review-gate.sh` (the `run_reviewer()` codex branch), this canvas.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Keep `codex exec "$prompt"` (positional) | Rejected — codex-cli 0.140.0 intermittently treats a large positional prompt as "Reading additional input from stdin..." and exits 0 with empty output, so the gate writes no artifact. |
| `printf '%s' "$prompt" \| codex exec` (stdin) | Accepted — matches the codex-cli stdin contract used for `resume`, deterministic, `printf %s` passes the prompt verbatim including `%`, backslashes, quotes. Minimal (1 line). |
| Add a retry-on-empty loop around the reviewer now | Rejected for this hotfix — broader behavior change; belongs to the A4 gate-hardening task. |
| Migrate to a here-doc / temp prompt file | Rejected — reintroduces tempfile dependency (the exact class of fragility fixed in A2) and is larger than needed. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `run_reviewer` codex branch | none (one extra `printf` + pipe) | none | Reviewer call already dominates wall-clock; the pipe is negligible. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Script still parses | `bash -n docs/harness/bin/review-gate.sh` (exit 0) |
| Prompt with shell metacharacters passed verbatim | `printf '%s' "$prompt"` uses `%s` so `%`, `\`, `"`, `$` in the prompt are data, not format/positional args |
| Non-codex reviewer branch unchanged | `REVIEWER_CLI=manual` still hits the `"$REVIEWER_CLI" "$prompt"` branch (untouched in the diff) |
| Post-gate now emits an artifact | running `review-gate.sh post a2-json-outputs --range=d499be1..HEAD` produced `docs/harness/reviews/2026-06-20-a2-json-outputs-post-codex.md` (it did not before the fix) |
| doctor still consistent | `bash docs/harness/bin/doctor.sh` (exit 0) |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| Stdin form breaks on a future codex-cli that wants positional | Gate returns empty again | Comment in code documents the 0.140.0 reason; A4 will add retry-on-empty | `git revert e6e4002` (restores positional `codex exec "$prompt"`) | `bash -n` + a live `post` run that produces an artifact |
| `printf` mangles a prompt with format-like content | Reviewer sees wrong prompt | `printf '%s'` treats the prompt purely as data | Revert to positional, or switch to `printf '%s\n'` | Inspect a generated `*-post-codex.md.raw` prompt echo |
| Non-codex reviewer regressed | Other REVIEWER_CLI backends break | That branch is unchanged in the diff | `git revert e6e4002` | `git diff 527a89e..e6e4002` shows only the codex branch changed |

## Decision

- Proceed / split / block: Proceed (committed as `e6e4002`; this canvas committed separately as the required complex-change evidence).
- Reason: A one-line invocation fix is the smallest change that restores the post-gate's ability to produce artifacts, unblocking every remaining harness task. Full gate hardening (retry-on-empty, Codex sandbox tightening, multi-CLI dispatch) stays in Task A4.
