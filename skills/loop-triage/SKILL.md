---
name: loop-triage
description: Use for a Codex daily triage loop that safely collects and classifies CI, issue, PR, commit, and chat signals into report-only handoff state with bounded scope, no auto-fix, and loop-run-log updates.
---

# Daily Triage Loop

Use this skill for repeatable L1 signal collection and safe report-only handoff.
Pair it with `skills/loop-engineering/SKILL.md` for the global loop guardrails.

## Inputs

Collect only the signals needed for the requested cadence:

- Recent CI or test failures from the last 24 hours.
- Open team issues, PRs, and review threads.
- Recent main-branch commits from the last 24 to 48 hours.
- Current `STATE.md` and `loop-run-log.md`.
- Existing loop budget and pause flags when present.

## Output

Append a concise update to `STATE.md`:

```markdown
## High Priority
- Item:
  Why now:
  Suggested next action:
  Effort estimate:

## Watch List

## Noise / Ignore

## State Updates
```

Append one summary line to `loop-run-log.md` with timestamp, result, evidence,
and next action.

## Rules

- Keep the loop L1 report-only unless the user explicitly raises it to L2.
- Put only high-signal items in High Priority.
- Do not make architecture changes.
- Do not edit product code.
- If no actionable items exist, record that and exit quickly.
- If a low-risk single-file bugfix candidate is found, create an L2 handoff
  item; do not auto-fix in week one.
- Escalate medium or high risk, unclear ownership, repeated failures, or
  denylisted paths to a human.

## Prompt Template

Use this shape when dispatching the loop:

```text
Run loop triage. Update STATE.md with High Priority, Watch List, Noise, and
State Updates. Update run timestamp and append loop-run-log.md. If action is
clear, low-risk, and a single-file bugfix candidate, escalate to minimal-fix
only in L2.
```

## Completion Gate

Mark the run complete only when `STATE.md` and `loop-run-log.md` are updated,
the evidence source is named, and any human-required item is escalated clearly.
