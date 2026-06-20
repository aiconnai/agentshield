---
name: loop-triage-ci
description: Use for a Codex CI Sweeper triage loop that groups CI failures, classifies root causes, caps attempts, and proposes bounded minimal-fix candidates only after budget, denylist, and verifier gates.
---

# CI Sweeper Triage Loop

Use this skill to identify repeated or impactful CI failures and classify
bounded automated-fix candidates. Pair it with
`skills/loop-engineering/SKILL.md` for global loop safety rules.

## Inputs

- Failed checks list with messages and logs.
- Commit that introduced failures, when available.
- Retry count and history from prior runs.
- Current `ci-sweeper-state.md`, `loop-run-log.md`, and `loop-budget.md`.
- Current denylist, allowlist, and pause flags.

## Output

Write only actionable findings:

```markdown
## High Priority
- Check:
  Root cause class: lint | test | type | runtime | dependency | config
  Repro confidence: high | medium | low
  Minimal fix path:
  Attempt:

## Watch

## Escalate
- Flakes:
- Infra/noise:
- Repeated failures with no stable fix:

## Suggested Loop Action
- open worktree + minimal-fix
- ESCALATE_HUMAN
```

Append a short run summary to `ci-sweeper-state.md` and one JSON line or table
row to `loop-run-log.md`, matching the repository's existing loop-log format.

## Rules

- Cap attempts at 3 per item.
- Reproduce or identify the failure class before proposing a fix.
- Prefer the smallest diff that addresses the failing check.
- Do not auto-fix dependency-major upgrades, auth, payments, migrations,
  production infrastructure, release publishing, or other denylisted paths.
- Route flakes, infrastructure failures, repeated low-confidence failures, and
  exhausted attempts to `ESCALATE_HUMAN`.
- For low-risk candidates, create an isolated worktree and dispatch a
  `minimal-fix` implementer followed by an independent verifier.

## Verification Gate

The verifier must check:

- The original failing command or closest local equivalent.
- Relevant tests, lint, type checks, or build commands.
- Scope diff against the declared minimal fix path.
- AgentShield when agent, script, CI, connector, dependency, or policy surfaces
  changed.
- The denylist before any PR, merge, or external write.

## Completion Gate

Mark the run complete only when the state files include the attempt count,
confidence, evidence, next action, and clear escalation for denied or uncertain
items.
