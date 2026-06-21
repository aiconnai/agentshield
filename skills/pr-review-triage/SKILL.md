---
name: pr-review-triage
description: Use for a Codex PR Babysitter triage loop that monitors PR aging, CI blocks, reviewer threads, and lightweight action proposals with isolated-worktree fix candidates and human escalation for risky changes.
---

# PR Babysitter Triage Loop

Use this skill for PR queue hygiene on a weekly or 5 to 15 minute cadence. The
default mode is proposal-only unless a low-risk L2 fix candidate passes the
gate. Pair it with `skills/loop-engineering/SKILL.md` for global loop controls.

## Inputs

- Open PR list and labels.
- CI status per PR.
- Required reviewer threads and blocking comments.
- Current `pr-babysitter-state.md`, history, run log, and budget file.
- Current denylist and auto-merge allowlist.

## Output

Append a concise triage block:

```markdown
## High Priority
- PR:
  Blocking condition:
  Why it blocks delivery:
  Exact action:
  Risk level:

## Watch

## Human Escalation

## State Updates
- Attempts already made:
- Last action taken:
- Who or what is next:
```

## Execution Gate

Only propose an isolated-worktree fix when all of these are true:

- CI is red or there is a clear review block.
- Attempts are below 3.
- The issue is a single-file or small-diff candidate.
- The path is not denylisted.
- A verifier is available after the implementer.

## Decision Matrix

- Low-risk minimal fix candidate: spawn `minimal-fix`, then `loop-verifier`.
- Medium or high risk, ambiguity, or path risk: append to triage inbox and
  escalate to a human.
- No actionable PRs: exit report-only after updating state and run log.

## Rules

- Do not auto-merge without an explicit allowlist.
- Do not resolve reviewer comments unless the verifier confirms the diff and
  intent.
- Do not edit auth, billing, migrations, production infra, secrets, release
  workflows, or AgentShield policy surfaces without human approval.
- Prefer a short comment or issue handoff over speculative code changes.

## Completion Gate

Mark the run complete only when every high-priority PR has a next action, risk
level, owner or escalation path, and run-log entry.
