---
name: dependency-triage
description: Use for a Codex dependency sweeper triage loop that watches advisories and lockfiles, proposes patch-only updates, rejects major upgrades without approval, and records reproducible verification commands.
---

# Dependency Sweeper Triage Loop

Use this skill to watch dependency alerts and propose low-risk patch candidates
only. Pair it with `skills/loop-engineering/SKILL.md` for the global loop
guardrails and AgentShield gate.

## Inputs

- Advisory feeds, security notices, or Renovate/Dependabot-style inputs.
- Lockfile and package manager metadata.
- Current `dependency-sweeper-state.md`, `loop-run-log.md`, and
  `loop-budget.md`.
- Relevant release notes or changelogs for candidate patch versions.
- Current denylist, pause flags, and attempt counts.

## Output

Record findings in state:

```markdown
## High Priority
- Package:
  Current version:
  Target patch version:
  CVE or issue:
  Version window:
  Blast radius estimate:
  Patch strategy:
  Verification command:

## Watch

## Escalate
```

## Rules

- Default policy is patch updates only.
- Never run major upgrades without human approval.
- Treat minor upgrades as human-reviewed unless the loop charter explicitly
  allows them.
- If no patch path exists, route to `ESCALATE_HUMAN` with evidence.
- Always include a reproducible verification command in the output.
- Do not update lockfiles or manifests when the budget guard, denylist, or
  verifier is missing.
- Run AgentShield when dependency metadata, CI, scripts, tools, or agent
  surfaces change.

## Patch Candidate Gate

A patch candidate is eligible for L2 only when:

- The advisory or issue is confirmed.
- The update is patch-level or explicitly approved.
- The affected package is not in a denied ecosystem or path.
- The test/build command is known.
- Attempts are below 3.
- The verifier can independently run the proposed verification command.

## Completion Gate

Mark the run complete only when high-priority advisories have a patch strategy
or escalation, watch items are recorded, and `loop-run-log.md` includes the
evidence source, budget status, and next action.
