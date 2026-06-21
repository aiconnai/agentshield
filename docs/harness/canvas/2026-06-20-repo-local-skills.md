# Review Canvas: repo-local-skills

Date: 2026-06-20
Owner: Codex
Scope: Promote loop triage skills from untracked files into the harness with validation.

## Trigger

- Trigger matched: harness behavior and repository skill surface changed.
- Files expected to change: `.gitignore`, `skills/*/SKILL.md`, harness docs,
  `docs/harness/bin/doctor.sh`, and this canvas.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Delete all untracked skills | Rejected because the files encode useful loop policy and would lose repo-specific process knowledge. |
| Move skills to `~/.codex/skills` | Rejected for these files because they reference AgentShield gates and repo paths. |
| Track skills and validate them in doctor | Accepted because it turns accidental files into explicit harness surface. |
| Ignore all `skills/*` | Rejected because it would hide future process drift. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `doctor.sh` skill validation | O(number of skills) | O(1) besides command output | Runs only during harness checks. |
| Skill loading by Codex | Human/agent initiated | Existing context cost | Skills are loaded only when relevant. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Untracked `skills/*/SKILL.md` should fail doctor | `git ls-files --others --exclude-standard -- 'skills/*/SKILL.md'` |
| Skill frontmatter must include name and description | `bash docs/harness/bin/doctor.sh` |
| `.omo/` evidence should stay out of Git status after recreation | `.gitignore` contains `.omo/` |

## Breakage Risk

| Risk | Impact | Mitigation | Verification |
|---|---|---|---|
| Personal skills become repo policy accidentally | Process noise | `docs/harness/SKILLS.md` says personal shortcuts belong in `~/.codex/skills` | Review diff and doctor |
| Future untracked skill files reappear | Dirty workspace and unclear ownership | Doctor checks untracked `skills/*/SKILL.md` | `bash docs/harness/bin/doctor.sh` |
| `.omo/` evidence is committed by accident | Leaks noisy local transcripts | `.gitignore` ignores `.omo/` | `git status --short` |

## Decision

- Proceed / split / block: Proceed.
- Reason: The skills match AgentShield loop operations and should be explicit,
  while local evidence should be ignored.
