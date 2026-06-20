# Repository Skills

AgentShield keeps repository-specific Codex skills under `skills/<name>/SKILL.md`.
These are part of the local harness surface when they describe repeatable
project work, review policy, loop behavior, or external-system operation.

This follows the same broad harness idea used by LazyCodex: skills are explicit
operational context, while diagnostics and doctor checks keep the harness
observable. Repo-local skills must therefore be tracked, reviewed, and validated
instead of left as accidental untracked files.

## Current Skills

| Skill | Purpose | Default level |
|---|---|---|
| `huly` | Huly project, issue, and document operations through the Platform API | Write-capable only after read-only probe |
| `loop-engineering` | Shared safety model for repeatable agent loops | Policy/reference |
| `loop-triage` | Daily signal triage for CI, issues, PRs, commits, and chat | L1 report-only |
| `loop-triage-ci` | CI failure grouping and bounded minimal-fix handoff | L1 report, L2 only with verifier |
| `dependency-triage` | Dependency advisory and patch-candidate triage | L1 report, patch-only candidates |
| `pr-review-triage` | PR aging, CI block, and reviewer-thread triage | L1 report, L2 only with verifier |

## Policy

- Every repo-local skill must live at `skills/<name>/SKILL.md`.
- Every skill must have YAML frontmatter with `name` and `description`.
- `name` must match the directory name.
- New skills require a harness review canvas when they change loop behavior,
  gate behavior, external-system operations, or automation level.
- Skills that only support a single operator and should not affect the repo
  belong in `~/.codex/skills`, not this repository.
- Local run artifacts, sub-agent evidence, and review transcripts belong in
  `.omo/` or `docs/harness/reviews/` according to their purpose; `.omo/` is
  intentionally ignored.

## Promotion Checklist

Before adding a new skill:

1. Decide whether it is repo policy or a personal operator shortcut.
2. Confirm the skill is report-only by default unless the user explicitly
   requests write-path work.
3. Name the verification commands or manual evidence the skill requires.
4. Add or update harness docs if the skill changes process.
5. Run `bash docs/harness/bin/doctor.sh`.
