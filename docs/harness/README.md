# AgentShield Harness - Operational Guide

This directory contains the local operational harness for `agentshield`. It gives agents and contributors a repeatable loop for context, consistency checks, scanner gates, independent review, progress memory, and periodic audit evidence.

The harness is local operational tooling. It is not production CI, and it must not weaken the scanner's offline-first security model.

## Model

| Script | Role | Contract |
|---|---|---|
| `bin/bootstrap.sh` | Orientation | Read-only, fast, prints branch/state and required read order |
| `bin/doctor.sh` | Consistency checker | Validates harness files, references, script executability, and shell syntax |
| `bin/sensors.sh` | Deterministic gates | No args means canonical full gate; modes are explicit developer aids |
| `bin/pr-title-policy.sh` | PR title policy | Rejects PR titles containing `[codex]` |
| `bin/review-gate.sh` | Independent review | General reviewer CLI gate with strict `REVIEW_VERDICT` artifacts |
| `bin/codex-gate.sh` | Compatibility wrapper | Runs `review-gate.sh` with `REVIEWER_CLI=codex` |
| `bin/baseline.sh` | Drift evidence | Writes cheap static repository facts to `.baseline-last` |
| `bin/quarterly-audit.sh` | Periodic evidence | Writes evidence-only audit reports under `audits/` |

## Layout

| Path | Layer | Purpose |
|---|---|---|
| `SPEC.md` | Feed-forward | Current scanner scope and active hardening program |
| `INVARIANTS.md` | Feed-forward | Rules that must not change without explicit decision |
| `WHAT_WE_DONT_DO.md` | Feed-forward | Negative scope and anti-pattern policy |
| `GATES.md` | Feedback | PASS/FAIL thresholds, sensor modes, review canvas, audit policy |
| `CODE_REVIEW_POLICY.md` | Review | Severity taxonomy, fake-success patterns, output/security review rules |
| `SKILLS.md` | Feed-forward | Repo-local skill inventory and promotion policy |
| `VERIFICATION_MANIFEST.md` | Evidence | Convention for recording verification and skipped checks |
| `known-issues/README.md` | Evidence | Contract for documented sensor exclusions |
| `progress.md` | Memory | Short live state for active harness work |
| `progress/*.md` | Memory | Detailed notes for bounded work streams |
| `canvas/README.md` | Review evidence | When complex-change evidence is required |
| `canvas/TEMPLATE.md` | Review evidence | Reusable review canvas template |
| `canvas/YYYY-MM-DD-<task>.md` | Review evidence | Task-specific complex-change evidence |
| `reviews/YYYY-MM-DD-<task>-{pre,post}.md` | Audit | Saved review outputs |
| `audits/*-quarterly-audit.md` | Audit | Evidence-only cleanup and drift reports |

## Mandatory Read Order

```text
SPEC.md -> INVARIANTS.md -> WHAT_WE_DONT_DO.md -> GATES.md -> CODE_REVIEW_POLICY.md -> progress.md -> active task or plan
```

`bootstrap.sh` prints this order at session start.

## Daily Flow

```text
bash docs/harness/bin/bootstrap.sh
read the mandatory files in order
optional: bash docs/harness/bin/review-gate.sh pre <task-id>
implement one issue or one bounded sub-area
bash docs/harness/bin/sensors.sh quick while iterating
bash docs/harness/bin/sensors.sh before completion or merge claims
optional: bash docs/harness/bin/review-gate.sh post <task-id>
record progress and verification evidence
```

## Sensor Modes

```bash
bash docs/harness/bin/sensors.sh
bash docs/harness/bin/sensors.sh full
bash docs/harness/bin/sensors.sh quick
bash docs/harness/bin/sensors.sh docs
bash docs/harness/bin/sensors.sh mcp
bash docs/harness/bin/sensors.sh fixtures
bash docs/harness/bin/sensors.sh sarif
bash docs/harness/bin/sensors.sh action
bash docs/harness/bin/sensors.sh release
bash docs/harness/bin/sensors.sh vscode
bash docs/harness/bin/sensors.sh baseline
bash docs/harness/bin/sensors.sh audit
```

No-argument `sensors.sh` and `sensors.sh full` are equivalent and remain the canonical full local gate. Optional lanes are developer aids and do not replace the full gate for completion claims.

## Review Canvas

Complex changes require a canvas under `docs/harness/canvas/YYYY-MM-DD-<task-id>.md` before post-review. Use `docs/harness/canvas/TEMPLATE.md`.

A change is complex when it changes more than roughly 200 non-generated lines, touches multiple scanner surfaces, changes CLI/output contracts, changes release/action/VS Code behavior, changes harness gates, adds dependencies, or introduces a new parser/runtime/security/signing pattern.

## Repo-Local Skills

Repository skills live under `skills/<name>/SKILL.md` and are documented in
`docs/harness/SKILLS.md`. They are harness inputs, not scratch files: new or
changed skills require review like other process changes. Personal operator
shortcuts belong in `~/.codex/skills`.

## Baseline And Audit

`baseline.sh` records cheap static repository facts in `docs/harness/.baseline-last`. It is drift evidence, not proof that implementation is correct.

`quarterly-audit.sh` is evidence-only. It writes reports under `docs/harness/audits/` and updates `docs/harness/.quarterly-audit-last`. It is not a pass/fail gate and must not delete, archive, or rewrite files.

## Known-Issue Sensor Exclusions

Sensor exclusions require:

- `--exclude-sensor <name>`
- `--known-issue <path>` pointing to a real known-issue file
- `--reason <text>`
- progress registration before relying on the exclusion

Exclusions are not a way to make production code look green.

## Current Scanner Surface

- Framework adapters: MCP, OpenClaw, Hermes Agent, CrewAI, LangChain, GPT Actions, Cursor Rules.
- Rule surface: 19 built-in detectors, `SHIELD-001` through `SHIELD-019`.
- Output formats: console, JSON, SARIF 2.1.0, HTML, plus DSSE attestation through `certify`.
- Trust workflows: suppressions, baselines, egress policy generation, optional runtime egress enforcement.
- Distribution surfaces: GitHub Action, release binaries for 5 targets, VS Code extension.

## Machine-readable Output

`doctor.sh` supports a `--json` mode that emits a single JSON object to stdout using the `harness-json-v1` contract defined in [`JSON_OUTPUTS.md`](JSON_OUTPUTS.md). Human output remains the default.

```bash
bash docs/harness/bin/doctor.sh --json
```

Exit codes match human mode: `0` on pass, `1` on failure, `2` for unknown flags. See `JSON_OUTPUTS.md` for the full envelope schema and `sensors.sh` mode list.

## Notes

- Changes under `docs/harness/bin/*`, `INVARIANTS.md`, `GATES.md`, `CODE_REVIEW_POLICY.md`, or bootstrap read order require progress updates.
- Changes under `docs/harness/bin/*` require independent post-review evidence. A self-generated or missing review artifact is not authoritative for harness script changes.
- Untracked `skills/*/SKILL.md` files are not allowed; promote them deliberately or move them outside the repo.
- PR titles must not contain `[codex]`; use `bash docs/harness/bin/pr-title-policy.sh --title "<title>"` or `--current-pr` before opening or updating a PR.
- The harness does not rewrite `AGENTS.md`.
- Generated review, progress, audit, and baseline artifacts are evidence, not source-of-truth scanner behavior.
