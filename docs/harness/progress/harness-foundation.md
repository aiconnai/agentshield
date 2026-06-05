# Harness Foundation

Date: 2026-06-05

## Decision

Create an AgentShield-specific harness under `docs/harness/` using cross-harness patterns as structure, not domain content.

## Initial Adaptations

- Replaced platform contract/dashboard gates with scanner gates.
- Added fixture, SARIF, GitHub Action, release, and VS Code sensor modes.
- Kept quarterly audit evidence-only.
- Kept review gates optional and advisory for code, but strict about parseable verdicts.
- Kept harness scripts local, not CI inputs.

## Cross-Harness Improvement Pass - 2026-06-05

- Added explicit negative-scope policy in `WHAT_WE_DONT_DO.md`.
- Added `CODE_REVIEW_POLICY.md` as centralized review policy.
- Added Review Canvas README and template for complex changes.
- Added `doctor.sh` to validate harness consistency.
- Added generalized `review-gate.sh` and made `codex-gate.sh` a compatibility wrapper.
- Added independent-review guard for `docs/harness/bin/*` changes.
- Changed `sensors.sh` default from `quick` to canonical `full`.
- Added known-issue exclusion and verification manifest conventions.

## Open Follow-ups

- Decide whether `full` should include `vscode` for release candidates or keep it as a separate mode.
- Decide whether quarterly audit reports should be committed or treated as local evidence only.
- Add issue-specific canvas files when complex scanner changes start.

## Review Canvas - 2026-06-05

- Created `docs/harness/canvas/2026-06-05-harness-hardening.md` for this complex harness change.
- Verification commands were not run in this pass; record them only after explicit execution.

## Harness follow-up - 2026-06-05

- Updated the bootstrap/read-order contract to stop at `progress.md` and the active task or plan.
- Added a dedicated `mcp` sensor lane that checks the existing MCP validation report evidence.
- Preserved the canonical no-argument `sensors.sh` full gate.
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: none
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: harness contract and reference checks
- harness_verify:
  command: bash docs/harness/bin/sensors.sh mcp
  exit_code: 0
  output_summary: ALL SENSORS GREEN (mcp)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: none
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: MCP validation-report parity

## Harness follow-up - 2026-06-05 (doctor tightening)

- Tightened `doctor.sh` so the `mcp` gate check matches the exact `GATES.md` row instead of any loose MCP mention.

## Harness follow-up - 2026-06-05 (broad match tightening)

- Tightened `sensors.sh` `mcp` checks to exact `docs/VALIDATION_REPORT.md` anchors.
- Tightened `doctor.sh` checks for `docs/harness/bin/*`, `--known-issue`, and `--exclude-sensor` to reduce incidental matches.

## Harness follow-up - 2026-06-05 (doctor regex fix)

- Updated `doctor.sh` to pass patterns to `rg` with `-e`, so flag-like patterns such as `--known-issue` are treated as literals.
- Corrected the `GATES.md` harness-script check to match the capitalized contract text.

## Harness follow-up - 2026-06-05 (review evidence path constraint)

- Constrained `HARNESS_SCRIPT_REVIEW_EVIDENCE` to artifacts under `docs/harness/reviews/`.
- Rejected path traversal in the review evidence path before verdict parsing.

## Harness follow-up - 2026-06-05 (review prompt drift)

- Aligned `review-gate.sh` prompts with the bootstrap read-order contract by removing `VERIFICATION_MANIFEST.md` from the mandatory read list.
- Kept verification-manifest guidance as conditional evidence handling instead of mandatory prompt reading.
