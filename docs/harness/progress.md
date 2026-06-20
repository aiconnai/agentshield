# AgentShield Harness Progress

Status: stricter cross-harness foundation added on 2026-06-05.

## Current Focus

- Keep local scanner gates explicit and repeatable.
- Keep AgentShield's CLI, output formats, GitHub Action, release workflow, and VS Code extension aligned.
- Preserve no-argument `sensors.sh` as the canonical full local gate.
- Capture periodic evidence without turning audit scripts into automatic cleanup or blocking policy.

## Adopted Improvements - 2026-06-05

- Added `docs/harness/WHAT_WE_DONT_DO.md` as explicit negative scope.
- Added `docs/harness/CODE_REVIEW_POLICY.md` with strict `REVIEW_VERDICT` review markers.
- Added Review Canvas docs and template under `docs/harness/canvas/`.
- Added `docs/harness/bin/doctor.sh` as the harness consistency checker.
- Generalized review gating through `docs/harness/bin/review-gate.sh`; `codex-gate.sh` is now a Codex wrapper.
- Added harness-script independent review guard.
- Added `docs/harness/VERIFICATION_MANIFEST.md` and `docs/harness/known-issues/README.md` conventions.
- Strengthened `sensors.sh`: no args now means `full`, while `quick` is explicit.
- Kept baseline and quarterly audit evidence-only.

## Active Notes

- Detailed foundation note: `docs/harness/progress/harness-foundation.md`.
- Review evidence should go under `docs/harness/canvas/` for complex changes.
- Review artifacts should go under `docs/harness/reviews/`.
- Quarterly evidence reports should go under `docs/harness/audits/`.
- PR titles must not contain `[codex]`; `docs/harness/bin/pr-title-policy.sh` is the local guard.

## Next Useful Runs

```bash
bash docs/harness/bin/bootstrap.sh
bash docs/harness/bin/doctor.sh
bash docs/harness/bin/sensors.sh quick
bash docs/harness/bin/sensors.sh baseline
```

## Verification Notes

No commands are recorded as verified unless they are run and logged using the `docs/harness/VERIFICATION_MANIFEST.md` convention.

## Review Canvas - 2026-06-05

- Added `docs/harness/canvas/2026-06-05-harness-hardening.md` for this harness hardening pass.
- Purpose: record approaches, complexity, edge cases, and breakage risks because the change modifies harness gates and review policy.

## Harness follow-up - 2026-06-05

- Tightened the mandatory read order so `VERIFICATION_MANIFEST.md` is no longer part of the bootstrap/read-order chain.
- Added an explicit `mcp` sensor lane backed by the existing MCP validation report evidence.
- Kept the canonical no-argument `sensors.sh` full gate unchanged.
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

## Harness follow-up - 2026-06-20 (A1: scope-validated commit message checker)

- Added `docs/harness/bin/check-commit-msg.sh` for Conventional-Commit + AgentShield scope validation.
- Chained checker into `.githooks/commit-msg` after trailer validation.
- Registered in `doctor.sh` with scope and GATES.md documentation checks.
- Documented in `GATES.md` with allowed types, required scopes, and invocation examples.
