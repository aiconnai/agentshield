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

## A1 post-gate fix round 1 - 2026-06-20

- Created `docs/harness/canvas/2026-06-20-a1-check-commit-msg.md` (missing review canvas — Finding 1).
- Fixed `--message` missing-operand guard in `check-commit-msg.sh` to exit 2 with usage message instead of crashing on unbound variable (Finding 2).
- Added verification evidence block below (Finding 3).
- harness_verify:
  command: bash -n docs/harness/bin/check-commit-msg.sh
  exit_code: 0
  output_summary: shell syntax clean
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms script is parseable by bash before any runtime check
- harness_verify:
  command: sh -n .githooks/commit-msg
  exit_code: 0
  output_summary: hook syntax clean under POSIX sh
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: hook is invoked by git under /bin/sh; must be POSIX-clean
- harness_verify:
  command: bash docs/harness/bin/check-commit-msg.sh --message
  exit_code: 2
  output_summary: printed usage line and exited 2 (documented usage-error code)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies Finding 2 fix — missing operand now exits 2, not unbound-variable crash
- harness_verify:
  command: bash docs/harness/bin/check-commit-msg.sh --message "feat(adapter): x"
  exit_code: 0
  output_summary: "OK commit message: feat(adapter): x"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms valid scope+type still accepted after guard insertion
- harness_verify:
  command: bash docs/harness/bin/check-commit-msg.sh --message "broken"
  exit_code: 1
  output_summary: FAIL — message does not match required format
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms malformed message rejected with exit 1
- harness_verify:
  command: bash docs/harness/bin/check-commit-msg.sh --message "feat(nope): x"
  exit_code: 1
  output_summary: FAIL — bad scope rejected with exit 1
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms unknown scope rejected with exit 1
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor (all checks pass including new canvas)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A1
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: doctor validates script, canvas dir, GATES.md references, and no regression

## Harness follow-up - 2026-06-20 (A2: harness-json-v1 contract + doctor --json)

- Created `docs/harness/JSON_OUTPUTS.md` defining the harness-json-v1 contract (adapted from Engram).
- Added `--json` mode to `docs/harness/bin/doctor.sh` with flag parsing, JSON_FAILURES accumulator, guarded echoes, and JSON output block.
- Registered `require_file docs/harness/JSON_OUTPUTS.md` and `require_match "README mentions JSON_OUTPUTS.md"` in doctor.sh.
- Added Machine-readable Output section to `docs/harness/README.md` linking the contract.
- Created `docs/harness/canvas/2026-06-20-a2-json-outputs.md` (canvas required by GATES.md for harness script changes).
- harness_verify:
  command: "bash docs/harness/bin/doctor.sh --json | python3 -c \"import sys,json; d=json.load(sys.stdin); assert d['schema_version']=='harness-json-v1' and d['tool']=='doctor'; print('OK', d['status'], d['failure_count'])\""
  exit_code: 0
  output_summary: OK pass 0
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms JSON envelope is valid, schema_version and tool fields correct, failure_count 0 on clean repo
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: "PASS: AgentShield harness doctor (exit 0)"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: human mode unchanged, exits 0 on clean repo
- harness_verify:
  command: bash docs/harness/bin/doctor.sh --json
  exit_code: 0
  output_summary: "one harness-json-v1 object, status pass, exit 0"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms exit code parity between human and JSON modes (both 0 on clean repo)
- harness_verify:
  command: bash docs/harness/bin/doctor.sh --bogus
  exit_code: 2
  output_summary: "Usage: doctor.sh [--json] on stderr, exit 2"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms unknown flag exits 2 (usage_error) as documented in JSON_OUTPUTS.md Status Vocabulary
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: human mode PASS line unchanged after all A2 modifications
- harness_verify:
  command: bash docs/harness/bin/sensors.sh quick
  exit_code: 0
  output_summary: ALL SENSORS GREEN (quick)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: no regression in quick sensor gate after A2 changes

## A2 post-gate fix round 1 - 2026-06-20 (JSON_OUTPUTS sensor-description parity)

- Codex gate returned FAIL [MED]: sensor-mode descriptions in `docs/harness/JSON_OUTPUTS.md` were copied
  from Engram and described the wrong commands for AgentShield.
- Corrected all 11 sensor-mode descriptions against GATES.md (authoritative source):
  - `full`: was "canonical full local gate" → "complete local gate: doctor + fmt + clippy + tests + fixture smoke + SARIF + action/release static checks"
  - `quick`: was "fast subset: doctor + clippy + fmt + unit tests" → "fast subset: harness checks (doctor + shell syntax) + fmt + cargo check --all-features"
  - `docs`: was "doc checks only" → "harness policy references and current CLI/action/release doc references are present"
  - `mcp`: was "MCP validation report parity" → "MCP validation report references the Anthropic reference servers and records current validation evidence"
  - `fixtures`: was "fixture scan checks" → "supported fixture scans return success or findings, not scan errors"
  - `sarif`: was "SARIF output checks" → "SARIF file is emitted and has expected top-level shape"
  - `action`: was "GitHub Action checks" → "composite action keeps expected inputs, SARIF upload, and exit-code behavior"
  - `release`: was "release workflow checks" → "release workflow keeps 5 targets, --features full, and wrap smoke checks"
  - `vscode`: was "VS Code extension checks" → "npm ci and npm run compile pass in vscode/"
  - `baseline`: was "baseline drift evidence" → "baseline snapshot writes .baseline-last and doctor passes"
  - `audit`: was "quarterly audit evidence" → "evidence-only quarterly audit report is generated and doctor passes"
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: doctor still passes after sensor description corrections
- harness_verify:
  command: bash docs/harness/bin/sensors.sh quick
  exit_code: 0
  output_summary: ALL SENSORS GREEN (quick)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: quick sensor gate unaffected by doc-only change
- harness_verify:
  command: bash docs/harness/bin/sensors.sh docs
  exit_code: 0
  output_summary: ALL SENSORS GREEN (docs)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: docs sensor (validates harness doc references) passes after parity fix

## A2 post-gate fix round 2 - 2026-06-20 (BLOCKER: doctor --json failure path tempfile-free)

- Codex gate returned FAIL [BLOCKER]: the `--json` failure path used `IFS='|' read -r -a _f <<< "$JSON_FAILURES"`.
  The here-string (`<<<`) is implemented by bash via a temp file. In a restricted environment
  (sandbox, locked-down CI, read-only FS) the here-string creation fails, `_f` is never
  assigned, and the subsequent `${_f[@]}` expansion aborts under `set -uo pipefail` with
  `_f[@]: unbound variable`, emitting shell errors instead of a valid JSON object.
- Fix: replaced the here-string split with pure-bash word-splitting:
  save IFS, disable globbing (`set -f`), assign `_f=( $JSON_FAILURES )` with `IFS='|'`,
  then restore. `_f=()` is initialized empty before the `if` so `${_f[@]}` is safe under
  `set -u` even when `JSON_FAILURES` is empty. No temp file, no subshell.
- `local` was NOT used — the block is at top level (not inside a function); using `local`
  outside a function is a bash error. Plain `_old_ifs=` and `_f=()` assignments used instead.
- harness_verify:
  command: "bash docs/harness/bin/doctor.sh --json | python3 -c \"import sys,json; d=json.load(sys.stdin); assert d['status']=='pass' and d['failure_count']==0; print('PASS-OK')\""
  exit_code: 0
  output_summary: PASS-OK (valid JSON, status=pass, failure_count=0)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: happy path still emits valid JSON after tempfile-free fix
- harness_verify:
  command: "env PATH=/usr/bin:/bin:/usr/sbin:/sbin bash docs/harness/bin/doctor.sh --json"
  exit_code: 1
  output_summary: "one harness-json-v1 object on stdout (status fail, exit_code 1, failure_count == len(failures) == 45); stderr 0 bytes; stdout parsed as valid JSON"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: failure path (rg hidden from PATH) emits exactly one valid JSON object, process exits 1, zero bytes on stderr (no shell errors)
- harness_verify:
  command: "TMPDIR=/nonexistent env PATH=/usr/bin:/bin:/usr/sbin:/sbin bash docs/harness/bin/doctor.sh --json"
  exit_code: 1
  output_summary: "with TMPDIR=/nonexistent: still one valid harness-json-v1 object on stdout, process exits 1, stderr 0 bytes"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms no temp file needed for the split — TMPDIR=/nonexistent does not affect correctness
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: human mode unaffected by the fix
- harness_verify:
  command: bash docs/harness/bin/sensors.sh quick
  exit_code: 0
  output_summary: ALL SENSORS GREEN (quick)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: no regression in quick sensor gate after BLOCKER fix

## A2 post-gate fix round 3 - 2026-06-20 (two MED: usage_error JSON envelope + progress.md exit_code masking)

- Codex gate returned FAIL [MED] finding 1: doctor.sh --json did not emit a JSON envelope on usage errors.
  When --json appeared before an unknown flag, JSON_MODE was set to 1 but the *)  branch still emitted
  a plain-text "Usage:" line to stderr and exited 2 — violating the JSON_OUTPUTS.md usage_error contract.
  The reverse order (--bogus --json) also failed because the *) branch exited before --json was processed.
  Fix: restructured arg parsing into two passes. First pass (loop over all args, --json only) sets
  JSON_MODE. usage_error() function then checks JSON_MODE and emits either a harness-json-v1 JSON envelope
  (status=usage_error, exit_code=2, failures=[], failure_count=0) or the plain-text Usage: line to stderr.
  Second pass detects unknown args and calls usage_error(). Order-independent; human mode unchanged.
- Codex gate returned FAIL [MED] finding 2: progress.md line 220-229 recorded command
  "bash docs/harness/bin/doctor.sh --bogus; echo \"exit=$?\"" with exit_code: 2, but the compound
  command (with the trailing echo) actually exits 0 (echo succeeds), making the recorded exit_code false.
  Fix: replaced command with bare "bash docs/harness/bin/doctor.sh --bogus" and updated output_summary
  to describe the real stderr output. No other A2 entries had the same false-exit-code pattern
  (lines 201 and 211 use masking but record exit_code: 0, which is truthful for those bare commands).
- Added canonical full-gate harness_verify entry (sensors.sh full) for A2 below.
- harness_verify:
  command: bash docs/harness/bin/doctor.sh --json --bogus
  exit_code: 2
  output_summary: '{"schema_version":"harness-json-v1","tool":"doctor","mode":"json","status":"usage_error","exit_code":2,"summary":"usage error: unknown argument","failures":[],"failure_count":0} on stdout, zero stderr bytes'
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: --json --bogus order emits valid JSON usage_error envelope, no plain-text on stderr
- harness_verify:
  command: bash docs/harness/bin/doctor.sh --bogus --json
  exit_code: 2
  output_summary: '{"schema_version":"harness-json-v1","tool":"doctor","mode":"json","status":"usage_error","exit_code":2,"summary":"usage error: unknown argument","failures":[],"failure_count":0} on stdout, zero stderr bytes'
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: --bogus --json order (json after bad flag) also emits valid JSON usage_error — order-independent
- harness_verify:
  command: bash docs/harness/bin/doctor.sh --bogus
  exit_code: 2
  output_summary: "Usage: doctor.sh [--json] on stderr, exit 2, no stdout"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: human mode (no --json) still emits plain-text Usage: to stderr unchanged
- harness_verify:
  command: bash docs/harness/bin/sensors.sh
  exit_code: 0
  output_summary: ALL SENSORS GREEN (full, 2026-06-20T18:56:43Z)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A2
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: canonical full gate passes after all A2 round-3 fixes

## A3 sensors status JSON - 2026-06-20

- Added a read-only `sensors.sh status --json` snapshot command for `docs/harness/.sensors-last`.
- The status snapshot maps saved `PASS` to `pass`, saved `FAIL` to `fail`, and missing/empty state to `warn`.
- The command reports saved state only; it exits 0 for valid status snapshots, including a saved failing run.
- Registered the subcommand in `doctor.sh` and documented the JSON object in `JSON_OUTPUTS.md`.
- harness_verify:
  command: bash -n docs/harness/bin/sensors.sh
  exit_code: 0
  output_summary: no output; shell syntax clean
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: changed harness script parses before behavior checks
- harness_verify:
  command: "bash docs/harness/bin/sensors.sh status --json | python3 -c \"import sys,json; d=json.load(sys.stdin); assert d['tool']=='sensors' and d['status'] in ('pass','warn','fail'); print('STATUS-JSON-OK', d['status'])\""
  exit_code: 0
  output_summary: STATUS-JSON-OK <pass|warn|fail> depending on current .sensors-last snapshot
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: populated .sensors-last emits valid harness-json-v1 status object
- harness_verify:
  command: python3 -c "import json,pathlib,subprocess; p=pathlib.Path('docs/harness/.sensors-last'); old=p.read_bytes() if p.exists() else None; p.unlink(missing_ok=True); cp=subprocess.run(['bash','docs/harness/bin/sensors.sh','status','--json'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE); p.write_bytes(old) if old is not None else p.unlink(missing_ok=True); d=json.loads(cp.stdout); assert cp.returncode==0 and cp.stderr=='' and d['status']=='warn' and d['exit_code']==0 and d['last_timestamp']=='' and d['last_mode']==''; print('MISSING-STATUS-OK', d['status'])"
  exit_code: 0
  output_summary: MISSING-STATUS-OK warn
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: missing .sensors-last is a valid read-only warn snapshot, not a command failure
- harness_verify:
  command: python3 -c "import json,pathlib,subprocess; p=pathlib.Path('docs/harness/.sensors-last'); old=p.read_bytes() if p.exists() else None; p.write_text('2026-06-20T00:00:00Z quick FAIL\n'); cp=subprocess.run(['bash','docs/harness/bin/sensors.sh','status','--json'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE); p.write_bytes(old) if old is not None else p.unlink(missing_ok=True); d=json.loads(cp.stdout); assert cp.returncode==0 and cp.stderr=='' and d['status']=='fail' and d['exit_code']==0; print('FAIL-STATUS-OK', d['status'])"
  exit_code: 0
  output_summary: FAIL-STATUS-OK fail
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: saved FAIL maps to JSON status fail while the read-only status command still exits 0
- harness_verify:
  command: bash docs/harness/bin/sensors.sh status
  exit_code: 0
  output_summary: "last sensors: 2026-06-20T22:20:19Z quick PASS"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: human default status output remains a one-line text summary
- harness_verify:
  command: bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: doctor includes and passes the sensors status subcommand self-check
- harness_verify:
  command: bash docs/harness/bin/sensors.sh quick
  exit_code: 0
  output_summary: ALL SENSORS GREEN (quick, 2026-06-20T22:21:47Z)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: existing quick sensor lane still passes after status subcommand addition
- harness_verify:
  command: bash docs/harness/bin/sensors.sh status --json --bogus
  exit_code: 2
  output_summary: '{"schema_version":"harness-json-v1","tool":"sensors","mode":"status","status":"usage_error","exit_code":2,"summary":"usage error: unknown argument","failures":[],"failure_count":0}'
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A3
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: JSON status mode reports unknown arguments as a machine-readable usage_error

## A4 review-gate hardening - 2026-06-21

- Created `docs/harness/canvas/2026-06-21-a4-review-gate-hardening.md` before script edits.
- Scope was narrowed from blind Engram multi-CLI porting to AgentShield review-gate hardening:
  preserve `REVIEWER_CLI=codex`, keep `codex-gate.sh` unchanged, run Codex through a read-only sandbox,
  retry only empty reviewer output, keep manual review artifact-driven, and fail unsupported backends clearly.
- Added post prompt re-injection for prior `[BLOCKER]` and `[HIGH]` findings under
  `## Prior unresolved findings (address or refute)`.
- Updated doctor and policy docs for the new reviewer backend contract.
- Temporary `docs/harness/reviews/*a4-*` artifacts from local behavior tests were removed before staging.
- harness_verify:
  command: rtk proxy bash -n docs/harness/bin/review-gate.sh
  exit_code: 0
  output_summary: no output; shell syntax clean
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: changed review gate parses before behavior checks
- harness_verify:
  command: rtk proxy bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor; included new checks for REVIEWER_RETRY_ATTEMPTS, read-only Codex sandbox, prior finding re-injection, manual flow, unsupported backend handling, and policy documentation
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: validates harness references and A4 hardening markers
- harness_verify:
  command: rtk proxy env REVIEWER_CLI=manual bash docs/harness/bin/review-gate.sh pre a4-review-gate-hardening
  exit_code: 0
  output_summary: Manual pre-gate advisory prompt saved to docs/harness/reviews/2026-06-21-a4-review-gate-hardening-pre-manual.md
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies manual pre is artifact-driven and exits 0
- harness_verify:
  command: rtk proxy rg -n '^REVIEW_VERDICT:[[:space:]]*PASS[[:space:]]*$' docs/harness/reviews/2026-06-21-a4-review-gate-hardening-pre-manual.md
  exit_code: 1
  output_summary: no output; no fabricated final PASS marker in manual advisory artifact
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms manual pre did not invent an automated PASS
- harness_verify:
  command: rtk proxy env REVIEWER_CLI=bogus bash docs/harness/bin/review-gate.sh pre a4-unknown-backend
  exit_code: 2
  output_summary: "ERROR: unknown REVIEWER_CLI: bogus (supported: codex, manual; reserved but unsupported: claude, grok, ollama)"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: unknown reviewer backend fails as usage error before review
- harness_verify:
  command: rtk proxy env REVIEWER_CLI=claude bash docs/harness/bin/review-gate.sh pre a4-unsupported-backend
  exit_code: 2
  output_summary: "ERROR: REVIEWER_CLI=claude is not supported by this harness yet; supply a verified backend implementation before using it."
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: reserved unsupported backend does not fall through to generic command execution
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, shutil, stat, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*a4-retry-stub*"):
        p.unlink()
    stubdir = pathlib.Path(tempfile.mkdtemp())
    log = pathlib.Path("/tmp/a4-retry-stub-args.log")
    count = pathlib.Path("/tmp/a4-retry-stub-count.txt")
    log.unlink(missing_ok=True)
    count.unlink(missing_ok=True)
    stub = stubdir / "codex"
    stub.write_text("""#!/usr/bin/env bash
    count=0
    [ -f "$A4_STUB_COUNT" ] && count=$(cat "$A4_STUB_COUNT")
    count=$((count + 1))
    printf "%s\n" "$count" > "$A4_STUB_COUNT"
    printf "%s\n" "$*" >> "$A4_STUB_LOG"
    cat >/dev/null
    [ "$count" -eq 1 ] && exit 0
    printf "REVIEW_VERDICT: PASS\n[LOW] retry stub pass\n"
    """)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{stubdir}:{env['PATH']}"
    env["REVIEWER_CLI"] = "codex"
    env["REVIEWER_RETRY_ATTEMPTS"] = "2"
    env["A4_STUB_LOG"] = str(log)
    env["A4_STUB_COUNT"] = str(count)
    cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "pre", "a4-retry-stub"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cp.stdout + cp.stderr
    for p in reviews.glob("*a4-retry-stub*"):
        p.unlink()
    shutil.rmtree(stubdir)
    args = log.read_text()
    calls = count.read_text().strip()
    log.unlink(missing_ok=True)
    count.unlink(missing_ok=True)
    assert cp.returncode == 0 and calls == "2"
    assert "exec --sandbox read-only -C /Users/ronaldo/Projects/_aiconnai/agentshield -" in args
    assert "WARN: reviewer produced empty output" in output
    print("RETRY-STUB-OK count=2")
    PY
  exit_code: 0
  output_summary: retry warning emitted once; pre-gate saved; review_status=0; stub args recorded twice as `exec --sandbox read-only -C /Users/ronaldo/Projects/_aiconnai/agentshield -`; stub_count=2
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies retry-on-empty and exact read-only Codex invocation
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, shutil, stat, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*a4-prior-stub*"):
        p.unlink()
    prior = reviews / "2026-06-21-a4-prior-stub-post-codex.md"
    prior.write_text("REVIEW_VERDICT: FAIL\n[BLOCKER] keep blocker finding\n- [HIGH] keep high finding\n[MED] drop med\n[LOW] drop low\n")
    stubdir = pathlib.Path(tempfile.mkdtemp())
    capture = pathlib.Path("/tmp/a4-prior-stub-prompt.md")
    capture.unlink(missing_ok=True)
    stub = stubdir / "codex"
    stub.write_text("""#!/usr/bin/env bash
    cat > "$A4_CAPTURE_PROMPT"
    printf "REVIEW_VERDICT: PASS\n[LOW] prior stub pass\n"
    """)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{stubdir}:{env['PATH']}"
    env["REVIEWER_CLI"] = "codex"
    env["A4_CAPTURE_PROMPT"] = str(capture)
    cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "post", "a4-prior-stub", "--range=HEAD..HEAD"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prompt = capture.read_text()
    block = prompt.split("## Prior unresolved findings (address or refute)", 1)[1].split("Verdict format required:", 1)[0]
    for p in reviews.glob("*a4-prior-stub*"):
        p.unlink()
    shutil.rmtree(stubdir)
    capture.unlink(missing_ok=True)
    assert cp.returncode == 0
    assert "[BLOCKER] keep blocker finding" in block and "- [HIGH] keep high finding" in block
    assert "[MED]" not in block and "[LOW]" not in block
    print("PRIOR-STUB-OK blocker/high-only")
    PY
  exit_code: 0
  output_summary: post-gate PASS; captured prior block contained `[BLOCKER] keep blocker finding` and `- [HIGH] keep high finding`; `[MED]` and `[LOW]` lines were absent
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies prior finding re-injection filters only BLOCKER/HIGH under the required heading
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, shutil, stat, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*a4-fail-no-retry*"):
        p.unlink()
    stubdir = pathlib.Path(tempfile.mkdtemp())
    count = pathlib.Path("/tmp/a4-fail-no-retry-count.txt")
    count.unlink(missing_ok=True)
    stub = stubdir / "codex"
    stub.write_text("""#!/usr/bin/env bash
    count=0
    [ -f "$A4_STUB_COUNT" ] && count=$(cat "$A4_STUB_COUNT")
    count=$((count + 1))
    printf "%s\n" "$count" > "$A4_STUB_COUNT"
    cat >/dev/null
    printf "REVIEW_VERDICT: FAIL\n[HIGH] stub fail must not retry\n"
    """)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{stubdir}:{env['PATH']}"
    env["REVIEWER_CLI"] = "codex"
    env["REVIEWER_RETRY_ATTEMPTS"] = "2"
    env["A4_STUB_COUNT"] = str(count)
    cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "pre", "a4-fail-no-retry"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    calls = count.read_text().strip()
    artifacts = list(reviews.glob("*a4-fail-no-retry*"))
    assert cp.returncode == 1 and calls == "1"
    assert artifacts, "expected saved review artifact"
    wrapped = next(p for p in artifacts if p.suffix == ".md" and not p.name.endswith(".raw"))
    text = wrapped.read_text()
    assert "REVIEW_VERDICT: FAIL" in text and "[HIGH] stub fail must not retry" in text
    for p in artifacts:
        p.unlink()
    shutil.rmtree(stubdir)
    count.unlink(missing_ok=True)
    print("FAIL-NO-RETRY-ENFORCED count=1")
    PY
  exit_code: 0
  output_summary: FAIL-NO-RETRY-ENFORCED count=1; pre-gate returned FAIL; stub_count=1
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies a real automated pre FAIL verdict is saved, not retried, and enforced
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*a4-manual-post-stub*"):
        p.unlink()
    fd, review_path = tempfile.mkstemp(prefix="a4-manual-review-", suffix=".md")
    pathlib.Path(review_path).write_text("REVIEW_VERDICT: PASS\n[LOW] manual stub pass\n")
    os.close(fd)
    env = os.environ.copy()
    env["REVIEWER_CLI"] = "manual"
    cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "post", "a4-manual-post-stub", "--range=HEAD..HEAD", f"--review-file={review_path}"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for p in reviews.glob("*a4-manual-post-stub*"):
        p.unlink()
    pathlib.Path(review_path).unlink(missing_ok=True)
    assert cp.returncode == 0 and "OK: manual post-gate PASS" in (cp.stdout + cp.stderr)
    print("MANUAL-POST-STUB-OK")
    PY
  exit_code: 0
  output_summary: OK: manual post-gate PASS; review_status=0
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies manual post accepts a supplied reviewer artifact instead of running an automated backend
- harness_verify:
  command: rtk proxy env REVIEWER_CLI=manual bash docs/harness/bin/review-gate.sh post a4-manual-post-missing --range=HEAD..HEAD
  exit_code: 2
  output_summary: "ERROR: REVIEWER_CLI=manual post requires --review-file=<path> with a reviewer artifact containing REVIEW_VERDICT"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies manual post does not invent a verdict when no artifact is supplied
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, subprocess
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*cq-slash-task*"):
        p.unlink()
    env = os.environ.copy()
    env["REVIEWER_CLI"] = "manual"
    cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "pre", "cq/slash-task"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    artifacts = list(reviews.glob("*cq-slash-task-pre-manual.md"))
    fabricated = any("REVIEW_VERDICT: PASS" in p.read_text() for p in artifacts)
    for p in reviews.glob("*cq-slash-task*"):
        p.unlink()
    assert cp.returncode == 0 and len(artifacts) == 1 and not fabricated
    print("TASK-SLUG-OK cq-slash-task")
    PY
  exit_code: 0
  output_summary: TASK-SLUG-OK cq-slash-task
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies task ids with slash cannot produce false-success artifact paths
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, stat, subprocess
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*cq-write-fail*"):
        p.unlink()
    old_mode = stat.S_IMODE(reviews.stat().st_mode)
    reviews.chmod(0o500)
    try:
        env = os.environ.copy()
        env["REVIEWER_CLI"] = "manual"
        cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "pre", "cq-write-fail"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finally:
        reviews.chmod(old_mode)
    artifacts = list(reviews.glob("*cq-write-fail*"))
    for p in artifacts:
        p.unlink()
    assert cp.returncode == 1 and not artifacts
    assert "failed to write manual pre-gate prompt artifact" in (cp.stdout + cp.stderr)
    print("MANUAL-WRITE-FAIL-OK")
    PY
  exit_code: 0
  output_summary: MANUAL-WRITE-FAIL-OK
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies manual pre cannot claim success when the review artifact cannot be written
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, shutil, stat, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*cq-auto-write-fail*"):
        p.unlink()
    stubdir = pathlib.Path(tempfile.mkdtemp())
    stub = stubdir / "codex"
    stub.write_text("""#!/usr/bin/env bash
    cat >/dev/null
    printf "REVIEW_VERDICT: PASS\n[LOW] stub pass\n"
    """)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    old_mode = stat.S_IMODE(reviews.stat().st_mode)
    reviews.chmod(0o500)
    try:
        env = os.environ.copy()
        env["PATH"] = f"{stubdir}:{env['PATH']}"
        env["REVIEWER_CLI"] = "codex"
        cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "pre", "cq-auto-write-fail"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finally:
        reviews.chmod(old_mode)
        shutil.rmtree(stubdir)
    artifacts = list(reviews.glob("*cq-auto-write-fail*"))
    for p in artifacts:
        p.unlink()
    assert cp.returncode == 1 and not artifacts
    assert "could not save raw reviewer transcript" in (cp.stdout + cp.stderr)
    print("AUTO-WRITE-FAIL-OK")
    PY
  exit_code: 0
  output_summary: AUTO-WRITE-FAIL-OK
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies automated reviewers cannot claim pre-gate success when raw/wrapped artifacts cannot be written
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, stat, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*a4-manual-post-write-fail*"):
        p.unlink()
    stale = reviews / "2026-06-21-a4-manual-post-write-fail-post-manual.md"
    stale.write_text("REVIEW_VERDICT: PASS\n[LOW] stale pass must not be reused\n")
    fd, review_path = tempfile.mkstemp(prefix="a4-manual-fresh-", suffix=".md")
    os.close(fd)
    pathlib.Path(review_path).write_text("REVIEW_VERDICT: PASS\n[LOW] fresh manual pass\n")
    old_mode = stat.S_IMODE(reviews.stat().st_mode)
    reviews.chmod(0o500)
    try:
        env = os.environ.copy()
        env["REVIEWER_CLI"] = "manual"
        cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "post", "a4-manual-post-write-fail", "--range=HEAD..HEAD", f"--review-file={review_path}"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finally:
        reviews.chmod(old_mode)
        pathlib.Path(review_path).unlink(missing_ok=True)
    artifacts = list(reviews.glob("*a4-manual-post-write-fail*"))
    for p in artifacts:
        p.unlink()
    assert cp.returncode == 1
    assert "failed to save manual post-gate review artifact" in (cp.stdout + cp.stderr)
    assert "OK: manual post-gate PASS" not in (cp.stdout + cp.stderr)
    print("MANUAL-POST-WRITE-FAIL-OK")
    PY
  exit_code: 0
  output_summary: MANUAL-POST-WRITE-FAIL-OK
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies manual post cannot parse a stale PASS artifact when saving the supplied review fails
- harness_verify:
  command: |
    python3 - <<'PY'
    import os, pathlib, shutil, stat, subprocess, tempfile
    repo = pathlib.Path.cwd()
    reviews = repo / "docs/harness/reviews"
    for p in reviews.glob("*a4-nonempty-nonzero*"):
        p.unlink()
    stubdir = pathlib.Path(tempfile.mkdtemp())
    stub = stubdir / "codex"
    stub.write_text("""#!/usr/bin/env bash
    cat >/dev/null
    printf "some non-empty error without verdict\n" >&2
    exit 9
    """)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{stubdir}:{env['PATH']}"
    env["REVIEWER_CLI"] = "codex"
    env["REVIEWER_RETRY_ATTEMPTS"] = "2"
    cp = subprocess.run(["bash", "docs/harness/bin/review-gate.sh", "pre", "a4-nonempty-nonzero"], cwd=repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    artifacts = list(reviews.glob("*a4-nonempty-nonzero-pre-codex.md"))
    text = artifacts[0].read_text() if artifacts else ""
    for p in reviews.glob("*a4-nonempty-nonzero*"):
        p.unlink()
    shutil.rmtree(stubdir)
    assert cp.returncode == 1 and "review saved to" in (cp.stdout + cp.stderr)
    assert "REVIEW_VERDICT: FAIL" in text and "parseable REVIEW_VERDICT marker" in text
    print("NONEMPTY-NONZERO-SAVED-OK")
    PY
  exit_code: 0
  output_summary: NONEMPTY-NONZERO-SAVED-OK
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: verifies non-empty reviewer output is saved even when reviewer exits nonzero
- harness_verify:
  command: rtk proxy bash docs/harness/bin/sensors.sh quick
  exit_code: 0
  output_summary: ALL SENSORS GREEN (quick, 2026-06-21T15:17:00Z)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: quick harness lane passes after review-gate hardening
- harness_verify:
  command: rtk find 'a4-*' docs/harness/reviews
  exit_code: 0
  output_summary: "0 for 'a4-*'"
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A4
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: confirms generated A4 review artifacts were cleaned before staging

## A5 doctor drift checks - 2026-06-21

- Created `docs/harness/canvas/2026-06-21-a5-doctor-drift-checks.md` before post-review because `doctor.sh` behavior changed.
- Added conservative checks for the latest review artifact's `REVIEW_VERDICT` marker and AgentShield's full `.sensors-last` `TIMESTAMP MODE PASS|FAIL` format.
- Engram's SPEC sprint/active-plan drift checks were not ported because AgentShield does not define the same fields.

- harness_verify:
  command: rtk proxy bash -n docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: shell syntax OK
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: doctor remains parseable after adding drift checks
- harness_verify:
  command: rtk proxy bash docs/harness/bin/doctor.sh
  exit_code: 0
  output_summary: PASS: AgentShield harness doctor; latest review has parseable REVIEW_VERDICT; .sensors-last has parseable TIMESTAMP MODE PASS or FAIL result
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: human doctor mode passes with live review and sensor drift checks
- harness_verify:
  command: rtk proxy bash docs/harness/bin/doctor.sh --json | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='pass'; print('JSON-OK')"
  exit_code: 0
  output_summary: JSON-OK
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: JSON doctor mode remains a single valid pass object
- harness_verify:
  command: |
    python3 - <<'PY'
    import pathlib, subprocess
    repo = pathlib.Path.cwd()
    fixture = repo / "docs/harness/reviews/9999-12-31-a5-review-verdict-fixture.md"
    fixture.write_text("REVIEW_VERDICT: PASS\n[LOW] temporary doctor fixture\n")
    try:
        cp = subprocess.run(["bash", "docs/harness/bin/doctor.sh"], cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = cp.stdout + cp.stderr
        assert cp.returncode == 0
        assert f"latest review has parseable REVIEW_VERDICT: {fixture.relative_to(repo)}" in output
    finally:
        fixture.unlink(missing_ok=True)
    print("LATEST-REVIEW-VERDICT-CHECK-OK")
    PY
  exit_code: 0
  output_summary: LATEST-REVIEW-VERDICT-CHECK-OK
  passed: true
  evidence_path: generated then removed
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: proves the latest-review verdict check is live using a deterministic temporary artifact
- harness_verify:
  command: rtk proxy python3 -c "import pathlib,re; text=pathlib.Path('docs/harness/.sensors-last').read_text(); assert re.search(r'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\\s+\\S+\\s+(PASS|FAIL)$', text); print('SENSORS-LAST-FORMAT-OK', text.strip())"
  exit_code: 0
  output_summary: SENSORS-LAST-FORMAT-OK 2026-06-21T16:42:31Z quick PASS
  passed: true
  evidence_path: docs/harness/.sensors-last
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: proves the `.sensors-last` full-format check is live against the current snapshot
- harness_verify:
  command: |
    python3 - <<'PY'
    import json, pathlib, subprocess
    repo = pathlib.Path.cwd()
    snapshot = repo / "docs/harness/.sensors-last"
    original = snapshot.read_text() if snapshot.exists() else None
    snapshot.write_text("BROKEN\n2026-06-21T16:35:40Z quick PASS\n")
    try:
        cp = subprocess.run(["bash", "docs/harness/bin/doctor.sh", "--json"], cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        data = json.loads(cp.stdout)
        assert cp.returncode == 1
        assert data["status"] == "fail"
        assert data["failure_count"] == 1
        assert len(data["failures"]) == 1
        assert "PASS or FAIL" in data["failures"][0]
    finally:
        if original is None:
            snapshot.unlink(missing_ok=True)
        else:
            snapshot.write_text(original)
    print("SENSORS-LAST-MULTILINE-JSON-FAIL-OK")
    PY
  exit_code: 0
  output_summary: SENSORS-LAST-MULTILINE-JSON-FAIL-OK
  passed: true
  evidence_path: generated then restored
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: proves malformed multi-line `.sensors-last` fails without splitting one JSON failure into multiple failures
- harness_verify:
  command: rtk proxy bash docs/harness/bin/sensors.sh quick
  exit_code: 0
  output_summary: ALL SENSORS GREEN (quick, 2026-06-21T16:42:31Z)
  passed: true
  evidence_path: none
  skipped_reason: none
  issue_numbers: A5
  workspace: /Users/ronaldo/Projects/_aiconnai/agentshield
  importance: quick harness lane passes after doctor drift checks
