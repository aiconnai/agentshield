# Review Canvas: harness-hardening

Date: 2026-06-05
Owner: agent
Scope: Strengthen the AgentShield harness with Engram-style consistency, review, verification, and exclusion controls.

## Trigger

- Trigger matched: harness gate, invariant, bootstrap, sensor, doctor, and review policy changes.
- Files expected to change: `docs/harness/**` and `.gitignore`.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Keep the initial lightweight harness | Rejected because it lacked a dedicated doctor, strict review verdicts, canvas templates, known-issue exclusions, and no-arg full gate semantics. |
| Copy the Engram plan literally | Rejected because Engram-specific storage/MCP/schema assumptions do not belong in AgentShield. |
| Adapt the Engram model to AgentShield surfaces | Accepted because it preserves AgentShield scanner authority while adding stronger operational controls. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `doctor.sh` | Linear in number of harness files and checked references | Constant, except command output | Local consistency check only. |
| `sensors.sh quick` | Dominated by `cargo check --all-features` | Cargo build cache dependent | Iteration lane; no-arg `full` remains canonical. |
| `review-gate.sh post` | Dominated by reviewer CLI and git diff inspection | Review artifact size | Blocks harness script changes without independent PASS evidence. |
| `quarterly-audit.sh` | Linear in bounded `rg`/`find` evidence commands | One generated markdown report | Evidence-only; not a pass/fail gate. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| No-arg `sensors.sh` maps to full, while `quick` remains explicit | `bash docs/harness/bin/sensors.sh --help` is not implemented; inspect `MODE="full"` and mode parsing in script. |
| Harness script changes cannot be post-reviewed by the modified gate alone | `review-gate.sh post` checks `docs/harness/bin` changes and requires `HARNESS_SCRIPT_REVIEW_EVIDENCE` with `REVIEW_VERDICT: PASS`. |
| Missing policy/canvas files fail doctor | `doctor.sh` requires `WHAT_WE_DONT_DO.md`, `CODE_REVIEW_POLICY.md`, `VERIFICATION_MANIFEST.md`, canvas docs, and known-issues docs. |
| Sensor exclusions require explicit known issue and progress registration | `sensors.sh` validates `--exclude-sensor`, `--known-issue`, `--reason`, file existence, and progress reference. |

## Breakage Risk

| Risk | Impact | Mitigation | Verification |
|---|---|---|---|
| `sensors.sh` full is heavier than the previous default | Developers may run longer checks when using no args | Document `quick` as iteration lane and keep no-arg full as intentional canonical gate | Run `bash docs/harness/bin/sensors.sh quick` and `bash docs/harness/bin/doctor.sh` when verification is approved. |
| New review gate blocks harness script post-review without evidence | Some workflows need an explicit independent artifact | Document `HARNESS_SCRIPT_REVIEW_EVIDENCE` and keep `codex-gate.sh` wrapper | Run `bash -n docs/harness/bin/review-gate.sh` and a controlled post-gate trace when verification is approved. |
| Generated audit/review artifacts are ignored by default | Reports may not be committed accidentally or may need force-add | Document evidence semantics; `.gitignore` keeps generated reports local by default | Inspect `.gitignore` and force-add intentional artifacts if needed. |
| Doctor checks become stale as harness evolves | False failures in harness consistency | Keep doctor checks tied to explicit required contracts only | Run `bash docs/harness/bin/doctor.sh` after harness changes. |

## Decision

- Proceed / split / block: Proceed.
- Reason: The added controls are docs-local and script-local, preserve scanner code, and strengthen harness review discipline without wiring local scripts into CI.
