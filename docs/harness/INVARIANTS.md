# Invariants - AgentShield

Rules in this file do not change without explicit owner decision or a documented architectural decision.

## Scanner Architecture Invariants

- Adapters produce IR; detectors consume IR. Adding a framework must not require rewriting existing detectors.
- All matching adapters must run. Mixed-framework repositories are valid scan targets.
- `ArgumentSource` remains the taint abstraction used by detectors. Safe variants must not be treated as tainted.
- Cross-file analysis runs after parsing and before detector execution.
- Policy is separate from detection. Detectors always emit raw findings; policy decides suppression, filtering, and fail/pass verdicts.
- No `unwrap()` or panic-prone production path should be introduced for untrusted scan input.

## Offline And Privacy Invariants

- Scanning must be offline-first. Source code must not be uploaded to a service as part of normal scan behavior.
- GitHub Action network usage is limited to downloading release artifacts and SARIF upload requested by the workflow.
- Egress runtime wrapping is opt-in and feature-gated; it must not become implicit scan behavior.
- Local secrets, `.env` files, generated attestations, and private signing material must not be committed accidentally.

## Output Contract Invariants

- SARIF output must remain SARIF 2.1.0 compatible and acceptable to GitHub Code Scanning.
- JSON output must remain parseable by the VS Code extension.
- Finding fingerprints must remain stable for equivalent findings across runs.
- Baseline and suppression workflows must not hide new findings silently.
- DSSE certification must represent the scan result that was actually produced.

## CLI And Distribution Invariants

- Release binaries should be built with `--features full` so Python, TypeScript, and runtime wrap support are available in distributed artifacts.
- The `wrap` command remains feature-gated and must be smoke-checked in release workflows when included.
- The GitHub Action must preserve scan exit codes after optional SARIF upload.
- The GitHub Action `ignore-tests` input must stay aligned with CLI `--ignore-tests` behavior.
- The VS Code extension must shell out through a user-configurable binary path or PATH and parse current JSON output.

## Fixture And Test Invariants

- Safe fixtures should stay low-noise and must not gain high-severity findings casually.
- Vulnerable fixtures should keep proving the intended detector fires.
- Adapter fixtures should remain concrete examples of supported frameworks.
- Test-file exclusion must happen before parsing when `--ignore-tests` is active.

## Harness Invariants

- `docs/harness/bin/*` scripts must run under `bash`.
- `bootstrap.sh` must be read-only and fast.
- `doctor.sh` must pass after harness docs, scripts, read order, or review policy changes.
- `sensors.sh` with no args must remain the canonical full local gate.
- Optional sensor lanes are developer aids and must not replace full-gate completion claims.
- `review-gate.sh post` must require a strict `REVIEW_VERDICT: PASS` or `REVIEW_VERDICT: FAIL` marker.
- Harness script changes require independent post-review evidence; a modified gate cannot be the sole reviewer of itself.
- Harness scripts are local operational tooling and must not be production CI inputs.
- After two consecutive post-gate failures on the same task, stop and escalate instead of looping.
- This harness does not rewrite `AGENTS.md`.
- Baseline and quarterly audit reports are evidence-only until an owner explicitly promotes a check to a gate.
