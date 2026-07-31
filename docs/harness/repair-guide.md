# Verification Repair Guide

Use the narrowest failing command to diagnose a problem before widening the
verification scope. Fix the cause, preserve the intended behavior, and rerun
the same command before claiming recovery.

## General Rules

- Treat a skipped or unavailable check as non-pass evidence.
- Do not silence diagnostics with broad `#[allow(...)]`, disable a gate, or
  alter a test solely to make it pass.
- Do not use production credentials, write paths, or bypass variables to repair
  a local or CI failure.
- If a failure is outside the requested change, record it with the command and
  relevant output rather than making unrelated changes.

## Format and Lint

| Symptom | First response | Verify recovery |
|---|---|---|
| `cargo fmt --check` fails | Run `cargo fmt --all`; review the resulting diff. | `cargo fmt --all -- --check` |
| Clippy fails | Read the diagnostic, fix the cause, and avoid broad suppressions. | Re-run the same `cargo clippy` command. |
| New `#[allow(...)]` is rejected | Add a specific, substantive justification only when the exception is necessary; otherwise remove the allow. | Re-run `sensors.sh` when policy changed. |

## Rust Build and Tests

| Symptom | First response | Verify recovery |
|---|---|---|
| Workspace check fails | Reproduce in the named crate or target, then inspect the smallest relevant call site. | `cargo check -p <crate> --all-targets --locked` or the original command. |
| Unit test fails | Run the test filter in the affected crate and inspect the failing path before editing. | Re-run the same filter, then the required broader gate. |
| Integration test fails | Confirm migrations, fixture assumptions, and required local services before changing code. | Re-run the exact integration test. |

## Documentation and Harness

| Symptom | First response | Verify recovery |
|---|---|---|
| Documentation sensor fails | Run the named generator or drift check, then update only the canonical source or generated output required by the failure. | `bash docs/harness/bin/sensors.sh docs` |
| `doctor.sh` fails | Read the specific failed invariant; update tracked harness structure, skill inventory, or frontmatter as required. | `bash docs/harness/bin/doctor.sh` |
| `verify` lane fails | Determine whether a known-bad fixture was accepted or a known-good fixture was rejected. Repair the checker or fixture without weakening the policy. | `bash docs/harness/bin/sensors.sh verify` |
| Harness script changes | Do not rely on the modified script as its sole proof. Request human review and run applicable protected-base CI evidence. | Required human review plus the relevant sensor output. |

## CI and External Boundaries

| Symptom | First response | Verify recovery |
|---|---|---|
| GitHub Actions workflow fails | Validate YAML, inspect the failed step, and reproduce the smallest safe local command when possible. | Re-run the workflow or required check after the targeted fix. |
| Missing credential or external service | Record the missing prerequisite and stop. Do not invent credentials or change code to hide the dependency. | A maintainer-provided environment or an explicitly approved mock. |
| Contract or security gate fails | Stop scope expansion, identify the affected boundary, and involve the owner when rollback or policy decisions are needed. | The contract/security-specific gate named in `GATES.md`. |

## Escalate Instead of Retrying

Escalate to a human when the repair would touch production data, secrets,
authentication, authorization, contracts, migrations, deployment configuration,
external remote state, or when the same focused repair has failed twice without
new evidence.