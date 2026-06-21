# Code Review Policy - AgentShield Harness

This policy is authoritative for `review-gate.sh` prompts and human review of AgentShield scanner and harness changes.

## Required Verdict Format

Every generated review artifact must contain exactly one final verdict marker:

```text
REVIEW_VERDICT: PASS
```

or:

```text
REVIEW_VERDICT: FAIL
```

The verdict must be followed by findings prefixed with `[BLOCKER]`, `[HIGH]`, `[MED]`, or `[LOW]` when findings exist.

## Reviewer CLI Selection

`review-gate.sh` selects the reviewer backend with `REVIEWER_CLI`. The default is `REVIEWER_CLI=codex`, and `docs/harness/bin/codex-gate.sh` remains the back-compat wrapper for callers that expect the Codex gate entrypoint.

The Codex backend must run through `codex exec --sandbox read-only -C "$REPO_ROOT" -` with the review prompt passed on stdin. Empty reviewer output may be retried up to `REVIEWER_RETRY_ATTEMPTS` times, defaulting to 3. A non-empty output containing `REVIEW_VERDICT: FAIL` must be saved and enforced, not retried or masked. Non-empty output without a parseable verdict must also be saved and handled by the normal verdict parser.

`REVIEWER_CLI=manual` is artifact-driven. Manual `pre` mode may write an advisory prompt artifact and exit 0, but it must not fabricate an automated PASS or FAIL. Manual `post` mode requires a supplied reviewer artifact, such as `--review-file=<path>`, containing a real `REVIEW_VERDICT` line.

`claude`, `grok`, and `ollama` are reserved backend names. They must fail with a usage error unless the harness has a verified local command path and invocation for that backend; the gate must not fall back to generic `"$REVIEWER_CLI" "$prompt"` execution.

On post-gate re-runs, the prompt must re-inject unresolved prior `[BLOCKER]` and `[HIGH]` findings for the same task under `## Prior unresolved findings (address or refute)`. `[MED]` and `[LOW]` findings are not re-injected.

## Severity Taxonomy

| Severity | Meaning |
|---|---|
| `[BLOCKER]` | Unsafe to merge; likely security regression, scanner false negative, broken output contract, broken gate, or hidden scope creep |
| `[HIGH]` | Material risk; likely false positive/negative drift, CLI/action/release/VS Code breakage, missing complex-change evidence, or gate weakening |
| `[MED]` | Correctness, maintainability, docs parity, or test coverage risk that should be fixed or explicitly accepted |
| `[LOW]` | Minor clarity, naming, ergonomics, or follow-up item |

## Review Focus

Reviewers must inspect for:

- scanner false negatives or false positives;
- adapter-to-IR contract violations;
- taint, sanitizer, cross-file analysis, source/sink, or policy mistakes;
- SARIF 2.1.0 and GitHub Code Scanning compatibility drift;
- JSON output drift that could break the VS Code extension;
- CLI, baseline, suppression, certify, egress, or wrap behavior drift;
- GitHub Action exit-code and SARIF upload behavior drift;
- release binaries accidentally omitting expected `full` features;
- offline-first or privacy regressions;
- documentation claiming more than code or gates prove;
- PR titles or PR automation that include the banned `[codex]` marker;
- hidden scope creep against `docs/harness/WHAT_WE_DONT_DO.md`.

## Fake-Success Patterns

Flag these as `[HIGH]` or `[BLOCKER]` depending on impact:

- tests or sensors that only prove a command ran, not that expected behavior occurred;
- SARIF shape checks that do not inspect required top-level fields;
- fixture scans that ignore scanner error exit codes;
- baseline or suppression changes that hide new findings silently;
- review artifacts without `REVIEW_VERDICT` markers;
- skipped checks omitted from progress or verification evidence;
- harness script changes reviewed only by the changed harness script.

## Review Canvas Requirement

If the diff is complex, verify that a matching Review Canvas exists under `docs/harness/canvas/` and contains:

- approaches considered and rejection reasons;
- hot-path complexity notes;
- at least two edge cases to test or trace;
- a breakage-risk table with mitigation and rollback.

Complex triggers are defined in `docs/harness/GATES.md` and `docs/harness/canvas/README.md`.

## Harness Script Changes

Harness script changes are process-critical. Reviewers must inspect them directly and must not rely only on generated prompt summaries.

Changes to `docs/harness/bin/*` require independent post-review evidence. If independent evidence is missing, `review-gate.sh post` must fail before claiming review success.

PR title policy changes must preserve the rule that pull request titles never contain `[codex]`.
