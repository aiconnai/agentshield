# Review Canvas: A4 review-gate hardening

Date: 2026-06-21
Owner: Codex
Scope: Harden AgentShield's existing reviewer backend contract, retry behavior, manual flow, and prior finding re-injection without changing `codex-gate.sh`.

## Trigger

- Trigger matched: Harness behavior change touching `docs/harness/bin/review-gate.sh`.
- Files expected to change:
  - `docs/harness/bin/review-gate.sh`
  - `docs/harness/bin/doctor.sh`
  - `docs/harness/CODE_REVIEW_POLICY.md`
  - `docs/harness/canvas/2026-06-21-a4-review-gate-hardening.md`
  - `docs/harness/progress.md`
  - `.superpowers/sdd/task-A4-report.md`

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Blind Engram port | Rejected. A4 scope was redefined because AgentShield already has `REVIEWER_CLI` and `run_reviewer`, and A2 already landed the stdin prompt hotfix. Blind copying could reintroduce false backends or drift existing compatibility. |
| Harden existing Codex backend | Accepted. Keep `REVIEWER_CLI=codex` as default and preserve `codex-gate.sh` compatibility while making the Codex call explicit: stdin prompt, read-only sandbox, and `-C "$REPO_ROOT"`. |
| Fake auto-review for unavailable backends | Rejected. `claude`, `grok`, and `ollama` should not imply automated review support unless a real local command path and safe invocation are verified. Unsupported backends must fail clearly with exit 2. |
| Manual artifact-driven flow | Accepted. `REVIEWER_CLI=manual` may generate advisory prompt artifacts for `pre` without fabricating PASS/FAIL. For `post`, any supported manual path must require a supplied review artifact instead of inventing a verdict. |
| Retry every missing verdict | Rejected. Empty reviewer output is a known transient and can be retried; non-empty output without a verdict should be preserved and handled by the existing verdict parser. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| Codex backend retry-on-empty | Up to `REVIEWER_RETRY_ATTEMPTS` reviewer invocations only when output is empty | One raw transcript per attempt plus final saved raw artifact | A real non-empty `REVIEW_VERDICT: FAIL` is terminal and must not be retried or masked. |
| Prior finding re-injection | One scan of the latest previous review artifact for the same task in `docs/harness/reviews/` | Small prompt string addition | Only `[BLOCKER]` and `[HIGH]` lines are re-injected, accepting optional bullet prefixes such as `- [HIGH]`. |
| Manual backend prompt generation | Constant time beyond prompt assembly | One advisory prompt artifact | `pre` exits 0 without automated verdict; `post` requires an explicit `--review-file` artifact if supported. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Empty Codex output retry | Use a temporary `codex` stub earlier in `PATH` that emits empty output first, then `REVIEW_VERDICT: PASS`; verify args include `exec --sandbox read-only -C <repo> -`. |
| Real FAIL verdict must not be retried or masked | Code trace: retry loop returns immediately on any non-empty output, including `REVIEW_VERDICT: FAIL`; existing parser then saves and enforces the FAIL. |
| Unknown reviewer backend | Run with an unsupported arbitrary `REVIEWER_CLI` value and verify exit 2 with a usage error before review starts. |
| Unsupported named backend | Run at least one of `REVIEWER_CLI=claude|grok|ollama` and verify exit 2 unless a real backend is implemented and locally verified. |
| Manual backend behavior | Run `REVIEWER_CLI=manual ... pre a4-review-gate-hardening` and verify it writes an advisory prompt artifact, exits 0, and does not fabricate `REVIEW_VERDICT: PASS`. |
| Prior findings absent | Run or trace post prompt assembly for a throwaway task with no previous artifacts and verify the heading includes a clear none line. |
| Prior findings present | Create temporary prior review artifacts with `[BLOCKER]`, `- [HIGH]`, `[MED]`, and `[LOW]`; verify only BLOCKER/HIGH appear under `## Prior unresolved findings (address or refute)`. |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| `codex-gate.sh` wrapper stops working | Existing Codex gate callers fail | Preserve default `REVIEWER_CLI=codex`, do not edit `codex-gate.sh`, keep mode/task interface unchanged | Revert the `review-gate.sh` backend dispatch changes only | `bash docs/harness/bin/doctor.sh`; syntax check; inspect `codex-gate.sh` remains untouched |
| Empty-output retry masks a real reviewer failure | False PASS or lost FAIL | Retry only exact empty raw output; stop on any non-empty output, including FAIL or malformed verdict | Remove retry wrapper and restore direct `run_reviewer` execution | Stub Codex retry test; parser test by code trace for non-empty FAIL |
| Manual backend fabricates review confidence | Harness claims review coverage it did not get | Manual pre only emits prompt/advisory artifact; manual post requires `--review-file` if used | Disable manual backend support entirely | Manual pre command exits 0 and generated artifact contains no PASS verdict |
| Unsupported backend silently falls back to unsafe generic invocation | False capability or command injection risk | `claude|grok|ollama` exit 2 unless explicitly implemented; unknown backends exit 2 before review | Remove named unsupported cases | Unknown backend and named unsupported backend checks |
| Prior finding scan re-injects low-priority noise | Review prompt becomes noisy and unstable | Filter only optional bullet-prefixed `[BLOCKER]` and `[HIGH]` lines | Remove prior finding prompt block | Temporary artifact injection test verifies MED/LOW excluded |
| Prior finding scan reads current output or wrong task | Prompt self-references stale or unrelated data | Match review filenames for the same task and exclude the current output path before writing it | Restore no re-injection behavior | Throwaway task artifact test with cleanup |

## Decision

- Proceed / split / block: Proceed.
- Reason: The change is limited to hardening an existing harness path and documentation. The risky parts have narrow verification: backend usage errors, manual artifact behavior, Codex stub retry, and prior finding filtering.
