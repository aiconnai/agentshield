# Review Canvas: a1-check-commit-msg

Date: 2026-06-20
Owner: Claude (Sonnet 4.6)
Scope: Add a harness gate that validates Conventional Commit format and AgentShield scopes on every local commit.

## Trigger

- Trigger matched: harness gate / commit-message validation change.
- Files expected to change: `docs/harness/bin/check-commit-msg.sh`, `.githooks/commit-msg`, `docs/harness/bin/doctor.sh`, `docs/harness/GATES.md`, and this canvas.

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Prompt-only / honor-system | Rejected — cannot be enforced; agents and humans can supply any commit message without a mechanical check. |
| Dedicated checker script chained into commit-msg hook + doctor registration | Accepted — deterministic, runs locally on every `git commit`, registered in `doctor.sh` so drift is caught, exit codes are stable and documented. |
| Enforce only in GitHub workflow | Rejected — the harness is intentionally local and workflows must not execute harness scripts (`docs/harness/WHAT_WE_DONT_DO.md`). |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `check-commit-msg.sh --message '…'` | O(n) in message length | O(n) message buffer | Runs once per `git commit` on a short string; negligible cost. |
| `check-commit-msg.sh path/to/COMMIT_EDITMSG` | O(n) in file size | O(n) file buffer | Git hook invocation; COMMIT_EDITMSG is always short. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| Valid `feat(adapter): x` accepted (exit 0) | `bash docs/harness/bin/check-commit-msg.sh --message "feat(adapter): x"` |
| Bad scope `feat(nope): x` rejected (exit 1) | `bash docs/harness/bin/check-commit-msg.sh --message "feat(nope): x"` |
| Malformed `broken` rejected (exit 1) | `bash docs/harness/bin/check-commit-msg.sh --message "broken"` |
| `--message` with no operand → exit 2 usage error | `bash docs/harness/bin/check-commit-msg.sh --message` |
| Comment lines stripped; first non-comment line validated | `printf '# comment\nfeat(cli): real subject\n' > /tmp/t.txt && bash docs/harness/bin/check-commit-msg.sh /tmp/t.txt` |

## Breakage Risk

| Risk | Impact | Mitigation | Verification |
|---|---|---|---|
| Hook rejects legitimate commits | Blocking for developers | Scope + type allowlist matches GATES.md exactly; POSIX-sh chaining means the hook only calls the script, not inline logic | `bash -n docs/harness/bin/check-commit-msg.sh && sh -n .githooks/commit-msg` + the four edge-case commands |
| Future scope additions not reflected in script | Script silently rejects valid scopes | `doctor.sh` `require_match` keeps GATES.md and script in sync; any new scope must be added to both or doctor fails | `bash docs/harness/bin/doctor.sh` |
| `--message` missing operand exits with unbound-variable error instead of documented exit 2 | Confusing UX; exit code does not match documented contract | Guard added: `if [ "$#" -lt 2 ]; then … exit 2; fi` before `$2` dereference | `bash docs/harness/bin/check-commit-msg.sh --message` → exit 2 |
| Unknown bare flags silently ignored | Mistyped flags produce no feedback | `*)` branch only accepts existing files; non-file bare args are silently skipped (acceptable for hook usage; CLI usage is `--message` or file path only) | No change needed; documented as by-design |

## Decision

- Proceed / split / block: Proceed.
- Reason: A small deterministic script chained into the existing commit-msg hook gives reliable local enforcement with minimal complexity. The doctor integration ensures future drift is caught automatically.
