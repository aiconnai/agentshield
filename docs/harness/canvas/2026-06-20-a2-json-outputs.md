# Review Canvas: a2-json-outputs

Date: 2026-06-20
Owner: Claude (Sonnet 4.6)
Scope: Add the harness-json-v1 contract document and a `--json` mode to `doctor.sh` so harness output becomes machine-consumable.

## Trigger

- Trigger matched: harness behavior change (doctor gains a JSON mode) + new contract doc (`JSON_OUTPUTS.md`). Per `docs/harness/GATES.md`, any change to `docs/harness/bin/*` requires independent post-review evidence and a Review Canvas.
- Files expected to change: `docs/harness/JSON_OUTPUTS.md` (new), `docs/harness/bin/doctor.sh` (flag parsing + JSON output), `docs/harness/README.md` (link to contract).

## Approaches Considered

| Approach | Why accepted or rejected |
|---|---|
| Text-only output stays | Rejected — human-readable lines are not machine-consumable; automation must scrape, which is fragile and breaks when message text changes. |
| JSON envelope `harness-json-v1` opt-in via `--json` flag; human default unchanged | Accepted — fully backward-compatible (existing callers unaffected), single JSON object to stdout, exit codes preserved, aligns with Engram contract. |
| Separate JSON tool (e.g. `doctor-json.sh`) | Rejected — duplicates all doctor logic; two scripts diverge over time; maintenance burden without benefit. |

## Hot Path Complexity

| Path | Time impact | Space impact | Notes |
|---|---|---|---|
| `doctor.sh --json` | O(n) checks, identical to human mode | O(n) failures buffer | JSON build is O(failures); number of failures is bounded by the fixed check list (~35 checks). |
| `doctor.sh` (human, unchanged) | No change | No change | Flag parsing adds one loop iteration per argument; negligible. |

## Edge Cases To Test Or Trace

| Edge case | Evidence command or manual trace |
|---|---|
| `--json` on a passing repo emits one JSON object with `status:"pass"`, exit 0 | `bash docs/harness/bin/doctor.sh --json \| python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='pass' and d['exit_code']==0; print('OK')"` |
| Human mode `doctor.sh` unchanged, same exit code as `--json` mode on clean repo | `bash docs/harness/bin/doctor.sh >/dev/null 2>&1; echo "human=$?"; bash docs/harness/bin/doctor.sh --json >/dev/null 2>&1; echo "json=$?"` — both must print `0` |
| Unknown flag `doctor.sh --bogus` exits 2 (usage error, stderr only) | `bash docs/harness/bin/doctor.sh --bogus; echo "exit=$?"` → `exit=2` |
| `failures[]` array correctly escapes a failure message containing a backslash and a double-quote | Trace: `esc="${m//\\/\\\\}"; esc="${esc//\"/\\\"}"` applied to `miss\ing "file"` produces `miss\\ing \"file\"` — valid JSON string content |

## Breakage Risk

| Risk | Impact | Mitigation | Rollback | Verification |
|---|---|---|---|---|
| JSON drift breaks a future consumer that expects exact field names | Consumer silently receives unexpected data or parse error | Field names locked by `JSON_OUTPUTS.md` contract; `schema_version` allows future breaking changes under a new version identifier | `git revert <commit>`; doctor reverts to text-only; no JSON consumers exist yet at time of writing | `bash docs/harness/bin/doctor.sh --json \| python3 -c "import sys,json; d=json.load(sys.stdin); assert d['schema_version']=='harness-json-v1'"` |
| Flag parsing rejects existing callers | Any `doctor.sh` invocation with unexpected args breaks | Only `--json` is accepted; no positional args existed before; `--bogus` exits 2 with usage message — callers that passed nothing still work | Remove the flag-parse `for` loop block from `doctor.sh` | `bash docs/harness/bin/doctor.sh; echo $?` → 0 |
| `JSON_FAILURES` pipe delimiter (`|`) collides with failure message text | Array splits incorrectly; failure string truncated or misattributed | All failure messages come from doctor's fixed `require_*` labels (short identifiers, no `|`); labels are controlled source | If collisions arise, replace delimiter with a NUL-separated approach; no rollback needed for existing messages | Review all `fail()` call sites in `doctor.sh` — none contain `|` |
| `require_file docs/harness/JSON_OUTPUTS.md` makes doctor fail before the file is committed | Doctor fails during the transition commit | File is created in the same commit as the `require_file` line; no window exists in which the check runs without the file | If accidentally split across commits, `git revert <partial commit>` and recommit together | `bash docs/harness/bin/doctor.sh` → PASS after both changes land |

## Decision

- Proceed / split / block: Proceed.
- Reason: The `--json` flag is purely additive and backward-compatible. The contract doc locks the field names so consumers can rely on them. Doctor self-registers the contract file so drift is caught automatically. All risks have low impact and clear rollback paths.
