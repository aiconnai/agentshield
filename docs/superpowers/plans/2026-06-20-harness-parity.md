# Harness Parity (AgentShield ⇄ Engram) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring both repos' agent harnesses to feature parity by cherry-picking each repo's strongest pieces into the other, adapting to each product — not by extracting a shared harness.

**Architecture:** Both harnesses already share one lineage (the `mbras-site` pattern: `SPEC → INVARIANTS → WHAT_WE_DONT_DO → GATES → CODE_REVIEW_POLICY → progress`, deterministic gates via `sensors.sh`, cross-model review via `review-gate.sh`, evidence via `canvas/ reviews/ audits/`). This plan ports missing, lineage-compatible pieces in both directions. Each task is an isolated, gated change.

**Tech Stack:** POSIX/bash scripts under `docs/harness/bin/`, markdown policy docs under `docs/harness/`, git hooks under `.githooks/`, Rust toolchain (`cargo fmt`/`clippy`/`test`).

## Global Constraints

- **Single-Process Judgment (INVARIANT, both repos):** the agent that writes a harness change is NOT its final judge. Every change to `docs/harness/bin/*` or harness policy docs requires an independent post-review (`review-gate.sh post <task-id>`) whose artifact carries a `REVIEW_VERDICT: PASS` line, written under `docs/harness/reviews/`.
- **Never edit a harness script in the same task that will use that script to gate itself.** Land the script change first, reviewed by the *prior* version of the gate, then use it. (`codex-as-reviewer.md`.)
- **Review Canvas required for complex changes** (200+ line diffs, gate changes, new external deps, schema changes): create `docs/harness/canvas/YYYY-MM-DD-<task>.md` from `TEMPLATE.md` before the post-review. Canvas is evidence, not approval.
- **All harness scripts:** `#!/usr/bin/env bash`, must pass `bash -n` (syntax), must be `chmod +x`, must be read-only at their default invocation, derive `REPO_ROOT` relative to `${BASH_SOURCE[0]}`.
- **`doctor.sh` is the source of truth for harness self-consistency.** After ANY harness change, `bash docs/harness/bin/doctor.sh` must exit 0. New files/scripts/cross-references MUST be registered in the relevant repo's `doctor.sh`, or it will (correctly) fail.
- **Conventional Commits, no `Co-authored-by: Claude/Anthropic` trailers** (enforced by `.githooks/commit-msg` in AgentShield).
- **AgentShield commit scopes (this plan's authority):** `adapter, detector, parser, analysis, output, ir, cli, rules, config, harness, ci, docs, vscode, action, release, infra, ibvi-[0-9]+`.
- **GitHub workflows must NOT execute `docs/harness/bin/*`** (AgentShield `doctor.sh` enforces this with `require_no_match`). Local gates stay local.
- **No `git add .`** — stage only the specific files a task touches.

---

## Direction & Sequencing

Two tracks, independent of each other. Within a track, tasks are ordered by dependency.

- **Track A — AgentShield gains from Engram** (the bigger gap): Tasks A1–A6.
- **Track B — Engram gains from AgentShield:** Tasks B1–B2.
- **Optional / larger** (explicitly out of the copy-port set): Task O1.

Per-task workflow for EVERY task below (the "gated loop"):

1. (If complex) create canvas from `docs/harness/canvas/TEMPLATE.md`.
2. Make the change + its tests.
3. `bash docs/harness/bin/doctor.sh` → must be `PASS`.
4. `bash docs/harness/bin/sensors.sh` (full) → must be `PASS` (or `quick` for docs-only tasks; full before merge).
5. `bash docs/harness/bin/review-gate.sh post <task-id>` → artifact with `REVIEW_VERDICT: PASS` under `docs/harness/reviews/`.
6. Update `docs/harness/progress.md`.
7. Commit specific files with a Conventional Commit message.

---

# Track A — AgentShield gains from Engram

### Task A1: Port `check-commit-msg.sh` (scope-validated commit checker)

AgentShield today only blocks `Co-authored-by` trailers (`.githooks/commit-msg`). It has no positive Conventional-Commit + scope validation. Engram has `check-commit-msg.sh`. Port it with **AgentShield scopes**.

**Files:**
- Create: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/check-commit-msg.sh`
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh` (register new script in the validation loop + add a `require_match` for AgentShield scopes)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/.githooks/commit-msg` (chain the new checker after the trailer block)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/GATES.md` (document the commit-message gate)

**Interfaces:**
- Consumes: nothing.
- Produces: `docs/harness/bin/check-commit-msg.sh` accepting `--message "<msg>"` OR a file path (git-hook style); exits `0` valid, `1` invalid format, `2` usage. Other tasks/hooks call it as `check-commit-msg.sh --message "..."`.

- [ ] **Step 1: Write the failing test (a shell assertion script run by hand)**

Create the checker's behavior contract as a throwaway test first. Run these exact commands and confirm they currently fail because the file does not exist:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/check-commit-msg.sh --message "feat(adapter): add cursor rules adapter"; echo "exit=$?"
```
Expected now: `bash: docs/harness/bin/check-commit-msg.sh: No such file or directory`, `exit=127`.

- [ ] **Step 2: Write `check-commit-msg.sh`** (adapted from Engram; AgentShield scopes)

```bash
#!/usr/bin/env bash
# docs/harness/bin/check-commit-msg.sh
#
# Lightweight Conventional Commit checker with AgentShield scopes.
# Used by .githooks/commit-msg and manually before `git commit`.

set -euo pipefail

MSG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --message)
      MSG="$2"
      shift 2
      ;;
    *)
      if [ -f "$1" ]; then
        MSG="$(cat "$1")"
      fi
      shift
      ;;
  esac
done

if [ -z "$MSG" ]; then
  echo "Usage: check-commit-msg.sh --message 'type(scope): subject'  or  path/to/COMMIT_EDITMSG" >&2
  exit 2
fi

CLEAN_MSG="$(printf '%s\n' "$MSG" | sed '/^#/d' | sed -n '1p')"
CLEAN_MSG="${CLEAN_MSG#"${CLEAN_MSG%%[![:space:]]*}"}"
CLEAN_MSG="${CLEAN_MSG%"${CLEAN_MSG##*[![:space:]]}"}"

TYPES='feat|fix|docs|refactor|test|perf|ci|chore|revert|style|build'
SCOPES='adapter|detector|parser|analysis|output|ir|cli|rules|config|harness|ci|docs|vscode|action|release|infra|ibvi-[0-9]+'

if echo "$CLEAN_MSG" | grep -qE "^(${TYPES})\((${SCOPES})\): .+"; then
  echo "OK commit message: $CLEAN_MSG"
  exit 0
else
  echo "FAIL commit message does not match required format."
  echo "Expected: type(scope): concise subject"
  echo "Allowed types: $TYPES"
  echo "Recommended scopes: adapter, detector, parser, analysis, output, ir, cli, rules, config, harness, ci, docs, vscode, action, release, or a task id (ibvi-488, etc.)"
  echo "Got: $CLEAN_MSG"
  exit 1
fi
```

- [ ] **Step 3: Make it executable and re-run the contract**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
chmod +x docs/harness/bin/check-commit-msg.sh
bash docs/harness/bin/check-commit-msg.sh --message "feat(adapter): add cursor rules adapter"; echo "exit=$?"
bash docs/harness/bin/check-commit-msg.sh --message "broken message"; echo "exit=$?"
bash docs/harness/bin/check-commit-msg.sh --message "feat(unknownscope): x"; echo "exit=$?"
```
Expected: first → `OK commit message: ...` `exit=0`; second → `FAIL ...` `exit=1`; third → `FAIL ...` `exit=1`.

- [ ] **Step 4: Chain it into `.githooks/commit-msg`** (append after the existing trailer block, before EOF)

Add to the END of `/Users/ronaldo/Projects/_aiconnai/agentshield/.githooks/commit-msg`:

```sh

# Validate Conventional Commit format + AgentShield scope.
if ! bash "$(dirname "$0")/../docs/harness/bin/check-commit-msg.sh" "$commit_msg_file"; then
  exit 1
fi
```

- [ ] **Step 5: Register the script in `doctor.sh`**

In `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh`, add `docs/harness/bin/check-commit-msg.sh \` to the `for script in \` list (the loop that does `require_file` + `require_executable` + `bash -n`). Then add this validation after the `PR title policy` matches block:

```bash
require_match "check-commit-msg lists adapter scope" 'adapter\|detector\|parser' docs/harness/bin/check-commit-msg.sh
require_match "GATES mentions commit message gate" 'check-commit-msg' docs/harness/GATES.md
```

- [ ] **Step 6: Document the gate in `GATES.md`**

Add a row/section to `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/GATES.md` under the commit/version-control gates describing: `check-commit-msg.sh --message "type(scope): subject"`, the allowed types/scopes, and that the `.githooks/commit-msg` hook runs it. Use exact scope list from Global Constraints.

- [ ] **Step 7: Run the gated loop (doctor → sensors → review-gate)**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post a1-check-commit-msg
```
Expected: `doctor=0`, `sensors=0`, and a review artifact `docs/harness/reviews/<date>-a1-check-commit-msg-*.md` with `REVIEW_VERDICT: PASS`.

- [ ] **Step 8: Update progress and commit**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
git add docs/harness/bin/check-commit-msg.sh .githooks/commit-msg docs/harness/bin/doctor.sh docs/harness/GATES.md docs/harness/progress.md
git commit -m "chore(harness): add scope-validated commit message checker"
```

---

### Task A2: Adopt `JSON_OUTPUTS.md` contract + `doctor.sh --json`

AgentShield gates are text-only. Engram defines `harness-json-v1` and emits it from `doctor.sh`/`sensors.sh status`. This is the highest-leverage item for making gates machine-consumable. Start with the contract doc + `doctor.sh --json`.

**Files:**
- Create: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/JSON_OUTPUTS.md`
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh` (add `--json` mode)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh` (self-register the JSON doc reference)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/README.md` (link the contract)

**Interfaces:**
- Consumes: nothing.
- Produces: `bash docs/harness/bin/doctor.sh --json` writes exactly one JSON object to stdout, exit code identical to human mode. Envelope: `schema_version="harness-json-v1"`, `tool="doctor"`, `mode="json"`, `status`, `exit_code`, `summary`, `failures` (array), `failure_count`. Later tasks (sensors `--json`) reuse this envelope.

- [ ] **Step 1: Copy the contract doc**

Copy `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/JSON_OUTPUTS.md` to `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/JSON_OUTPUTS.md`. Then edit: replace Engram-specific tool examples (`sensors.sh status`, engram check ids) with AgentShield's (`doctor`, `sensors` modes from `GATES.md`: `full, quick, docs, mcp, fixtures, sarif, action, release, vscode, baseline, audit`). Keep Global Rules, Status Vocabulary, Common Envelope verbatim.

- [ ] **Step 2: Write the failing check**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['schema_version'], d['tool'], d['status'])"
```
Expected now: doctor ignores `--json` (it has no flag parsing) and prints human lines → the python `json.load` fails / prints nothing. That failure is the RED.

- [ ] **Step 3: Add `--json` to `doctor.sh`**

In `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh`:

a) Right after `cd "$REPO_ROOT"`, add flag parsing and a failures accumulator:

```bash
JSON_MODE=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON_MODE=1 ;;
    *) echo "Usage: doctor.sh [--json]" >&2; exit 2 ;;
  esac
done

JSON_FAILURES=""
```

b) In the `fail()` function, also record the message for JSON (append after the existing `FAILURES=$((FAILURES + 1))`):

```bash
  JSON_FAILURES="${JSON_FAILURES}${JSON_FAILURES:+|}$*"
```

c) Suppress human `ok`/`fail` echoes when `JSON_MODE=1`. Change `ok()` and `fail()` to guard their `echo` with `[ "$JSON_MODE" -eq 0 ] && echo ...` (keep the `FAILURES`/`JSON_FAILURES` bookkeeping unconditional).

d) Replace the final pass/fail block with JSON-aware output:

```bash
if [ "$JSON_MODE" -eq 1 ]; then
  status="pass"; [ "$FAILURES" -ne 0 ] && status="fail"
  exit_code=0; [ "$FAILURES" -ne 0 ] && exit_code=1
  # build failures JSON array from JSON_FAILURES ('|'-separated)
  fjson=""
  if [ -n "$JSON_FAILURES" ]; then
    IFS='|' read -r -a _f <<< "$JSON_FAILURES"
    for m in "${_f[@]}"; do
      esc="${m//\\/\\\\}"; esc="${esc//\"/\\\"}"
      fjson="${fjson}${fjson:+,}\"${esc}\""
    done
  fi
  printf '{"schema_version":"harness-json-v1","tool":"doctor","mode":"json","status":"%s","exit_code":%d,"summary":"harness doctor %s","failures":[%s],"failure_count":%d}\n' \
    "$status" "$exit_code" "$status" "$fjson" "$FAILURES"
  exit "$exit_code"
fi

if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: AgentShield harness doctor"
  exit 0
fi
echo "FAIL: AgentShield harness doctor found $FAILURES issue(s)" >&2
exit 1
```

- [ ] **Step 4: Add the JSON doc to doctor's own validation**

In `doctor.sh`, add near the other `require_file` lines:

```bash
require_file docs/harness/JSON_OUTPUTS.md
```
and near README matches:
```bash
require_match "README mentions JSON outputs" 'JSON_OUTPUTS\.md' docs/harness/README.md
```

- [ ] **Step 5: Link the contract from README**

Add a short "Machine-readable output" subsection to `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/README.md` pointing to `JSON_OUTPUTS.md` and showing `bash docs/harness/bin/doctor.sh --json`.

- [ ] **Step 6: Verify GREEN**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh --json | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['schema_version']=='harness-json-v1' and d['tool']=='doctor'; print('OK', d['status'], d['failure_count'])"
echo "human-exit:"; bash docs/harness/bin/doctor.sh >/dev/null 2>&1; echo $?
echo "json-exit:"; bash docs/harness/bin/doctor.sh --json >/dev/null 2>&1; echo $?
```
Expected: `OK pass 0`; both exits identical (`0`).

- [ ] **Step 7: Gated loop + commit**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post a2-json-outputs
git add docs/harness/JSON_OUTPUTS.md docs/harness/bin/doctor.sh docs/harness/README.md docs/harness/progress.md
git commit -m "feat(harness): add harness-json-v1 contract and doctor --json mode"
```

---

### Task A3: Add `sensors.sh status --json`

Extends the A2 contract to sensors. Read-only snapshot of `.sensors-last` as `harness-json-v1`, so CI/loops can poll last-gate state without parsing text.

**Files:**
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/sensors.sh` (add `status --json` subcommand)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh` (add a `require_match` for the status subcommand)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/JSON_OUTPUTS.md` (document `sensors status` shape + `.sensors-last` relationship)

**Interfaces:**
- Consumes: `docs/harness/.sensors-last` (format `TIMESTAMP MODE PASS|FAIL`), `harness-json-v1` envelope from A2.
- Produces: `bash docs/harness/bin/sensors.sh status --json` → one JSON object: `tool="sensors"`, `mode="status"`, `status` (mapped from last result: PASS→`pass`, FAIL→`fail`, missing→`warn`), plus `last_timestamp`, `last_mode`. Read-only, exit `0`.

- [ ] **Step 1: Inspect the current `.sensors-last` format AND read Engram's reference implementation**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
cat docs/harness/.sensors-last 2>/dev/null || echo "(none yet)"
# Engram already implements `sensors.sh status --json` — port from it:
grep -n "status)" /Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/sensors.sh
```
Note the exact field order so the parser matches it; prefer Engram's `status` block shape as the template (adapt field order to AgentShield's `.sensors-last`).

- [ ] **Step 2: Write the failing check**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/sensors.sh status --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['tool'])"
```
Expected now: `status` is not a recognized mode → no valid JSON → python fails. RED.

- [ ] **Step 3: Add the `status` subcommand to `sensors.sh`**

At the START of `sensors.sh` argument handling (before the existing mode `case`), intercept `status`:

```bash
if [ "${1:-}" = "status" ]; then
  shift
  JSON=0; [ "${1:-}" = "--json" ] && JSON=1
  LAST_FILE="docs/harness/.sensors-last"
  ts=""; mode=""; res=""
  if [ -f "$LAST_FILE" ]; then
    read -r ts mode res < "$LAST_FILE" || true
  fi
  status="warn"
  case "$res" in PASS) status="pass" ;; FAIL) status="fail" ;; esac
  if [ "$JSON" -eq 1 ]; then
    printf '{"schema_version":"harness-json-v1","tool":"sensors","mode":"status","status":"%s","exit_code":0,"summary":"last sensors run: %s %s %s","last_timestamp":"%s","last_mode":"%s"}\n' \
      "$status" "${ts:-none}" "${mode:-none}" "${res:-none}" "${ts:-}" "${mode:-}"
  else
    echo "last sensors: ${ts:-none} ${mode:-none} ${res:-none}"
  fi
  exit 0
fi
```
(Adjust the `read` field order to match what Step 1 showed if it differs.)

- [ ] **Step 4: Register in `doctor.sh`**

```bash
require_match "sensors supports status subcommand" 'status\)' docs/harness/bin/sensors.sh
```
(If the literal differs from your implementation, match the actual token, e.g. `"status"`.)

- [ ] **Step 5: Document in `JSON_OUTPUTS.md`**

Add a "sensors status" section to `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/JSON_OUTPUTS.md` showing the object from Step 3 and noting it is read-only and reflects `.sensors-last`.

- [ ] **Step 6: Verify GREEN**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/sensors.sh quick >/dev/null 2>&1   # populate .sensors-last
bash docs/harness/bin/sensors.sh status --json | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['tool']=='sensors' and d['status'] in ('pass','warn','fail'); print('OK', d['status'])"
```
Expected: `OK pass` (or `warn` if `.sensors-last` was empty).

- [ ] **Step 7: Gated loop + commit**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post a3-sensors-status-json
git add docs/harness/bin/sensors.sh docs/harness/bin/doctor.sh docs/harness/JSON_OUTPUTS.md docs/harness/progress.md
git commit -m "feat(harness): add sensors status --json read-only snapshot"
```

---

### Task A4: Generalize `review-gate.sh` to multi-CLI + finding re-injection

AgentShield's `review-gate.sh` exists and `codex-gate.sh` wraps it, but Engram's version supports `REVIEWER_CLI=claude|grok|codex|ollama|manual` and re-injects prior `[BLOCKER]`/`[HIGH]` findings into the re-run after a FAIL (continuity with stable ids). This is the most behavior-heavy task — **canvas required**.

**Files:**
- Create: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/canvas/<date>-review-gate-multicli.md`
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/review-gate.sh`
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh` (validate new backends + re-injection markers)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/CODE_REVIEW_POLICY.md` (document multi-CLI selection)

**Interfaces:**
- Consumes: existing `review-gate.sh` prompt assembly; `REVIEWER_CLI` env (default `codex` to preserve current behavior).
- Produces: `REVIEWER_CLI` selects backend; `codex-gate.sh` still works unchanged (it sets `REVIEWER_CLI=codex`). On a re-run after FAIL, the prompt includes prior unresolved `[BLOCKER]`/`[HIGH]` findings under a stable heading.

- [ ] **Step 1: Create the canvas** from `docs/harness/canvas/TEMPLATE.md`. Capture: current behavior, target behavior, the diff of the two `review-gate.sh` versions (read `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/review-gate.sh`), edge cases (unknown `REVIEWER_CLI`, missing CLI binary, first run with no prior findings), and a risk table. This is required before any edit per Global Constraints.

- [ ] **Step 2: Read both versions side by side**

```bash
sed -n '1,400p' /Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/review-gate.sh
sed -n '1,400p' /Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/review-gate.sh
```
Identify: (a) the backend-dispatch block keyed on `REVIEWER_CLI`, (b) the prior-findings re-injection block. These are the two pieces to port.

- [ ] **Step 3: Add `REVIEWER_CLI` backend dispatch** to AgentShield's `review-gate.sh`, defaulting to `codex` so existing behavior is byte-compatible. Port Engram's `case "$REVIEWER_CLI" in claude|grok|codex|ollama|manual) ... esac` block, adapting binary names/flags to what's installed. Unknown value → exit `2` with a clear message.

- [ ] **Step 4: Port the finding re-injection block** — on `post` re-runs, scan the latest prior review artifact under `docs/harness/reviews/` for lines matching `^\[(BLOCKER|HIGH)\]` and prepend them to the prompt under a heading like `## Prior unresolved findings (address or refute)`.

- [ ] **Step 5: Register in `doctor.sh`**

```bash
require_match "review-gate supports REVIEWER_CLI" 'REVIEWER_CLI' docs/harness/bin/review-gate.sh
require_match "review-gate re-injects prior findings" 'Prior unresolved findings' docs/harness/bin/review-gate.sh
require_match "CODE_REVIEW_POLICY documents reviewer CLI" 'REVIEWER_CLI' docs/harness/CODE_REVIEW_POLICY.md
```

- [ ] **Step 6: Document in `CODE_REVIEW_POLICY.md`** — add a "Reviewer CLI selection" subsection listing the backends and the default (`codex`), and that `codex-gate.sh` is the back-compat wrapper.

- [ ] **Step 7: Verify back-compat + new path**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
# Back-compat: codex-gate still drives review-gate with codex
REVIEWER_CLI=manual bash docs/harness/bin/review-gate.sh pre a4-review-gate-multicli >/dev/null 2>&1; echo "manual-pre-exit=$?"
```
Expected: `doctor=0`; `manual` backend produces a prompt file / advisory output without error (`pre` always exits 0).

- [ ] **Step 8: Gated loop + commit** — because this is a harness-script change, the post-review must be done by a DIFFERENT CLI than the one that wrote it.

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/sensors.sh; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post a4-review-gate-multicli
git add docs/harness/bin/review-gate.sh docs/harness/bin/doctor.sh docs/harness/CODE_REVIEW_POLICY.md docs/harness/canvas/ docs/harness/progress.md
git commit -m "feat(harness): support multi-CLI reviewers and prior-finding re-injection"
```

---

### Task A5: Expand `doctor.sh` with drift / cross-reference validations from Engram

Engram's `doctor.sh` (23 KB) validates SPEC↔progress drift, active-plan existence, and that the latest review has a parseable `REVIEW_VERDICT`. AgentShield's (7.5 KB) does not. Port the *applicable* checks (not Engram-specific file names).

**Files:**
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh`

**Interfaces:**
- Consumes: `docs/harness/SPEC.md`, `docs/harness/progress.md`, `docs/harness/reviews/*`. Uses the existing `require_match`/`fail`/`ok` helpers already in AgentShield's doctor.
- Produces: additional FAIL conditions; no new public interface.

- [ ] **Step 1: Read Engram's drift checks**

```bash
grep -n "REVIEW_VERDICT\|active plan\|sprint\|drift\|sensors-last" /Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/doctor.sh
```
Pick the checks that map to AgentShield's docs (latest-review-has-verdict, `.sensors-last` format).

- [ ] **Step 2: Write the failing check** — temporarily corrupt a review artifact to prove the new check would catch it:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
ls docs/harness/reviews/*.md | tail -1
```
(Confirm at least one review exists to validate against; if not, the check should still pass vacuously — note that in the canvas-free reasoning.)

- [ ] **Step 3: Add "latest review carries REVIEW_VERDICT" check** to `doctor.sh`, after the existing `review-gate` matches:

```bash
LATEST_REVIEW="$(ls -1 docs/harness/reviews/*.md 2>/dev/null | sort | tail -1 || true)"
if [ -n "$LATEST_REVIEW" ]; then
  if rg -n -e '^REVIEW_VERDICT:[[:space:]]*(PASS|FAIL)\b' "$LATEST_REVIEW" >/dev/null 2>&1; then
    ok "latest review has REVIEW_VERDICT: $LATEST_REVIEW"
  else
    fail "latest review missing parseable REVIEW_VERDICT: $LATEST_REVIEW"
  fi
fi
```

- [ ] **Step 4: Add ".sensors-last format" check**:

```bash
if [ -f docs/harness/.sensors-last ]; then
  if rg -n -e '(PASS|FAIL)' docs/harness/.sensors-last >/dev/null 2>&1; then
    ok ".sensors-last has a result token"
  else
    fail ".sensors-last present but has no PASS/FAIL token"
  fi
fi
```

- [ ] **Step 5: Verify GREEN**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
```
Expected: `doctor=0` with new `OK:` lines for the latest review and `.sensors-last`.

- [ ] **Step 6: Gated loop + commit**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post a5-doctor-drift-checks
git add docs/harness/bin/doctor.sh docs/harness/progress.md
git commit -m "chore(harness): doctor validates review verdict and sensors-last format"
```

---

### Task A6: Reconcile `AGENTS.md` with `CLAUDE.md` (fix the v0.1.0 snapshot drift)

AgentShield's `AGENTS.md` is a v0.1.0 snapshot (missing 6 detectors, GPT Actions, Cursor Rules, `certify`); `CLAUDE.md` is current (v0.8.0). Make `AGENTS.md` either a thin pointer to `CLAUDE.md` or sync the diverged sections. **Docs-only task** (gate = `quick`).

**Files:**
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/AGENTS.md`

**Interfaces:**
- Consumes: `CLAUDE.md` content.
- Produces: an `AGENTS.md` consistent with v0.8.0.

- [ ] **Step 1: Diff the two files**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
diff <(sed -n '1,200p' AGENTS.md) <(sed -n '1,200p' CLAUDE.md) || true
```
Identify the diverged sections (detector count, adapter list, CLI commands, version table).

- [ ] **Step 2: Decide the model.** Recommended: make `AGENTS.md` a short header + "See `CLAUDE.md` for the authoritative project guide" pointer for the sections that duplicate, keeping only AGENTS-specific framing. This avoids re-drifting. (If you prefer a full copy, sync the diverged sections verbatim from `CLAUDE.md`.)

- [ ] **Step 3: Apply the edit** to `AGENTS.md` per Step 2.

- [ ] **Step 4: Verify no stale facts remain**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
grep -nE "12 detectors|v0\.1\.0|4 adapters" AGENTS.md || echo "no stale version facts"
```
Expected: `no stale version facts` (or only inside an explicit Version History row).

- [ ] **Step 5: Gated loop + commit**

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post a6-agents-md-reconcile
git add AGENTS.md docs/harness/progress.md
git commit -m "docs(harness): reconcile AGENTS.md with current CLAUDE.md (v0.8.0)"
```

---

# Track B — Engram gains from AgentShield

> **Working directory for Track B is `/Users/ronaldo/Projects/_aiconnai/engram/`.** Engram's commit scopes (from its `check-commit-msg.sh`): `harness|mcp|storage|search|intelligence|hooks|sdk-python|sdk-ts|cli|server|watcher|embedding|graph|sync|snapshot|attestation|ci|docs|infra|engra-[0-9]+|rfc-[0-9]+`. Engram's gated loop adds `vc-gate.sh` and uses `bash docs/harness/bin/check-commit-msg.sh --message "..."` before committing.

### Task B1: Port `pr-title-policy.sh` to Engram

Engram runs multi-CLI review (Grok/Codex/etc.), which is exactly where CLI-tagged titles like `[codex]` leak into PRs — yet Engram has no PR title gate. AgentShield's `pr-title-policy.sh` is product-agnostic and ports cleanly.

**Files:**
- Create: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/pr-title-policy.sh`
- Modify: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/doctor.sh` (register script + matches)
- Modify: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/sensors.sh` (run it in the appropriate lane, mirroring AgentShield)
- Modify: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/GATES.md` (document the gate)

**Interfaces:**
- Consumes: `gh` CLI (only for `--current-pr`), `PR_TITLE` env, or `--stdin`.
- Produces: `pr-title-policy.sh --title <t> | --current-pr | --stdin`; exit `4` if title contains `[codex]`, `0` if OK, `2` usage, `3` missing `gh`.

- [ ] **Step 1: Copy the script verbatim**

Copy `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/pr-title-policy.sh` → `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/pr-title-policy.sh`. It derives `REPO_ROOT` relative to `BASH_SOURCE`, so no path edits are needed. `chmod +x` it.

- [ ] **Step 2: Verify behavior (RED→GREEN in one shot since it's a verbatim port)**

```bash
cd /Users/ronaldo/Projects/_aiconnai/engram
chmod +x docs/harness/bin/pr-title-policy.sh
bash docs/harness/bin/pr-title-policy.sh --title "feat(mcp): add tool"; echo "exit=$?"
bash docs/harness/bin/pr-title-policy.sh --title "[codex] feat(mcp): add tool"; echo "exit=$?"
```
Expected: first → `OK: PR title policy` `exit=0`; second → `FAIL: PR title must not contain [codex]` `exit=4`.

- [ ] **Step 3: Register in Engram's `doctor.sh`** — add the script to its required-scripts loop (find the equivalent loop) and add matches:

```bash
require_match "PR title policy rejects codex marker" '\[codex\]' docs/harness/bin/pr-title-policy.sh
require_match "GATES mentions PR title policy" 'PR title policy' docs/harness/GATES.md
```

- [ ] **Step 4: Wire into `sensors.sh`** — mirror AgentShield: invoke `pr-title-policy.sh` with `--current-pr` (guarded so it no-ops when `gh`/PR is absent) in the same lane AgentShield uses. Read AgentShield's `sensors.sh` for the exact invocation guard:

```bash
grep -n "pr-title-policy" /Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/sensors.sh
```
Port that guarded block.

- [ ] **Step 5: Document in Engram `GATES.md`** — add a PR-title-policy section describing the `[codex]` rejection and the three input modes.

- [ ] **Step 6: Gated loop + commit (Engram flow)**

```bash
cd /Users/ronaldo/Projects/_aiconnai/engram
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post b1-pr-title-policy
bash docs/harness/bin/check-commit-msg.sh --message "chore(harness): add PR title policy gate"
git add docs/harness/bin/pr-title-policy.sh docs/harness/bin/doctor.sh docs/harness/bin/sensors.sh docs/harness/GATES.md docs/harness/progress.md
git commit -m "chore(harness): add PR title policy gate"
```

---

### Task B2: Port AgentShield's loop-engineering skill family + `SKILLS.md` promotion policy to Engram

AgentShield has a richer loop discipline: `loop-engineering` (shared safety model: repeatable/observable/resumable, L1 report-only / L2 only-with-verifier), plus `loop-triage`, `loop-triage-ci`, `dependency-triage`, `pr-review-triage`, governed by `docs/harness/SKILLS.md` with a canvas-gated promotion policy. Engram has only 3 skills and no `SKILLS.md`. Port the **policy + the `loop-engineering` base skill** (the others are optional follow-ups).

**Files:**
- Create: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/SKILLS.md`
- Create: `/Users/ronaldo/Projects/_aiconnai/engram/skills/loop-engineering/SKILL.md`
- Modify: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/bin/doctor.sh` (inventory + skill-frontmatter validation, mirroring AgentShield)
- Modify: `/Users/ronaldo/Projects/_aiconnai/engram/docs/harness/README.md` (link SKILLS.md)

**Interfaces:**
- Consumes: nothing (policy + skill docs).
- Produces: `docs/harness/SKILLS.md` inventory; `skills/loop-engineering/SKILL.md` with `name:`/`description:` frontmatter; doctor enforces every `skills/*/SKILL.md` is tracked, name-matches its dir, and is inventoried.

- [ ] **Step 1: Read the source skill + policy**

```bash
cat /Users/ronaldo/Projects/_aiconnai/agentshield/skills/loop-engineering/SKILL.md
cat /Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/SKILLS.md
```

- [ ] **Step 2: Create `skills/loop-engineering/SKILL.md`** in Engram — copy AgentShield's content, adapting product references (AgentShield scanner → Engram MCP/memory loops; e.g. the existing `agentshield-scan` and `engram-council` loops become the worked examples). Keep the L1/L2 safety model and frontmatter (`name: loop-engineering`, `description: ...`) intact.

- [ ] **Step 3: Create `docs/harness/SKILLS.md`** in Engram — port AgentShield's structure: inventory table of `skills/*` (now including `agentshield-scan`, `engram-council`, `engram-onboarding`, `loop-engineering`), the promotion policy (new/loop/gate/automation-affecting skill requires a canvas), and the personal-skill-location note adapted to Engram's CLIs.

- [ ] **Step 4: Port the skill-validation block to Engram `doctor.sh`** — copy AgentShield's `find skills -mindepth 2 -maxdepth 2 -name SKILL.md` loop and the untracked-skills check. Read it from:

```bash
grep -n "skills/\*/SKILL.md\|UNTRACKED_SKILLS\|skill has matching name\|is inventoried" /Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/doctor.sh
```
Add equivalents. Also `require_file docs/harness/SKILLS.md` and a README match.

- [ ] **Step 5: Verify GREEN**

```bash
cd /Users/ronaldo/Projects/_aiconnai/engram
bash docs/harness/bin/doctor.sh; echo "doctor=$?"
```
Expected: `doctor=0`, with new `OK:` lines that each `skills/*/SKILL.md` (including the 3 existing) is tracked, name-matches, and is inventoried in `SKILLS.md`. (Verified at plan time: the 3 existing Engram skills — `agentshield-scan`, `engram-council`, `engram-onboarding` — already have `name:` matching their dirs, so only the new `loop-engineering` and the `SKILLS.md` inventory rows are new work.)

- [ ] **Step 6: Gated loop + commit (Engram flow)**

```bash
cd /Users/ronaldo/Projects/_aiconnai/engram
bash docs/harness/bin/sensors.sh quick; echo "sensors=$?"
bash docs/harness/bin/review-gate.sh post b2-loop-skills-policy
bash docs/harness/bin/check-commit-msg.sh --message "docs(harness): add SKILLS.md policy and loop-engineering skill"
git add docs/harness/SKILLS.md skills/loop-engineering/SKILL.md docs/harness/bin/doctor.sh docs/harness/README.md docs/harness/progress.md
git commit -m "docs(harness): add SKILLS.md policy and loop-engineering skill"
```

---

# Optional / larger (out of the copy-port set)

### Task O1 (optional): Local CI entrypoint + `ci-parity-check.sh` for AgentShield

AgentShield has no `justfile`/`Makefile`; CI runs `cargo` directly in `ci.yml`. Engram's `ci-parity-check.sh` only makes sense once a local `just ci`/`make ci` entrypoint exists that mirrors the workflow. This is an **addition**, not a copy-port, and is the only task that touches build orchestration — keep it separate and optional.

**Files:**
- Create: `/Users/ronaldo/Projects/_aiconnai/agentshield/justfile` (or `Makefile`)
- Create: `/Users/ronaldo/Projects/_aiconnai/agentshield/scripts/ci.sh`
- Create: `/Users/ronaldo/Projects/_aiconnai/agentshield/scripts/ci-parity-check.sh`
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/.githooks/pre-commit` (create it; AgentShield currently has no pre-commit hook — prefer `just pre-commit`, fall back to `cargo fmt --check` + `clippy`)
- Modify: `/Users/ronaldo/Projects/_aiconnai/agentshield/docs/harness/bin/sensors.sh` (route `full` through `just ci`/`scripts/ci.sh` instead of inline cargo, IFF you adopt this)

**Interfaces:**
- Consumes: `ci.yml` job definitions (to mirror them).
- Produces: `just ci` (== the GitHub gate), `scripts/ci-parity-check.sh` (fails on drift between `ci.yml` and `scripts/ci.sh`).

- [ ] **Step 1: Decide scope with the user first.** This changes how `sensors.sh full` runs. Do NOT start without confirming, since it alters the canonical gate's internals. Brainstorm via `superpowers:brainstorming` before planning the sub-steps.

- [ ] **Step 2 (if approved):** Mirror `ci.yml` jobs (`cargo test --all-features`, `cargo clippy --all-features -- -D warnings`, `cargo fmt --check`, the smoke steps) into `scripts/ci.sh`; expose `just ci` → `scripts/ci.sh`; write `ci-parity-check.sh` comparing the two; then re-point `sensors.sh full`. Each gets its own gated loop + canvas (it's a gate change).

---

## Self-Review

**Spec coverage** — every gap from the comparison maps to a task:

| Comparison gap | Direction | Task |
|---|---|---|
| Scope-validated commit checker | E→AS | A1 |
| `JSON_OUTPUTS.md` contract | E→AS | A2 |
| `doctor --json` | E→AS | A2 |
| `sensors status --json` | E→AS | A3 |
| Multi-CLI reviewers + finding re-injection | E→AS | A4 |
| Bigger `doctor.sh` (drift/verdict checks) | E→AS | A5 |
| `AGENTS.md` v0.1.0 drift | internal AS | A6 |
| `pr-title-policy.sh` | AS→E | B1 |
| loop-engineering family + `SKILLS.md` policy | AS→E | B2 |
| `vc-gate.sh` | E→AS | **deferred** — AS already has `release-checklist.sh`; the user opted for copy-port low-risk first. Not in this plan; revisit after A1–A6. |
| `lib.sh` | E→AS | **folded** — trivial single helper; port only if a future task needs `field_value`. Not standalone. |
| Local CI entrypoint + parity check | E→AS | O1 (optional) |
| Multi-CLI config files (`.aider.conf.yml`, `.gemini/`) | E→AS | **deferred** — cosmetic signal; low value, revisit later. |

**Placeholder scan:** every code step contains the actual script body, edit, or exact command + expected output. Backend binary names in A4 are intentionally left to the implementer to match installed CLIs (documented as such), not a placeholder.

**Type/name consistency:** envelope `schema_version="harness-json-v1"`, `tool` values (`doctor`, `sensors`), and the `--json`/`status` interfaces introduced in A2 are reused consistently in A3. Task ids (`a1-...`, `b1-...`) are used consistently in each task's `review-gate.sh post` call and commit.

**Note on review independence (A4 especially):** any task editing a harness script must be post-reviewed by a CLI/model different from the one that wrote it (Single-Process Judgment). For A4, do not let the same agent that ported the multi-CLI dispatch also sign its `REVIEW_VERDICT`.
