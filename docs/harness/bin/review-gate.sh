#!/usr/bin/env bash
# General independent review gate for AgentShield.
#
# Usage:
#   bash docs/harness/bin/review-gate.sh pre  TASK-ID
#   bash docs/harness/bin/review-gate.sh post TASK-ID
#   bash docs/harness/bin/review-gate.sh post TASK-ID --range=main..HEAD
#
# Environment:
#   REVIEWER_CLI=codex
#   HARNESS_SCRIPT_REVIEW_EVIDENCE=docs/harness/reviews/<independent-review>.md

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-}"
TASK="${2:-}"
EXTRA="${3:-}"
REVIEWER_CLI="${REVIEWER_CLI:-codex}"

if [ -z "$MODE" ] || [ -z "$TASK" ]; then
  echo "Usage: $0 pre|post <task-id> [--range=<base>..<head>]" >&2
  exit 2
fi

RANGE=""
if [ -n "$EXTRA" ]; then
  case "$EXTRA" in
    --range=*)
      RANGE="${EXTRA#--range=}"
      if [ "$MODE" != "post" ] || [[ "$RANGE" != *..* ]]; then
        echo "ERROR: --range is only valid for post mode and must be <base>..<head>" >&2
        exit 2
      fi
      ;;
    *)
      echo "ERROR: unknown option: $EXTRA" >&2
      exit 2
      ;;
  esac
fi

if ! command -v "$REVIEWER_CLI" >/dev/null 2>&1; then
  echo "FAIL: reviewer CLI not found on PATH: $REVIEWER_CLI" >&2
  exit 3
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: rg not found: install ripgrep" >&2
  exit 3
fi

DATE="$(date -u +%Y-%m-%d)"
REVIEW_DIR="docs/harness/reviews"
mkdir -p "$REVIEW_DIR"

review_slug() {
  printf '%s' "$REVIEWER_CLI" | tr -c 'A-Za-z0-9_.-' '-'
}

changed_harness_scripts() {
  local dirty_non_review
  dirty_non_review="$(git status --porcelain -- ':(exclude)docs/harness/reviews/*' 2>/dev/null || true)"

  if [ -n "$RANGE" ]; then
    git diff --name-only "$RANGE" -- docs/harness/bin 2>/dev/null || true
  elif [ -n "$dirty_non_review" ]; then
    git status --porcelain -- docs/harness/bin 2>/dev/null || true
  else
    git show --name-only --format='' HEAD -- docs/harness/bin 2>/dev/null || true
  fi
}

require_harness_script_evidence() {
  local changed="$1"
  local evidence="${HARNESS_SCRIPT_REVIEW_EVIDENCE:-}"

  if [ -z "$changed" ]; then
    return 0
  fi

  if [ -z "$evidence" ]; then
    echo "FAIL: docs/harness/bin/* changed and requires independent post-review evidence." >&2
    printf '%s\n' "$changed" >&2
    echo "Set HARNESS_SCRIPT_REVIEW_EVIDENCE=<path> to an existing independent review artifact under docs/harness/reviews/ containing REVIEW_VERDICT: PASS." >&2
    exit 4
  fi

  if [ ! -f "$evidence" ]; then
    echo "FAIL: HARNESS_SCRIPT_REVIEW_EVIDENCE does not exist: $evidence" >&2
    exit 4
  fi

  case "$evidence" in
    docs/harness/reviews/*) ;;
    *)
      echo "FAIL: HARNESS_SCRIPT_REVIEW_EVIDENCE must live under docs/harness/reviews/: $evidence" >&2
      exit 4
      ;;
  esac

  case "$evidence" in
    *'/../'*|../*|*'/..')
      echo "FAIL: HARNESS_SCRIPT_REVIEW_EVIDENCE must not use path traversal: $evidence" >&2
      exit 4
      ;;
  esac

  if ! rg -n '^REVIEW_VERDICT:[[:space:]]*PASS[[:space:]]*$' "$evidence" >/dev/null 2>&1; then
    echo "FAIL: independent harness-script review evidence does not contain REVIEW_VERDICT: PASS: $evidence" >&2
    exit 4
  fi

  echo "OK: independent harness-script review evidence found: $evidence"
}

run_reviewer() {
  local prompt="$1"
  case "$REVIEWER_CLI" in
    codex)
      codex exec "$prompt"
      ;;
    *)
      "$REVIEWER_CLI" "$prompt"
      ;;
  esac
}

write_review() {
  local raw="$1"
  local out="$2"
  local kind="$3"
  local verdict_line

  verdict_line="$(grep -n -E '^REVIEW_VERDICT:[[:space:]]*(PASS|FAIL)[[:space:]]*$' "$raw" | tail -1 | cut -d: -f1)"
  {
    echo "# $(review_slug) $kind-gate review for $TASK"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Reviewer CLI: $REVIEWER_CLI"
    echo "Raw transcript: $out.raw"
    echo
    if [ -n "$verdict_line" ]; then
      awk -v start="$verdict_line" 'NR >= start' "$raw"
    else
      echo "REVIEW_VERDICT: FAIL"
      echo "[BLOCKER] Review output did not contain a parseable REVIEW_VERDICT marker."
    fi
  } > "$out"
}

parse_verdict() {
  grep -m1 -E '^REVIEW_VERDICT:[[:space:]]*(PASS|FAIL)[[:space:]]*$' "$1" |
    awk -F: '{ gsub(/[[:space:]]/, "", $2); print toupper($2) }'
}

case "$MODE" in
  pre)
    OUTFILE="$REVIEW_DIR/${DATE}-${TASK}-pre-$(review_slug).md"
    PROMPT="$(cat <<PROMPT_TEXT
You are an independent advisory reviewer for the AgentShield Rust security scanner.

Task ID: ${TASK}

Read and apply:
- docs/harness/SPEC.md
- docs/harness/INVARIANTS.md
- docs/harness/WHAT_WE_DONT_DO.md
- docs/harness/GATES.md
- docs/harness/CODE_REVIEW_POLICY.md
- active task context if visible in docs/harness/progress.md or docs/harness/progress/

Compare scope against docs/harness/WHAT_WE_DONT_DO.md.
Flag hidden scope creep, weakening of gates, or product changes bundled into harness work.

Find risks before implementation starts:
- scanner false negatives or false positives
- adapter-to-IR contract violations
- taint, sanitizer, or cross-file analysis mistakes
- SARIF 2.1.0 or GitHub Code Scanning compatibility drift
- JSON output drift that could break the VS Code extension
- CLI, baseline, suppression, certify, egress, or wrap behavior drift
- release workflow, GitHub Action, or docs mismatch
- offline-first/privacy regressions
- missing tests, fixtures, or fake-success paths
- scope creep against WHAT_WE_DONT_DO.md

If verification evidence is being claimed or skipped, consult docs/harness/VERIFICATION_MANIFEST.md and check that skipped checks are recorded explicitly.

If the planned work is complex, require a Review Canvas under docs/harness/canvas/ with approaches considered, complexity notes, at least two edge cases, and a breakage-risk table.

Do not flag docs/harness/reviews artifacts. Do not rewrite files.

Verdict format required:
One final verdict line exactly as REVIEW_VERDICT: PASS or REVIEW_VERDICT: FAIL.
Then bullets prefixed [BLOCKER], [HIGH], [MED], or [LOW].
PROMPT_TEXT
)"
    TMP_RAW="$(mktemp "${TMPDIR:-/tmp}/agentshield-review-gate-${TASK}.XXXXXX.raw")" || exit 3
    run_reviewer "$PROMPT" 2>&1 | tee "$TMP_RAW" >&2
    REVIEW_STATUS=${PIPESTATUS[0]}
    if [ "$REVIEW_STATUS" -ne 0 ]; then
      echo "FAIL: reviewer exited with status $REVIEW_STATUS; review not saved" >&2
      rm -f "$TMP_RAW"
      exit 1
    fi
    cp "$TMP_RAW" "$OUTFILE.raw"
    write_review "$TMP_RAW" "$OUTFILE" "pre"
    rm -f "$TMP_RAW"
    echo "Pre-gate saved to $OUTFILE"
    exit 0
    ;;

  post)
    CHANGED_HARNESS="$(changed_harness_scripts)"
    require_harness_script_evidence "$CHANGED_HARNESS"

    OUTFILE="$REVIEW_DIR/${DATE}-${TASK}-post-$(review_slug).md"
    EXCLUDE_PATHSPEC=":(exclude)docs/harness/reviews/*"
    DIRTY_NON_REVIEW="$(git status --porcelain -- ':(exclude)docs/harness/reviews/*' 2>/dev/null || true)"

    if [ -n "$RANGE" ]; then
      TARGET="commit range ${RANGE}; inspect with git diff ${RANGE} -- '${EXCLUDE_PATHSPEC}'"
    elif [ -n "$DIRTY_NON_REVIEW" ]; then
      TARGET="uncommitted non-review changes; inspect with git diff -- '${EXCLUDE_PATHSPEC}' and git diff --staged -- '${EXCLUDE_PATHSPEC}'"
    else
      TARGET="HEAD; inspect with git show HEAD -- '${EXCLUDE_PATHSPEC}'"
    fi

    PROMPT="$(cat <<PROMPT_TEXT
You are reviewing ${TARGET} for the AgentShield Rust security scanner.

Task ID: ${TASK}

Read and apply:
- docs/harness/SPEC.md
- docs/harness/INVARIANTS.md
- docs/harness/WHAT_WE_DONT_DO.md
- docs/harness/GATES.md
- docs/harness/CODE_REVIEW_POLICY.md

Compare scope against docs/harness/WHAT_WE_DONT_DO.md.
Flag hidden scope creep, weakening of gates, or product changes bundled into harness work.

Focus on real defects:
- scanner false negatives or false positives
- adapter-to-IR contract violations
- taint, sanitizer, or cross-file analysis mistakes
- SARIF 2.1.0 or GitHub Code Scanning compatibility regressions
- JSON output drift that could break the VS Code extension
- CLI, baseline, suppression, certify, egress, or wrap behavior regressions
- release workflow, GitHub Action, or docs mismatch
- offline-first/privacy regressions
- incorrect deletion of live detector, parser, adapter, fixture, or trust workflow code
- hidden scope creep against WHAT_WE_DONT_DO.md
- skipped verification omitted from progress or verification evidence

If verification evidence is being claimed or skipped, consult docs/harness/VERIFICATION_MANIFEST.md and ensure skipped checks are recorded explicitly.

If the diff is complex, verify that a matching Review Canvas exists under docs/harness/canvas/ and contains approaches considered, complexity notes, at least two edge cases, and a breakage-risk table.

Harness script changes are process-critical. If docs/harness/bin/* changed, verify independent review evidence and inspect script behavior directly.

Ignore docs/harness/reviews artifacts.

Verdict format required:
One final verdict line exactly as REVIEW_VERDICT: PASS or REVIEW_VERDICT: FAIL.
Then bullets prefixed [BLOCKER], [HIGH], [MED], or [LOW].
PROMPT_TEXT
)"

    TMP_RAW="$(mktemp "${TMPDIR:-/tmp}/agentshield-review-gate-${TASK}.XXXXXX.raw")" || exit 3
    run_reviewer "$PROMPT" 2>&1 | tee "$TMP_RAW" >&2
    REVIEW_STATUS=${PIPESTATUS[0]}
    if [ "$REVIEW_STATUS" -ne 0 ]; then
      echo "FAIL: reviewer exited with status $REVIEW_STATUS; review not saved" >&2
      rm -f "$TMP_RAW"
      exit 1
    fi
    cp "$TMP_RAW" "$OUTFILE.raw"
    write_review "$TMP_RAW" "$OUTFILE" "post"
    rm -f "$TMP_RAW"

    VERDICT="$(parse_verdict "$OUTFILE")"
    case "$VERDICT" in
      PASS)
        echo "OK: post-gate PASS ($OUTFILE)"
        exit 0
        ;;
      FAIL)
        echo "FAIL: post-gate returned FAIL. See $OUTFILE" >&2
        exit 1
        ;;
      *)
        echo "FAIL: post-gate output did not contain a parseable REVIEW_VERDICT. See $OUTFILE" >&2
        exit 1
        ;;
    esac
    ;;

  *)
    echo "Unknown mode: $MODE" >&2
    exit 2
    ;;
esac
