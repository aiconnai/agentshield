#!/usr/bin/env bash
# General independent review gate for AgentShield.
#
# Usage:
#   bash docs/harness/bin/review-gate.sh pre  TASK-ID
#   bash docs/harness/bin/review-gate.sh post TASK-ID
#   bash docs/harness/bin/review-gate.sh post TASK-ID --range=main..HEAD
#   REVIEWER_CLI=manual bash docs/harness/bin/review-gate.sh post TASK-ID --review-file=path/to/review.md
#
# Environment:
#   REVIEWER_CLI=codex
#   REVIEWER_RETRY_ATTEMPTS=3
#   HARNESS_SCRIPT_REVIEW_EVIDENCE=docs/harness/reviews/<independent-review>.md

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-}"
TASK="${2:-}"
REVIEWER_CLI="${REVIEWER_CLI:-codex}"
REVIEWER_RETRY_ATTEMPTS="${REVIEWER_RETRY_ATTEMPTS:-3}"
REVIEW_FILE=""

if [ -z "$MODE" ] || [ -z "$TASK" ]; then
  echo "Usage: $0 pre|post <task-id> [--range=<base>..<head>] [--review-file=<path>]" >&2
  exit 2
fi

RANGE=""
shift 2
for EXTRA in "$@"; do
  case "$EXTRA" in
    --range=*)
      RANGE="${EXTRA#--range=}"
      if [ "$MODE" != "post" ] || [[ "$RANGE" != *..* ]]; then
        echo "ERROR: --range is only valid for post mode and must be <base>..<head>" >&2
        exit 2
      fi
      ;;
    --review-file=*)
      REVIEW_FILE="${EXTRA#--review-file=}"
      ;;
    *)
      echo "ERROR: unknown option: $EXTRA" >&2
      exit 2
      ;;
  esac
done

case "$REVIEWER_RETRY_ATTEMPTS" in
  ''|*[!0-9]*)
    echo "ERROR: REVIEWER_RETRY_ATTEMPTS must be a positive integer" >&2
    exit 2
    ;;
esac
if [ "$REVIEWER_RETRY_ATTEMPTS" -lt 1 ]; then
  echo "ERROR: REVIEWER_RETRY_ATTEMPTS must be a positive integer" >&2
  exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: rg not found: install ripgrep" >&2
  exit 3
fi

validate_reviewer_backend() {
  case "$REVIEWER_CLI" in
    codex)
      if ! command -v codex >/dev/null 2>&1; then
        echo "FAIL: reviewer CLI not found on PATH: codex" >&2
        exit 3
      fi
      ;;
    manual)
      ;;
    claude|grok|ollama)
      echo "ERROR: REVIEWER_CLI=$REVIEWER_CLI is not supported by this harness yet; supply a verified backend implementation before using it." >&2
      exit 2
      ;;
    *)
      echo "ERROR: unknown REVIEWER_CLI: $REVIEWER_CLI (supported: codex, manual; reserved but unsupported: claude, grok, ollama)" >&2
      exit 2
      ;;
  esac
}

validate_reviewer_backend

if [ -n "$REVIEW_FILE" ] && { [ "$MODE" != "post" ] || [ "$REVIEWER_CLI" != "manual" ]; }; then
  echo "ERROR: --review-file is only valid for REVIEWER_CLI=manual post mode" >&2
  exit 2
fi

if [ "$REVIEWER_CLI" = "manual" ] && [ "$MODE" = "post" ] && [ -z "$REVIEW_FILE" ]; then
  echo "ERROR: REVIEWER_CLI=manual post requires --review-file=<path> with a reviewer artifact containing REVIEW_VERDICT" >&2
  exit 2
fi

DATE="$(date -u +%Y-%m-%d)"
REVIEW_DIR="docs/harness/reviews"
mkdir -p "$REVIEW_DIR"

task_slug() {
  printf '%s' "$TASK" | tr -c 'A-Za-z0-9_.-' '-'
}

review_slug() {
  printf '%s' "$REVIEWER_CLI" | tr -c 'A-Za-z0-9_.-' '-'
}

write_file_atomically() {
  local out="$1"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/agentshield-review-gate-write.XXXXXX")" || return 1
  if ! cat > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv "$tmp" "$out"; then
    rm -f "$tmp"
    return 1
  fi
  [ -f "$out" ]
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
  local attempt=1
  local output=""
  local status=0

  while [ "$attempt" -le "$REVIEWER_RETRY_ATTEMPTS" ]; do
    output="$(run_reviewer_once "$prompt" 2>&1)"
    status=$?
    if [ -n "$output" ]; then
      printf '%s\n' "$output"
      return "$status"
    fi

    if [ "$attempt" -lt "$REVIEWER_RETRY_ATTEMPTS" ]; then
      echo "WARN: reviewer produced empty output; retrying attempt $((attempt + 1)) of $REVIEWER_RETRY_ATTEMPTS" >&2
    fi
    attempt=$((attempt + 1))
  done

  return "$status"
}

run_reviewer_once() {
  local prompt="$1"
  case "$REVIEWER_CLI" in
    codex)
      # Pass the prompt via stdin: codex-cli 0.140.0 intermittently treats a
      # large positional prompt as a request to read more input from stdin and
      # then exits with empty output. Piping the prompt avoids that path.
      printf '%s' "$prompt" | codex exec --sandbox read-only -C "$REPO_ROOT" -
      ;;
    manual)
      echo "ERROR: manual reviewer backend is artifact-driven and cannot run automated review" >&2
      return 2
      ;;
  esac
}

write_manual_prompt() {
  local prompt="$1"
  local out="$2"
  local kind="$3"

  if ! {
    echo "# manual $kind-gate advisory prompt for $TASK"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Reviewer CLI: manual"
    echo
    echo "This artifact is an advisory prompt for a human or external reviewer."
    echo "It is not an automated review result and does not contain a harness verdict."
    echo
    echo '```text'
    printf '%s\n' "$prompt"
    echo '```'
  } | write_file_atomically "$out"; then
    echo "ERROR: failed to write manual $kind-gate prompt artifact: $out" >&2
    return 1
  fi
}

write_manual_review() {
  local review_file="$1"
  local out="$2"
  local kind="$3"

  if [ ! -f "$review_file" ]; then
    echo "ERROR: --review-file does not exist: $review_file" >&2
    exit 2
  fi

  if ! grep -E '^REVIEW_VERDICT:[[:space:]]*(PASS|FAIL)[[:space:]]*$' "$review_file" >/dev/null 2>&1; then
    echo "ERROR: --review-file must contain REVIEW_VERDICT: PASS or REVIEW_VERDICT: FAIL: $review_file" >&2
    exit 2
  fi

  cp "$review_file" "$out.raw"
  write_review "$out.raw" "$out" "$kind"
}

prior_unresolved_findings() {
  local prior=""
  local findings=""

  prior="$(find "$REVIEW_DIR" -maxdepth 1 -type f -name "*-$(task_slug)-post-*.md" ! -name "*.raw" -print 2>/dev/null | sort | tail -n 1)"
  if [ -n "$prior" ]; then
    findings="$(rg -N '^[[:space:]]*([-*][[:space:]]*)?\[(BLOCKER|HIGH)\]' "$prior" 2>/dev/null || true)"
  fi

  echo "## Prior unresolved findings (address or refute)"
  echo
  if [ -n "$findings" ]; then
    printf '%s\n' "$findings"
  else
    echo "- None found in prior review artifacts for this task."
  fi
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
  } | write_file_atomically "$out"
}

save_reviewer_artifacts() {
  local raw="$1"
  local out="$2"
  local kind="$3"

  if ! cp "$raw" "$out.raw"; then
    echo "FAIL: could not save raw reviewer transcript: $out.raw" >&2
    return 1
  fi
  if ! write_review "$raw" "$out" "$kind"; then
    echo "FAIL: could not save wrapped reviewer artifact: $out" >&2
    rm -f "$out.raw"
    return 1
  fi
  [ -f "$out" ] && [ -f "$out.raw" ]
}

parse_verdict() {
  grep -m1 -E '^REVIEW_VERDICT:[[:space:]]*(PASS|FAIL)[[:space:]]*$' "$1" |
    awk -F: '{ gsub(/[[:space:]]/, "", $2); print toupper($2) }'
}

case "$MODE" in
  pre)
    OUTFILE="$REVIEW_DIR/${DATE}-$(task_slug)-pre-$(review_slug).md"
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
    if [ "$REVIEWER_CLI" = "manual" ]; then
      write_manual_prompt "$PROMPT" "$OUTFILE" "pre" || exit 1
      echo "Manual pre-gate advisory prompt saved to $OUTFILE"
      exit 0
    fi

    TMP_RAW="$(mktemp "${TMPDIR:-/tmp}/agentshield-review-gate-$(task_slug).XXXXXX.raw")" || exit 3
    run_reviewer "$PROMPT" 2>&1 | tee "$TMP_RAW" >&2
    REVIEW_STATUS=${PIPESTATUS[0]}
    if ! save_reviewer_artifacts "$TMP_RAW" "$OUTFILE" "pre"; then
      rm -f "$TMP_RAW"
      exit 1
    fi
    rm -f "$TMP_RAW"
    if [ "$REVIEW_STATUS" -ne 0 ]; then
      echo "FAIL: reviewer exited with status $REVIEW_STATUS; review saved to $OUTFILE" >&2
      exit 1
    fi
    echo "Pre-gate saved to $OUTFILE"
    exit 0
    ;;

  post)
    CHANGED_HARNESS="$(changed_harness_scripts)"
    require_harness_script_evidence "$CHANGED_HARNESS"

    OUTFILE="$REVIEW_DIR/${DATE}-$(task_slug)-post-$(review_slug).md"
    EXCLUDE_PATHSPEC=":(exclude)docs/harness/reviews/*"
    DIRTY_NON_REVIEW="$(git status --porcelain -- ':(exclude)docs/harness/reviews/*' 2>/dev/null || true)"

    if [ -n "$RANGE" ]; then
      TARGET="commit range ${RANGE}; inspect with git diff ${RANGE} -- '${EXCLUDE_PATHSPEC}'"
    elif [ -n "$DIRTY_NON_REVIEW" ]; then
      TARGET="uncommitted non-review changes; inspect with git diff -- '${EXCLUDE_PATHSPEC}' and git diff --staged -- '${EXCLUDE_PATHSPEC}'"
    else
      TARGET="HEAD; inspect with git show HEAD -- '${EXCLUDE_PATHSPEC}'"
    fi
    PRIOR_FINDINGS="$(prior_unresolved_findings)"

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

${PRIOR_FINDINGS}

Verdict format required:
One final verdict line exactly as REVIEW_VERDICT: PASS or REVIEW_VERDICT: FAIL.
Then bullets prefixed [BLOCKER], [HIGH], [MED], or [LOW].
PROMPT_TEXT
)"

    if [ "$REVIEWER_CLI" = "manual" ]; then
      write_manual_review "$REVIEW_FILE" "$OUTFILE" "post"

      VERDICT="$(parse_verdict "$OUTFILE")"
      case "$VERDICT" in
        PASS)
          echo "OK: manual post-gate PASS ($OUTFILE)"
          exit 0
          ;;
        FAIL)
          echo "FAIL: manual post-gate returned FAIL. See $OUTFILE" >&2
          exit 1
          ;;
      esac
    fi

    TMP_RAW="$(mktemp "${TMPDIR:-/tmp}/agentshield-review-gate-$(task_slug).XXXXXX.raw")" || exit 3
    run_reviewer "$PROMPT" 2>&1 | tee "$TMP_RAW" >&2
    REVIEW_STATUS=${PIPESTATUS[0]}
    if ! save_reviewer_artifacts "$TMP_RAW" "$OUTFILE" "post"; then
      rm -f "$TMP_RAW"
      exit 1
    fi
    rm -f "$TMP_RAW"
    VERDICT="$(parse_verdict "$OUTFILE")"
    if [ "$REVIEW_STATUS" -ne 0 ]; then
      echo "FAIL: reviewer exited with status $REVIEW_STATUS; review saved to $OUTFILE; parsed verdict: ${VERDICT:-none}" >&2
      exit 1
    fi

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
