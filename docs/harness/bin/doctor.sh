#!/usr/bin/env bash
# Validate AgentShield harness consistency.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

FAILURES=0

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

ok() {
  echo "OK: $*"
}

need_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    ok "command available: $1"
  else
    fail "required command not found: $1"
  fi
}

require_file() {
  if [ -f "$1" ]; then
    ok "file exists: $1"
  else
    fail "missing file: $1"
  fi
}

require_dir() {
  if [ -d "$1" ]; then
    ok "directory exists: $1"
  else
    fail "missing directory: $1"
  fi
}

require_executable() {
  if [ -x "$1" ]; then
    ok "executable: $1"
  else
    fail "not executable: $1"
  fi
}

require_match() {
  local label="$1"
  local pattern="$2"
  shift 2
  if rg -n -e "$pattern" "$@" >/dev/null 2>&1; then
    ok "$label"
  else
    fail "$label"
  fi
}

require_no_match() {
  local label="$1"
  local pattern="$2"
  shift 2
  local status
  rg -n -e "$pattern" "$@" >/dev/null 2>&1
  status=$?
  if [ "$status" -eq 1 ]; then
    ok "$label"
  else
    fail "$label"
  fi
}

need_cmd rg
need_cmd bash

require_file docs/harness/README.md
require_file docs/harness/SPEC.md
require_file docs/harness/INVARIANTS.md
require_file docs/harness/WHAT_WE_DONT_DO.md
require_file docs/harness/GATES.md
require_file docs/harness/CODE_REVIEW_POLICY.md
require_file docs/harness/VERIFICATION_MANIFEST.md
require_file docs/harness/progress.md
require_file docs/harness/progress/harness-foundation.md
require_file docs/harness/canvas/README.md
require_file docs/harness/canvas/TEMPLATE.md
require_file docs/harness/known-issues/README.md
require_file docs/harness/audits/.gitkeep
require_file docs/harness/reviews/.gitkeep
require_file docs/harness/canvas/.gitkeep

require_dir docs/harness/audits
require_dir docs/harness/reviews
require_dir docs/harness/canvas
require_dir docs/harness/progress
require_dir docs/harness/known-issues

for script in \
  docs/harness/bin/bootstrap.sh \
  docs/harness/bin/doctor.sh \
  docs/harness/bin/sensors.sh \
  docs/harness/bin/pr-title-policy.sh \
  docs/harness/bin/review-gate.sh \
  docs/harness/bin/codex-gate.sh \
  docs/harness/bin/baseline.sh \
  docs/harness/bin/quarterly-audit.sh; do
  require_file "$script"
  require_executable "$script"
  if bash -n "$script"; then
    ok "shell syntax: $script"
  else
    fail "shell syntax: $script"
  fi
done

require_match "bootstrap mentions WHAT_WE_DONT_DO.md" 'WHAT_WE_DONT_DO\.md' docs/harness/bin/bootstrap.sh
require_match "bootstrap mentions CODE_REVIEW_POLICY.md" 'CODE_REVIEW_POLICY\.md' docs/harness/bin/bootstrap.sh
require_match "README mentions WHAT_WE_DONT_DO.md" 'WHAT_WE_DONT_DO\.md' docs/harness/README.md
require_match "README mentions CODE_REVIEW_POLICY.md" 'CODE_REVIEW_POLICY\.md' docs/harness/README.md
require_match "README mentions Review Canvas" 'Review Canvas' docs/harness/README.md
require_match "README mentions doctor.sh" 'doctor\.sh' docs/harness/README.md
require_match "README mentions baseline.sh" 'baseline\.sh' docs/harness/README.md
require_match "README mentions quarterly-audit.sh" 'quarterly-audit\.sh' docs/harness/README.md
require_match "README lists full sensor" 'sensors\.sh full' docs/harness/README.md
require_match "README lists quick sensor" 'sensors\.sh quick' docs/harness/README.md
require_match "README lists mcp sensor" 'sensors\.sh mcp' docs/harness/README.md
require_match "README lists baseline sensor" 'sensors\.sh baseline' docs/harness/README.md

require_match "GATES mentions WHAT_WE_DONT_DO.md" 'WHAT_WE_DONT_DO\.md' docs/harness/GATES.md
require_match "GATES mentions Review Canvas" 'Review Canvas' docs/harness/GATES.md
require_match "GATES mentions baseline.sh" 'baseline\.sh' docs/harness/GATES.md
require_match "GATES mentions quarterly-audit.sh" 'quarterly-audit\.sh' docs/harness/GATES.md
require_match "GATES mentions mcp sensor" '\| `mcp` \|' docs/harness/GATES.md
require_match "GATES says optional lanes do not replace full gate" 'Optional sensor lanes are developer aids' docs/harness/GATES.md
require_match "GATES mentions docs/harness/bin" 'Changes to `docs/harness/bin/\*` require independent post-review evidence' docs/harness/GATES.md

require_match "CODE_REVIEW_POLICY mentions WHAT_WE_DONT_DO.md" 'WHAT_WE_DONT_DO\.md' docs/harness/CODE_REVIEW_POLICY.md
require_match "CODE_REVIEW_POLICY mentions Review Canvas" 'Review Canvas' docs/harness/CODE_REVIEW_POLICY.md
require_match "CODE_REVIEW_POLICY mentions harness script changes" 'Harness script changes' docs/harness/CODE_REVIEW_POLICY.md
require_match "CODE_REVIEW_POLICY mentions REVIEW_VERDICT" 'REVIEW_VERDICT' docs/harness/CODE_REVIEW_POLICY.md

require_match "review-gate mentions WHAT_WE_DONT_DO.md" 'WHAT_WE_DONT_DO\.md' docs/harness/bin/review-gate.sh
require_match "review-gate mentions Review Canvas" 'Review Canvas' docs/harness/bin/review-gate.sh
require_match "review-gate mentions docs/harness/bin" 'verify independent review evidence and inspect script behavior directly' docs/harness/bin/review-gate.sh
require_match "review-gate requires REVIEW_VERDICT" 'REVIEW_VERDICT' docs/harness/bin/review-gate.sh
require_match "codex-gate delegates to review-gate" 'review-gate\.sh' docs/harness/bin/codex-gate.sh

require_match "sensors mentions full" 'full\)' docs/harness/bin/sensors.sh
require_match "sensors mentions quick" 'quick\)' docs/harness/bin/sensors.sh
require_match "sensors mentions mcp" 'mcp\)' docs/harness/bin/sensors.sh
require_match "sensors mentions baseline" 'baseline\)' docs/harness/bin/sensors.sh
require_match "sensors runs doctor" 'doctor\.sh' docs/harness/bin/sensors.sh
require_match "sensors supports known issue flag" '--known-issue' docs/harness/bin/sensors.sh
require_match "sensors supports exclusion flag" '--exclude-sensor' docs/harness/bin/sensors.sh
require_match "PR title policy rejects codex marker" '\[codex\]' docs/harness/bin/pr-title-policy.sh
require_match "sensors runs PR title policy" 'pr-title-policy\.sh' docs/harness/bin/sensors.sh
require_match "README mentions PR title policy" 'PR title policy' docs/harness/README.md
require_match "GATES mentions PR title policy" 'PR title policy' docs/harness/GATES.md
require_match "CODE_REVIEW_POLICY mentions PR title policy" 'PR title policy' docs/harness/CODE_REVIEW_POLICY.md

require_no_match "GitHub workflows do not execute harness scripts" 'docs/harness/bin' .github/workflows

if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: AgentShield harness doctor"
  exit 0
fi

echo "FAIL: AgentShield harness doctor found $FAILURES issue(s)" >&2
exit 1
