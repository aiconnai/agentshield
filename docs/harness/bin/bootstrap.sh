#!/usr/bin/env bash
# Print curated AgentShield harness context for a new session.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

repo_value() {
  local fallback="$1"
  shift
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/agentshield-bootstrap.XXXXXX")" || return 1
  if "$@" >"$tmp" 2>/dev/null; then
    cat "$tmp"
  else
    echo "$fallback"
  fi
  rm -f "$tmp"
}

echo "=== AgentShield harness state ==="
if command -v git >/dev/null 2>&1; then
  echo "Branch: $(repo_value unknown git branch --show-current)"
  echo "Last commit: $(repo_value none git log -1 --oneline)"
  dirty="$(git status --porcelain 2>/dev/null || true)"
  if [ -n "$dirty" ]; then
    echo "Working tree: dirty"
  else
    echo "Working tree: clean"
  fi
else
  echo "Branch: unknown (git not found)"
  echo "Last commit: unknown (git not found)"
  echo "Working tree: unknown (git not found)"
fi

echo
echo "--- Active progress ---"
if [ -f docs/harness/progress.md ]; then
  head -45 docs/harness/progress.md
else
  echo "(progress.md missing)"
fi

echo
echo "--- Last sensors run ---"
if [ -f docs/harness/.sensors-last ]; then
  cat docs/harness/.sensors-last
else
  echo "(never run)"
fi

echo
echo "--- Last baseline ---"
if [ -f docs/harness/.baseline-last ]; then
  head -25 docs/harness/.baseline-last
else
  echo "(never run)"
fi

echo
echo "--- Last quarterly audit ---"
if [ -f docs/harness/.quarterly-audit-last ]; then
  cat docs/harness/.quarterly-audit-last
else
  echo "(never run)"
fi

echo
echo "--- Last review artifact ---"
LATEST_REVIEW="$(ls -t docs/harness/reviews/*.md 2>/dev/null | head -1 || true)"
if [ -n "${LATEST_REVIEW:-}" ]; then
  echo "$LATEST_REVIEW"
else
  echo "(no reviews yet)"
fi

echo
echo "--- Mandatory read order ---"
echo "  docs/harness/SPEC.md"
echo "  docs/harness/INVARIANTS.md"
echo "  docs/harness/WHAT_WE_DONT_DO.md"
echo "  docs/harness/GATES.md"
echo "  docs/harness/CODE_REVIEW_POLICY.md"
echo "  docs/harness/progress.md"
echo "  active task or plan"
