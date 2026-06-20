#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

usage() {
  echo "Usage: $0 --title <title> | --current-pr | --stdin" >&2
}

reject_if_disallowed() {
  local title="$1"

  if printf '%s\n' "$title" | grep -Eiq '\[[[:space:]]*codex[[:space:]]*\]'; then
    echo "FAIL: PR title must not contain [codex]" >&2
    exit 4
  fi

  echo "OK: PR title policy"
}

TITLE=""
READ_STDIN=0
CURRENT_PR=0
SOURCE_COUNT=0

if [ $# -eq 0 ] && [ -n "${PR_TITLE:-}" ]; then
  TITLE="$PR_TITLE"
  SOURCE_COUNT=1
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --title)
      if [ $# -lt 2 ]; then
        usage
        exit 2
      fi
      TITLE="${2:-}"
      SOURCE_COUNT=$((SOURCE_COUNT + 1))
      shift 2
      ;;
    --current-pr)
      CURRENT_PR=1
      SOURCE_COUNT=$((SOURCE_COUNT + 1))
      shift
      ;;
    --stdin)
      READ_STDIN=1
      SOURCE_COUNT=$((SOURCE_COUNT + 1))
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [ "$SOURCE_COUNT" -ne 1 ]; then
  usage
  exit 2
fi

if [ "$CURRENT_PR" -eq 1 ]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "FAIL: gh is required for --current-pr" >&2
    exit 3
  fi
  TITLE="$(gh pr view --json title --jq .title)"
fi

if [ "$READ_STDIN" -eq 1 ]; then
  TITLE="$(cat)"
fi

if [ -z "$TITLE" ]; then
  usage
  exit 2
fi

reject_if_disallowed "$TITLE"
