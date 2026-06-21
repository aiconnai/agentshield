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
      if [ "$#" -lt 2 ]; then
        echo "Usage: check-commit-msg.sh --message 'type(scope): subject'  or  path/to/COMMIT_EDITMSG" >&2
        exit 2
      fi
      MSG="$2"
      shift 2
      ;;
    *)
      if [ -f "$1" ]; then
        MSG="$(cat "$1")"
      else
        echo "ERROR: unknown argument or message file not found: $1" >&2
        echo "Usage: check-commit-msg.sh --message 'type(scope): subject'  or  path/to/COMMIT_EDITMSG" >&2
        exit 2
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
