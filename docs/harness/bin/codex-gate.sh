#!/usr/bin/env bash
# Compatibility wrapper for the generalized AgentShield review gate.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

REVIEWER_CLI="${REVIEWER_CLI:-codex}" exec bash docs/harness/bin/review-gate.sh "$@"
