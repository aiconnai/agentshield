#!/usr/bin/env bash
# Run release-readiness checks for AgentShield.
#
# Usage:
#   bash docs/harness/bin/release-checklist.sh <version> [--allow-untagged]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
ALLOW_UNTAGGED=false

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version> [--allow-untagged]" >&2
  exit 2
fi

shift
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-untagged)
      ALLOW_UNTAGGED=true
      shift
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      echo "Usage: $0 <version> [--allow-untagged]" >&2
      exit 2
      ;;
  esac
done

run() {
  local label="$1"
  shift
  echo "=== $label ==="
  "$@"
}

cargo_version() {
  awk '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ && in_package { exit }
    in_package && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' Cargo.toml
}

fallback_release_gate() {
  local actual
  local tag
  local tag_commit
  local head_commit

  actual="$(cargo_version)"
  if [ "$actual" != "$VERSION" ]; then
    echo "FAIL: Cargo.toml version is $actual, expected $VERSION" >&2
    exit 1
  fi
  echo "OK: Cargo.toml version matches $VERSION"

  tag="v$VERSION"
  if [ "$ALLOW_UNTAGGED" = false ]; then
    tag_commit="$(git rev-parse -q --verify "refs/tags/$tag^{commit}")" || {
      echo "FAIL: missing release tag $tag" >&2
      exit 1
    }
    head_commit="$(git rev-parse HEAD)"
    if [ "$tag_commit" != "$head_commit" ]; then
      echo "FAIL: tag $tag does not point to HEAD" >&2
      echo "tag:  $tag_commit" >&2
      echo "HEAD: $head_commit" >&2
      exit 1
    fi
    echo "OK: tag $tag points to HEAD"

    if [ -n "$(git status --porcelain)" ]; then
      echo "FAIL: worktree must be clean for final publish" >&2
      git status --short >&2
      exit 1
    fi
    echo "OK: worktree clean"
  else
    echo "OK: skipping tag and clean-worktree requirements for untagged preflight"
  fi
}

VC_GATE="docs/harness/bin/vc-gate.sh"
if [ -f "$VC_GATE" ]; then
  if [ "$ALLOW_UNTAGGED" = true ]; then
    run "vc-gate release preflight" bash "$VC_GATE" release "$VERSION" --allow-untagged
  else
    run "vc-gate release" bash "$VC_GATE" release "$VERSION"
  fi
else
  run "fallback release gate" fallback_release_gate
fi

RELEASE_INVARIANTS=".github/scripts/check-release-invariants.sh"
if [ -f "$RELEASE_INVARIANTS" ]; then
  run "release invariants" bash "$RELEASE_INVARIANTS" "v$VERSION"
fi

run "cargo fmt" cargo fmt --check
run "cargo clippy" cargo clippy -- -D warnings
run "cargo test" cargo test
run "cargo publish dry-run" cargo publish --dry-run

echo "PASS: release checklist completed for $VERSION"
