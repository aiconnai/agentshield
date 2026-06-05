#!/usr/bin/env bash
# Capture lightweight AgentShield scanner and release-surface metrics.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT="docs/harness/.baseline-last"
TMP="$(mktemp "${TMPDIR:-/tmp}/agentshield-baseline.XXXXXX")" || exit 3

cleanup() {
  rm -f "${TMP:-}"
}
trap cleanup EXIT

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "FAIL: required command not found: $1" >&2
    exit 127
  fi
}

count_lines() {
  find "$@" -type f -name '*.rs' -print0 2>/dev/null |
    xargs -0 wc -l 2>/dev/null |
    awk 'END { print $1 + 0 }'
}

count_files() {
  find "$@" -type f -name '*.rs' 2>/dev/null | wc -l | tr -d ' '
}

count_rg() {
  local pattern="$1"
  shift
  rg -n "$pattern" "$@" 2>/dev/null | wc -l | tr -d ' '
}

need rg

branch="$(git branch --show-current 2>/dev/null || true)"
commit="$(git log -1 --format=%H 2>/dev/null || true)"
if [ -n "$(git status --porcelain 2>/dev/null || true)" ]; then
  dirty="yes"
else
  dirty="no"
fi

rust_files="$(count_files src tests benches)"
rust_loc="$(count_lines src tests benches)"
adapter_modules="$(find src/adapter -maxdepth 1 -type f -name '*.rs' ! -name mod.rs 2>/dev/null | wc -l | tr -d ' ')"
detectors="$(count_rg 'Box::new\(' src/rules/builtin/mod.rs)"
parser_modules="$(find src/parser -maxdepth 1 -type f -name '*.rs' ! -name mod.rs 2>/dev/null | wc -l | tr -d ' ')"
fixture_roots="$(find tests/fixtures -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
cli_commands="$(count_rg '^    [A-Z][A-Za-z0-9_]+( \{|,)' src/bin/cli.rs)"
release_targets="$(count_rg '^          - target: ' .github/workflows/release.yml)"
docs_files="$(find docs -type f -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
harness_scripts="$(find docs/harness/bin -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
review_artifacts="$(find docs/harness/reviews -maxdepth 1 -type f -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
vscode_ts_files="$(find vscode/src -type f -name '*.ts' 2>/dev/null | wc -l | tr -d ' ')"

{
  echo "# AgentShield baseline"
  echo "timestamp=$TIMESTAMP"
  echo "branch=$branch"
  echo "commit=$commit"
  echo "dirty=$dirty"
  echo "cargo=$(cargo --version 2>/dev/null || echo missing)"
  echo "rustc=$(rustc --version 2>/dev/null || echo missing)"
  echo
  echo "| Metric | Value |"
  echo "|---|---:|"
  echo "| Rust source/test/bench files | $rust_files |"
  echo "| Rust source/test/bench LOC | $rust_loc |"
  echo "| Adapter modules | $adapter_modules |"
  echo "| Built-in detectors | $detectors |"
  echo "| Parser modules | $parser_modules |"
  echo "| Top-level fixture groups | $fixture_roots |"
  echo "| CLI command variants | $cli_commands |"
  echo "| Release targets | $release_targets |"
  echo "| Markdown docs | $docs_files |"
  echo "| Harness scripts | $harness_scripts |"
  echo "| Review artifacts | $review_artifacts |"
  echo "| VS Code TypeScript files | $vscode_ts_files |"
  echo
  echo "## Cargo features"
  rg -n '^(default|python|typescript|runtime|full) =' Cargo.toml || true
  echo
  echo "## Adapter modules"
  find src/adapter -maxdepth 1 -type f -name '*.rs' ! -name mod.rs -exec basename {} \; | sort
  echo
  echo "## Detector registration"
  rg -n 'Box::new\(' src/rules/builtin/mod.rs || true
  echo
  echo "## Release targets"
  rg -n '^          - target: ' .github/workflows/release.yml || true
} > "$TMP"

mv "$TMP" "$OUT"
echo "Baseline written to $OUT"
cat "$OUT"
