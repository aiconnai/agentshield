#!/usr/bin/env bash
# Run AgentShield harness sensors.
#
# Usage:
#   bash docs/harness/bin/sensors.sh
#   bash docs/harness/bin/sensors.sh full
#   bash docs/harness/bin/sensors.sh quick
#   bash docs/harness/bin/sensors.sh docs
#   bash docs/harness/bin/sensors.sh mcp
#   bash docs/harness/bin/sensors.sh fixtures
#   bash docs/harness/bin/sensors.sh sarif
#   bash docs/harness/bin/sensors.sh action
#   bash docs/harness/bin/sensors.sh release
#   bash docs/harness/bin/sensors.sh vscode
#   bash docs/harness/bin/sensors.sh baseline
#   bash docs/harness/bin/sensors.sh audit

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

MODE="full"
if [ $# -gt 0 ] && [[ "${1:-}" != --* ]]; then
  MODE="$1"
  shift
fi

EXCLUDE_SENSOR=""
KNOWN_ISSUE=""
EXCLUSION_REASON=""
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

while [ $# -gt 0 ]; do
  case "$1" in
    --exclude-sensor)
      EXCLUDE_SENSOR="${2:-}"
      shift 2
      ;;
    --known-issue)
      KNOWN_ISSUE="${2:-}"
      shift 2
      ;;
    --reason)
      EXCLUSION_REASON="${2:-}"
      shift 2
      ;;
    *)
      echo "Usage: $0 [full|quick|docs|mcp|fixtures|sarif|action|release|vscode|baseline|audit] [--exclude-sensor <name> --known-issue <path> --reason <text>]" >&2
      exit 2
      ;;
  esac
done

run() {
  local label="$1"
  shift
  echo "=== $label ==="
  if "$@"; then
    echo "OK: $label"
  else
    echo "FAIL: $label" >&2
    return 1
  fi
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "FAIL: required command not found: $1" >&2
    exit 127
  fi
}

write_success() {
  echo "$TIMESTAMP $MODE PASS" > docs/harness/.sensors-last
  echo "=== ALL SENSORS GREEN ($MODE, $TIMESTAMP) ==="
}

assert_match() {
  local label="$1"
  local pattern="$2"
  shift 2
  local output
  local status

  echo "=== $label ==="
  status=0
  output="$(rg -n "$pattern" "$@" 2>&1)" || status=$?
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output"
    echo "OK: $label"
    return 0
  fi
  printf '%s\n' "$output" >&2
  echo "FAIL: $label" >&2
  return 1
}

run_expected_exit() {
  local label="$1"
  local expected="$2"
  shift 2
  local status

  echo "=== $label ==="
  status=0
  "$@" || status=$?
  if [ "$status" -eq "$expected" ]; then
    echo "OK: $label exited $status"
    return 0
  fi
  echo "FAIL: $label expected exit $expected, got $status" >&2
  return 1
}

run_scan_allow_findings() {
  local label="$1"
  shift
  local status

  echo "=== $label ==="
  status=0
  "$@" || status=$?
  case "$status" in
    0|1)
      echo "OK: $label exited $status"
      return 0
      ;;
    *)
      echo "FAIL: $label scanner error exit $status" >&2
      return 1
      ;;
  esac
}

validate_exclusion_contract() {
  if [ -z "$EXCLUDE_SENSOR" ] && [ -z "$KNOWN_ISSUE" ] && [ -z "$EXCLUSION_REASON" ]; then
    return 0
  fi

  if [ -z "$EXCLUDE_SENSOR" ] || [ -z "$KNOWN_ISSUE" ] || [ -z "$EXCLUSION_REASON" ]; then
    echo "FAIL: exclusions require --exclude-sensor, --known-issue, and --reason" >&2
    exit 2
  fi

  if [ ! -f "$KNOWN_ISSUE" ]; then
    echo "FAIL: known issue file not found: $KNOWN_ISSUE" >&2
    exit 2
  fi

  if ! rg -n -F "$KNOWN_ISSUE" docs/harness/progress.md docs/harness/progress >/dev/null 2>&1 && \
     ! rg -n -F "$EXCLUDE_SENSOR" docs/harness/progress.md docs/harness/progress >/dev/null 2>&1; then
    echo "FAIL: exclusion is not registered in docs/harness/progress.md or docs/harness/progress/" >&2
    exit 2
  fi
}

should_skip() {
  local sensor="$1"
  if [ -n "$EXCLUDE_SENSOR" ] && [ "$EXCLUDE_SENSOR" = "$sensor" ]; then
    echo "SKIP: $sensor excluded by known issue $KNOWN_ISSUE: $EXCLUSION_REASON"
    return 0
  fi
  return 1
}

run_sensor() {
  local sensor="$1"
  local label="$2"
  shift 2
  if should_skip "$sensor"; then
    return 0
  fi
  run "$label" "$@"
}

harness_checks() {
  run_sensor doctor "harness doctor" bash docs/harness/bin/doctor.sh || return 1
  if ! should_skip pr-title-policy; then
    run "PR title policy accepts clean title" \
      bash docs/harness/bin/pr-title-policy.sh --title "fix: clean title" || return 1
    run_expected_exit "PR title policy rejects [codex] title" 4 \
      bash docs/harness/bin/pr-title-policy.sh --title "[codex] fix: bad title" || return 1
    run_expected_exit "PR title policy rejects spaced mixed-case codex title" 4 \
      bash docs/harness/bin/pr-title-policy.sh --title "[ CoDeX ] fix: bad title" || return 1
  fi
}

docs_checks() {
  harness_checks || return 1
  assert_match "README documents mandatory read order" 'Mandatory Read Order' docs/harness/README.md || return 1
  assert_match "negative scope is documented" 'WHAT_WE_DONT_DO\.md' docs/harness/README.md docs/harness/GATES.md docs/harness/CODE_REVIEW_POLICY.md || return 1
  assert_match "review canvas is documented" 'Review Canvas' docs/harness/README.md docs/harness/GATES.md docs/harness/CODE_REVIEW_POLICY.md || return 1
  assert_match "verification manifest is documented" 'VERIFICATION_MANIFEST\.md|Verification Manifest' docs/harness/README.md docs/harness/VERIFICATION_MANIFEST.md || return 1
  assert_match "current scanner surface is documented" 'MCP, OpenClaw, CrewAI, LangChain, GPT Actions, Cursor Rules|SHIELD-001' docs/harness/README.md docs/harness/SPEC.md || return 1
}

mcp_checks() {
  assert_match "MCP validation report references the reference servers" '^\*\*Target:\*\* \[modelcontextprotocol/servers\]' docs/VALIDATION_REPORT.md || return 1
  assert_match "MCP validation report records summary outcomes" '^\*\*Total findings across 7 servers:\*\* 170 ' docs/VALIDATION_REPORT.md || return 1
  assert_match "MCP validation report preserves post-fix narrative" '^## Post-Fix Re-Scan \(Feb 20, 2026\)' docs/VALIDATION_REPORT.md || return 1
}

action_checks() {
  assert_match "action exposes ignore-tests input" '^  ignore-tests:' action.yml || return 1
  assert_match "action supports SARIF upload" 'upload-sarif' action.yml || return 1
  assert_match "action supports local binary e2e override" '^  binary-path:' action.yml || return 1
  assert_match "action records SARIF output path" 'sarif-file' action.yml || return 1
  assert_match "action preserves scan exit code" 'AGENTSHIELD_EXIT' action.yml || return 1
  assert_match "action reports finding count" 'finding-count' action.yml || return 1
  assert_match "action e2e invokes the local composite action" 'uses: \./' .github/workflows/action-e2e.yml || return 1
  assert_match "action e2e covers subdirectory path filters" 'Composite action honors root config path filters' .github/workflows/action-e2e.yml || return 1
}

release_checks() {
  assert_match "release builds native artifacts with full features" \
    'cargo build --release --target .* --features full' \
    .github/workflows/release.yml || return 1
  assert_match "release builds cross artifacts with full features" \
    'cross build --release --target .* --features full' \
    .github/workflows/release.yml || return 1
  assert_match "release smoke checks wrap command" \
    'grep wrap|Select-String wrap' \
    .github/workflows/release.yml || return 1
  assert_match "release includes linux x64" 'x86_64-unknown-linux-gnu' .github/workflows/release.yml || return 1
  assert_match "release includes linux arm64" 'aarch64-unknown-linux-gnu' .github/workflows/release.yml || return 1
  assert_match "release includes macOS x64" 'x86_64-apple-darwin' .github/workflows/release.yml || return 1
  assert_match "release includes macOS arm64" 'aarch64-apple-darwin' .github/workflows/release.yml || return 1
  assert_match "release includes Windows x64" 'x86_64-pc-windows-msvc' .github/workflows/release.yml || return 1
}

fixture_smoke() {
  run_sensor fixtures-build "debug build with full features" cargo build --features full || return 1
  local bin="target/debug/agentshield"
  run "list rules" "$bin" list-rules || return 1
  run_scan_allow_findings "MCP safe calculator scan" \
    "$bin" scan tests/fixtures/mcp_servers/safe_calculator --ignore-tests --format json || return 1
  run_expected_exit "MCP vulnerable command injection fails policy" 1 \
    "$bin" scan tests/fixtures/mcp_servers/vuln_cmd_inject --format console || return 1
  run_scan_allow_findings "CrewAI adapter smoke" \
    "$bin" scan tests/fixtures/crewai_project --ignore-tests --format json || return 1
  run_scan_allow_findings "LangChain adapter smoke" \
    "$bin" scan tests/fixtures/langchain_project --ignore-tests --format json || return 1
  run_scan_allow_findings "GPT Actions adapter smoke" \
    "$bin" scan tests/fixtures/gpt_actions --ignore-tests --format json || return 1
  run_scan_allow_findings "Cursor Rules adapter smoke" \
    "$bin" scan tests/fixtures/cursor_rules --ignore-tests --format json || return 1
}

sarif_checks() {
  need python3
  run_sensor sarif-build "debug build with full features" cargo build --features full || return 1
  local bin="target/debug/agentshield"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/agentshield-sarif.XXXXXX.sarif")" || return 1
  run_scan_allow_findings "SARIF vulnerable fixture scan" \
    "$bin" scan tests/fixtures/mcp_servers/vuln_cmd_inject --format sarif --output "$tmp" || {
      rm -f "$tmp"
      return 1
    }
  echo "=== SARIF top-level shape ==="
  if python3 - "$tmp" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text())
assert data.get("version") == "2.1.0"
runs = data.get("runs")
assert isinstance(runs, list) and runs
run = runs[0]
assert isinstance(run.get("tool", {}).get("driver"), dict)
assert isinstance(run.get("results"), list)
PY
  then
    echo "OK: SARIF top-level shape"
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  echo "FAIL: SARIF top-level shape" >&2
  return 1
}

vscode_checks() {
  need npm
  (
    cd vscode || exit 1
    run "VS Code npm ci" npm ci || exit 1
    run "VS Code compile" npm run compile || exit 1
  )
}

need cargo
need rg
validate_exclusion_contract

case "$MODE" in
  full)
    harness_checks || exit 1
    run_sensor fmt "fmt" cargo fmt --check || exit 1
    run_sensor clippy "clippy all features" cargo clippy --all-features -- -D warnings || exit 1
    run_sensor tests "tests all features" cargo test --all-features || exit 1
    if should_skip fixtures; then :; else fixture_smoke || exit 1; fi
    if should_skip sarif; then :; else sarif_checks || exit 1; fi
    if should_skip action; then :; else action_checks || exit 1; fi
    if should_skip release; then :; else release_checks || exit 1; fi
    write_success
    ;;

  quick)
    harness_checks || exit 1
    run_sensor fmt "fmt" cargo fmt --check || exit 1
    run_sensor check "cargo check all features" cargo check --all-features || exit 1
    write_success
    ;;

  docs)
    docs_checks || exit 1
    write_success
    ;;

  mcp)
    harness_checks || exit 1
    if should_skip mcp; then :; else mcp_checks || exit 1; fi
    write_success
    ;;

  fixtures)
    harness_checks || exit 1
    if should_skip fixtures; then :; else fixture_smoke || exit 1; fi
    write_success
    ;;

  sarif)
    harness_checks || exit 1
    if should_skip sarif; then :; else sarif_checks || exit 1; fi
    write_success
    ;;

  action)
    harness_checks || exit 1
    if should_skip action; then :; else action_checks || exit 1; fi
    write_success
    ;;

  release)
    harness_checks || exit 1
    if should_skip release; then :; else release_checks || exit 1; fi
    write_success
    ;;

  vscode)
    harness_checks || exit 1
    if should_skip vscode; then :; else vscode_checks || exit 1; fi
    write_success
    ;;

  baseline)
    if should_skip baseline; then :; else bash docs/harness/bin/baseline.sh || exit 1; fi
    harness_checks || exit 1
    write_success
    ;;

  audit)
    if should_skip audit; then :; else bash docs/harness/bin/quarterly-audit.sh || exit 1; fi
    harness_checks || exit 1
    write_success
    ;;

  *)
    echo "Usage: $0 [full|quick|docs|mcp|fixtures|sarif|action|release|vscode|baseline|audit] [--exclude-sensor <name> --known-issue <path> --reason <text>]" >&2
    exit 2
    ;;
esac
