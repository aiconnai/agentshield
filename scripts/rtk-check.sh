#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/rtk-check.sh quick
  scripts/rtk-check.sh test
  scripts/rtk-check.sh clippy
  scripts/rtk-check.sh fmt
  scripts/rtk-check.sh scan-fixture
  scripts/rtk-check.sh scan-json
  scripts/rtk-check.sh scan-sarif
  scripts/rtk-check.sh raw -- <command> [args...]

Modes:
  quick        Run fmt check, clippy, tests, and a smoke scan with filtered output.
  test         Run cargo test with filtered output.
  clippy       Run cargo clippy with filtered output.
  fmt          Run cargo fmt --check with filtered output.
  scan-fixture Run a vulnerable fixture scan with filtered output.
  scan-json    Run JSON scan and write complete raw JSON to target/agentshield/scan.json.
  scan-sarif   Run SARIF scan and write complete raw SARIF to target/agentshield/scan.sarif.
  raw          Run a command through rtk proxy if available, otherwise run it directly.

Policy:
  Filter noisy local feedback.
  Preserve full machine-readable artifacts.
  Use raw mode for debugging failures and security-critical decisions.
EOF
}

has_rtk() {
  command -v rtk >/dev/null 2>&1
}

run_filtered() {
  if has_rtk; then
    rtk "$@"
  else
    "$@"
  fi
}

run_raw() {
  if has_rtk; then
    rtk proxy "$@"
  else
    "$@"
  fi
}

ensure_artifact_dir() {
  mkdir -p target/agentshield
}

mode="${1:-}"

case "$mode" in
  quick)
    run_filtered cargo fmt --check
    run_filtered cargo clippy -- -D warnings
    run_filtered cargo test
    run_filtered cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
    ;;
  test)
    run_filtered cargo test
    ;;
  clippy)
    run_filtered cargo clippy -- -D warnings
    ;;
  fmt)
    run_filtered cargo fmt --check
    ;;
  scan-fixture)
    run_filtered cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
    ;;
  scan-json)
    ensure_artifact_dir
    run_raw cargo run -- scan . --ignore-tests --format json --output target/agentshield/scan.json
    run_filtered wc -c target/agentshield/scan.json
    ;;
  scan-sarif)
    ensure_artifact_dir
    run_raw cargo run -- scan . --ignore-tests --format sarif --output target/agentshield/scan.sarif
    run_filtered wc -c target/agentshield/scan.sarif
    ;;
  raw)
    shift
    if [[ "${1:-}" == "--" ]]; then
      shift
    fi
    if [[ "$#" -eq 0 ]]; then
      echo "error: raw mode requires a command" >&2
      usage >&2
      exit 2
    fi
    run_raw "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  "")
    usage >&2
    exit 2
    ;;
  *)
    echo "error: unknown mode: $mode" >&2
    usage >&2
    exit 2
    ;;
esac
