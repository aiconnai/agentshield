# RTK Check Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional RTK-powered developer check loop for AgentShield that reduces noisy command output seen by agents/humans while preserving complete scanner outputs for clients, CI, audit, SARIF, JSON, and debugging.

**Architecture:** RTK stays outside the Rust scanner and acts only as a local command-output filter for developer workflows. AgentShield's public CLI contracts remain unchanged; wrappers and docs route noisy checks through `rtk`, while raw commands remain available for failures, security decisions, and machine-readable artifacts.

**Tech Stack:** Bash, Cargo, Rust test suite, AgentShield CLI, RTK CLI, Markdown documentation.

---

## Scope and Non-Goals

This plan implements RTK as an optional development helper, not as a runtime dependency of AgentShield.

In scope:

- Add a local script for filtered check loops.
- Add a raw fallback path for complete diagnostic output.
- Document when to use filtered versus raw commands.
- Add lightweight tests for the wrapper behavior.
- Optionally expose convenient Makefile targets if the repository already accepts Makefile-based workflows.

Out of scope:

- Changing `src/output/json.rs`.
- Changing `src/output/sarif.rs`.
- Compressing SARIF or JSON emitted to clients.
- Adding RTK as a Rust crate dependency.
- Requiring RTK in CI.
- Replacing policy evaluation or detector output.

## Design Decision

RTK should be used at the observability boundary:

- `agent/human sees filtered summary`
- `files, clients, CI artifacts receive raw complete output`

The scanner must remain deterministic and contract-stable. If AgentShield emits SARIF, JSON, console, or HTML, those formats should continue to mean exactly what they mean today.

## File Structure

Create:

- `scripts/rtk-check.sh` - developer wrapper around common AgentShield checks using RTK when available.
- `tests/scripts/rtk-check.bats` - shell-level tests for wrapper behavior if Bats is already acceptable in the repo.

Modify:

- `README.md` - add a short section explaining filtered local checks and raw audit commands.
- `AGENTS.md` - if this file exists in the repo, add RTK guidance for future agents.
- `Makefile` - only if the repo already has a Makefile; add convenience targets without making RTK mandatory.
- `.gitignore` - only if generated local reports are not already ignored.

Do not modify:

- `src/output/json.rs`
- `src/output/sarif.rs`
- `src/lib.rs`
- `src/bin/cli.rs`, unless a later product decision adds a native `--format summary`.

---

### Task 1: Add RTK Check Wrapper

**Files:**

- Create: `scripts/rtk-check.sh`

- [ ] **Step 1: Create the wrapper script**

Create `scripts/rtk-check.sh` with this exact content:

```bash
#!/usr/bin/env bash
set -euo pipefail

SMOKE_TARGET="tests/fixtures/mcp_servers/safe_calculator"

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
  scan-fixture Run the safe smoke fixture scan with filtered output.
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
    run_filtered cargo run -- scan "$SMOKE_TARGET"
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
    run_filtered cargo run -- scan "$SMOKE_TARGET"
    ;;
  scan-json)
    ensure_artifact_dir
    run_raw cargo run -- scan "$SMOKE_TARGET" --format json --output target/agentshield/scan.json
    run_filtered wc -c target/agentshield/scan.json
    ;;
  scan-sarif)
    ensure_artifact_dir
    run_raw cargo run -- scan "$SMOKE_TARGET" --format sarif --output target/agentshield/scan.sarif
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
```

- [ ] **Step 2: Make the script executable**

Run:

```bash
chmod +x scripts/rtk-check.sh
```

Expected:

```text
No output. The script becomes executable.
```

- [ ] **Step 3: Commit**

Run:

```bash
git add scripts/rtk-check.sh
git commit -m "chore: add rtk check wrapper"
```

Expected:

```text
[branch commit] chore: add rtk check wrapper
```

---

### Task 2: Add Wrapper Tests

**Files:**

- Create: `tests/scripts/rtk-check.bats`

- [ ] **Step 1: Decide whether Bats is already acceptable**

Run:

```bash
command -v bats
```

Expected if available:

```text
/path/to/bats
```

Expected if unavailable:

```text
No output and non-zero exit.
```

If Bats is unavailable and the repository does not already use shell tests, skip this task and perform Task 3 documentation instead. Do not add a new test framework just for this wrapper.

- [ ] **Step 2: Create shell tests when Bats is available**

Create `tests/scripts/rtk-check.bats` with this exact content:

```bash
#!/usr/bin/env bats

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/rtk-check.sh"
}

@test "help output lists supported modes" {
  run "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"quick"* ]]
  [[ "$output" == *"scan-json"* ]]
  [[ "$output" == *"raw"* ]]
}

@test "unknown mode exits with usage error" {
  run "$SCRIPT" definitely-not-a-mode
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown mode"* ]]
}

@test "raw mode requires a command" {
  run "$SCRIPT" raw
  [ "$status" -eq 2 ]
  [[ "$output" == *"raw mode requires a command"* ]]
}

@test "raw mode executes a simple command" {
  run "$SCRIPT" raw -- printf "agent-shield-rtk"
  [ "$status" -eq 0 ]
  [[ "$output" == *"agent-shield-rtk"* ]]
}
```

- [ ] **Step 3: Run wrapper tests**

Run:

```bash
bats tests/scripts/rtk-check.bats
```

Expected:

```text
4 tests, 0 failures
```

- [ ] **Step 4: Commit**

Run:

```bash
git add tests/scripts/rtk-check.bats
git commit -m "test: cover rtk check wrapper"
```

Expected:

```text
[branch commit] test: cover rtk check wrapper
```

---

### Task 3: Document RTK Policy in README

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Add a local developer check section**

Append this section to the development or contributing area of `README.md`:

```markdown
## Token-Optimized Local Checks with RTK

AgentShield can produce noisy command output during local development, especially from `cargo test`, `cargo clippy`, and scanner runs that emit JSON or SARIF. If `rtk` is installed, use the optional wrapper to reduce output shown to humans and coding agents:

```bash
scripts/rtk-check.sh quick
scripts/rtk-check.sh test
scripts/rtk-check.sh clippy
scripts/rtk-check.sh scan-fixture
```

The wrapper is intentionally local-only. It does not change AgentShield's scanner behavior, output formats, CI contract, or GitHub Code Scanning SARIF output.

Use raw output for debugging, audit, and security decisions:

```bash
scripts/rtk-check.sh raw -- cargo test
scripts/rtk-check.sh raw -- cargo run -- scan tests/fixtures/mcp_servers/safe_calculator --format sarif --output target/agentshield/scan.sarif
```

Policy:

- Use filtered output for fast local feedback.
- Use raw output when investigating test failures, parser bugs, detector behavior, or security-sensitive findings.
- Always write complete `json` and `sarif` reports to files when clients or CI consume them.
```

- [ ] **Step 2: Commit**

Run:

```bash
git add README.md
git commit -m "docs: document rtk local check workflow"
```

Expected:

```text
[branch commit] docs: document rtk local check workflow
```

---

### Task 4: Add Agent Guidance

**Files:**

- Modify: `AGENTS.md` if it exists in the repository root.
- If `AGENTS.md` does not exist in the repository root, create it only if the project wants repo-local agent guidance instead of relying on external session instructions.

- [ ] **Step 1: Check whether repo-local AGENTS.md exists**

Run:

```bash
test -f AGENTS.md
```

Expected if present:

```text
No output and exit code 0.
```

Expected if absent:

```text
No output and non-zero exit.
```

- [ ] **Step 2: Add RTK guidance when AGENTS.md exists**

Add this section to `AGENTS.md`:

```markdown
## RTK Usage for Agent Check Loops

RTK is optional and should only filter command output seen by agents or humans. It must not change AgentShield's machine-readable scanner contracts.

Use filtered commands for noisy local checks:

```bash
rtk cargo test
rtk cargo clippy -- -D warnings
rtk cargo run -- scan tests/fixtures/mcp_servers/safe_calculator
```

Use raw commands for complete diagnostics:

```bash
rtk proxy cargo test
rtk proxy cargo run -- scan tests/fixtures/mcp_servers/safe_calculator --format sarif --output target/agentshield/scan.sarif
```

Rules:

- Do not filter final SARIF or JSON artifacts consumed by clients.
- Do not rely on filtered output to make security-critical decisions.
- If a test, parser, detector, or policy check fails, rerun the specific command raw before making code changes based on the failure.
```

- [ ] **Step 3: Commit**

Run:

```bash
git add AGENTS.md
git commit -m "docs: add rtk guidance for agents"
```

Expected:

```text
[branch commit] docs: add rtk guidance for agents
```

---

### Task 5: Add Optional Makefile Targets

**Files:**

- Modify: `Makefile` only if a Makefile already exists.

- [ ] **Step 1: Check whether Makefile exists**

Run:

```bash
test -f Makefile
```

Expected if present:

```text
No output and exit code 0.
```

Expected if absent:

```text
No output and non-zero exit.
```

If `Makefile` does not exist, skip this task. Do not introduce Makefile as a new convention only for RTK.

- [ ] **Step 2: Add convenience targets when Makefile exists**

Append this content to `Makefile`:

```make
.PHONY: check-rtk test-rtk clippy-rtk scan-rtk scan-rtk-json scan-rtk-sarif

check-rtk:
	./scripts/rtk-check.sh quick

test-rtk:
	./scripts/rtk-check.sh test

clippy-rtk:
	./scripts/rtk-check.sh clippy

scan-rtk:
	./scripts/rtk-check.sh scan-fixture

scan-rtk-json:
	./scripts/rtk-check.sh scan-json

scan-rtk-sarif:
	./scripts/rtk-check.sh scan-sarif
```

- [ ] **Step 3: Commit**

Run:

```bash
git add Makefile
git commit -m "chore: add rtk make targets"
```

Expected:

```text
[branch commit] chore: add rtk make targets
```

---

### Task 6: Ensure Generated Reports Stay Local

**Files:**

- Modify: `.gitignore` only if `target/` is not already ignored.

- [ ] **Step 1: Check ignore behavior**

Run:

```bash
git check-ignore target/agentshield/scan.json target/agentshield/scan.sarif
```

Expected if already ignored:

```text
target/agentshield/scan.json
target/agentshield/scan.sarif
```

If both files are ignored, skip this task.

- [ ] **Step 2: Add local report ignores when needed**

Append this to `.gitignore`:

```gitignore
# Local AgentShield reports
target/agentshield/
```

- [ ] **Step 3: Commit**

Run:

```bash
git add .gitignore
git commit -m "chore: ignore local agentshield reports"
```

Expected:

```text
[branch commit] chore: ignore local agentshield reports
```

---

### Task 7: Run the Filtered Development Loop

**Files:**

- No file changes.

- [ ] **Step 1: Run the quick filtered loop**

Run:

```bash
scripts/rtk-check.sh quick
```

Expected:

```text
Filtered output from fmt, clippy, tests, and fixture scan. Exit code 0 when all checks pass.
```

- [ ] **Step 2: Inspect RTK savings**

Run:

```bash
rtk gain
```

Expected:

```text
RTK reports token savings for recent filtered commands.
```

- [ ] **Step 3: Commit only if Task 7 required fixes**

If Task 7 exposes issues and fixes were made, commit those fixes with a specific message:

```bash
git add <changed-files>
git commit -m "fix: address rtk check loop issues"
```

Expected:

```text
[branch commit] fix: address rtk check loop issues
```

---

### Task 8: Verify Raw Artifact Preservation

**Files:**

- No source file changes.
- Generated local files:
  - `target/agentshield/scan.json`
  - `target/agentshield/scan.sarif`

- [ ] **Step 1: Generate complete JSON artifact**

Run:

```bash
scripts/rtk-check.sh scan-json
```

Expected:

```text
Complete JSON is written to target/agentshield/scan.json. Terminal output is limited to command status and byte count.
```

- [ ] **Step 2: Generate complete SARIF artifact**

Run:

```bash
scripts/rtk-check.sh scan-sarif
```

Expected:

```text
Complete SARIF is written to target/agentshield/scan.sarif. Terminal output is limited to command status and byte count.
```

- [ ] **Step 3: Confirm artifact files are non-empty**

Run:

```bash
test -s target/agentshield/scan.json
test -s target/agentshield/scan.sarif
```

Expected:

```text
No output and exit code 0 for both files.
```

---

### Task 9: Failure Investigation Procedure

**Files:**

- No file changes unless a real issue is found.

- [ ] **Step 1: If filtered `cargo test` fails, rerun raw**

Run:

```bash
scripts/rtk-check.sh raw -- cargo test
```

Expected:

```text
Complete Cargo test failure output, including panic messages and stack traces when present.
```

- [ ] **Step 2: If filtered scanner output shows a suspicious finding, rerun raw SARIF**

Run:

```bash
scripts/rtk-check.sh raw -- cargo run -- scan tests/fixtures/mcp_servers/safe_calculator --ignore-tests --format sarif --output target/agentshield/investigation.sarif
```

Expected:

```text
Complete SARIF is written to target/agentshield/investigation.sarif.
```

- [ ] **Step 3: If the issue concerns CLI console formatting, rerun raw console output**

Run:

```bash
scripts/rtk-check.sh raw -- cargo run -- scan tests/fixtures/mcp_servers/safe_calculator
```

Expected:

```text
Complete console output from the scanner.
```

---

### Task 10: Final Documentation Review

**Files:**

- Modify: `README.md`
- Modify: `AGENTS.md` if present

- [ ] **Step 1: Confirm the docs state the hard boundary**

Ensure both docs contain this rule in equivalent wording:

```markdown
RTK filters local command output only. It must not alter AgentShield JSON, SARIF, HTML, or console output contracts consumed by users, clients, CI, or GitHub Code Scanning.
```

- [ ] **Step 2: Confirm docs include raw fallback examples**

Ensure both docs include examples equivalent to:

```bash
scripts/rtk-check.sh raw -- cargo test
scripts/rtk-check.sh raw -- cargo run -- scan tests/fixtures/mcp_servers/safe_calculator --format sarif --output target/agentshield/scan.sarif
```

- [ ] **Step 3: Commit final doc adjustments**

Run:

```bash
git add README.md AGENTS.md
git commit -m "docs: clarify rtk raw fallback policy"
```

Expected:

```text
[branch commit] docs: clarify rtk raw fallback policy
```

---

## Operational Policy

Use this default decision table:

| Situation | Command Style | Reason |
|---|---|---|
| Fast local test loop | `rtk cargo test` or `scripts/rtk-check.sh test` | Reduces noisy successful output |
| Clippy/fmt check | `rtk cargo clippy -- -D warnings` | Usually only summary matters |
| Fixture smoke scan | `rtk cargo run -- scan tests/fixtures/mcp_servers/safe_calculator` | Keeps agent context small |
| JSON/SARIF consumed by tools | Raw command with `--output <file>` | Preserves contract |
| Security-sensitive investigation | `rtk proxy <command>` or `scripts/rtk-check.sh raw -- <command>` | Avoids missing evidence |
| CI artifact generation | Raw command | Reproducibility and audit |
| CI log summarization | Optional filtered post-processing | Logs can be summarized, artifacts cannot |

## Acceptance Criteria

- `scripts/rtk-check.sh quick` runs the standard local loop and uses RTK only when available.
- The wrapper works even when `rtk` is not installed by falling back to raw commands.
- `scripts/rtk-check.sh raw -- <command>` provides an explicit complete-output path.
- JSON and SARIF outputs are written complete to files, not compressed or rewritten.
- README documents filtered checks, raw fallback, and the no-contract-change boundary.
- Agent guidance documents when agents should rerun raw commands.
- No Rust scanner output modules are changed.

## Rollback Plan

If RTK creates confusion or hides important diagnostics:

```bash
git revert <commit-that-added-rtk-wrapper>
git revert <commit-that-added-rtk-docs>
```

If only the Makefile targets are unwanted:

```bash
git revert <commit-that-added-rtk-make-targets>
```

The scanner itself is unaffected because RTK integration is external to Rust code.

## Future Product Option

If users want a native summary mode later, implement it separately as a first-class AgentShield output format:

- Add `Summary` to `src/output/mod.rs`.
- Create `src/output/summary.rs`.
- Add `--format summary` to the CLI enum.
- Test that `summary` is human-readable and that `json`/`sarif` remain byte-for-byte contract-compatible for equivalent findings.

Do not use RTK as the implementation of a product output format.
