#!/usr/bin/env bash
# Evidence-only quarterly audit for AgentShield.
#
# Usage:
#   bash docs/harness/bin/quarterly-audit.sh
#
# The report is intentionally not a pass/fail gate. It gathers review evidence
# for humans to decide what to keep, archive, delete, or promote into gates.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
REPORT_DIR="docs/harness/audits"
REPORT="$REPORT_DIR/${TIMESTAMP}-quarterly-audit.md"
LAST_FILE="docs/harness/.quarterly-audit-last"
RG_SAFE_GLOBS="--glob '!docs/harness/audits/**' --glob '!docs/harness/reviews/**' --glob '!target/**' --glob '!vscode/node_modules/**'"

mkdir -p "$REPORT_DIR"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "FAIL: required command not found: $1" >&2
    exit 127
  fi
}

append_cmd() {
  local title="$1"
  local cmd="$2"
  local output
  local status

  {
    echo
    echo "### $title"
    echo
    echo '```bash'
    echo "$cmd"
    echo '```'
    echo
    echo '```text'
  } >> "$REPORT"

  status=0
  output="$(bash -o pipefail -c "$cmd" 2>&1)" || status=$?
  if [ -n "$output" ]; then
    printf '%s\n' "$output" >> "$REPORT"
  else
    echo "(no output)" >> "$REPORT"
  fi
  {
    echo "exit_status=$status"
    echo '```'
  } >> "$REPORT"
}

append_decision_table() {
  local title="$1"
  {
    echo
    echo "### $title"
    echo
    echo "| Item | Evidence | Decision | Owner | Follow-up |"
    echo "|---|---|---|---|---|"
    echo "|  |  | Keep / Archive / Delete / Promote to gate |  |  |"
  } >> "$REPORT"
}

need git
need rg

cat > "$REPORT" <<EOF_REPORT
# Quarterly Harness Audit

Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Repo: \`agentshield\`
Mode: evidence-only

This report gathers evidence for a human cleanup, drift, and scanner-surface review. It does not declare pass/fail and does not delete, archive, or rewrite anything.

## How To Use

1. Review each evidence section.
2. Fill decision tables with \`Keep\`, \`Archive\`, \`Delete\`, or \`Promote to gate\`.
3. Convert accepted cleanup into focused tasks, issues, PRs, or ADRs.
4. Keep exceptions documented in \`docs/harness/WHAT_WE_DONT_DO.md\`, \`docs/harness/INVARIANTS.md\`, or an ADR.

## Repo State
EOF_REPORT

append_cmd "Current branch and commit" "git branch --show-current && git log -1 --oneline"
append_cmd "Working tree status" "git status --short"
append_cmd "Harness policy references" "rg -n 'WHAT_WE_DONT_DO|CODE_REVIEW_POLICY|VERIFICATION_MANIFEST|Review Canvas|review-gate|doctor.sh|sensors.sh|baseline.sh|quarterly-audit' docs/harness README.md AGENTS.md 2>/dev/null | head -180"

{
  echo
  echo "## Scanner Surface"
  echo
  echo "Review adapter, parser, detector, and analysis growth before adding more scanning surface."
} >> "$REPORT"
append_cmd "Adapter modules" "find src/adapter -maxdepth 1 -type f -name '*.rs' | sort"
append_cmd "Parser modules" "find src/parser -maxdepth 1 -type f -name '*.rs' | sort"
append_cmd "Detector registration and rule references" "rg -n 'Box::new|SHIELD-[0-9]{3}' src/rules README.md docs/RULES.md $RG_SAFE_GLOBS | head -260"
append_cmd "Taint and sanitizer references" "rg -n 'ArgumentSource|Sanitized|is_tainted|sanitize|validate|cross_file' src tests docs $RG_SAFE_GLOBS | head -240"
append_decision_table "Scanner Surface Decisions"

{
  echo
  echo "## CLI And Documentation Parity"
  echo
  echo "Look for commands, features, adapters, or versions advertised in docs but absent from code."
} >> "$REPORT"
append_cmd "CLI command references" "rg -n 'agentshield (scan|list-rules|init|suppress|list-suppressions|certify|wrap|doctor)' README.md docs src/bin/cli.rs action.yml $RG_SAFE_GLOBS | head -260"
append_cmd "Potential stale version or issue references" "rg -n 'v0\\.[0-9]|doctor|IBVI|Linear|Huly|AGENT-|TODO|Done v' README.md docs action.yml .github $RG_SAFE_GLOBS | head -260"
append_decision_table "Documentation Parity Decisions"

{
  echo
  echo "## Fixture And Validation Evidence"
  echo
  echo "Review whether fixtures still represent the supported framework and rule surface."
} >> "$REPORT"
append_cmd "Fixture files" "find tests/fixtures -maxdepth 3 -type f | sort | head -260"
append_cmd "Fixture references in tests" "rg -n 'tests/fixtures|safe_calculator|vuln_cmd_inject|crewai|langchain|gpt_actions|cursor_rules' src tests docs $RG_SAFE_GLOBS | head -260"
append_decision_table "Fixture Decisions"

{
  echo
  echo "## SARIF And Output Compatibility"
  echo
  echo "Review GitHub Code Scanning compatibility, output contracts, and fingerprint behavior."
} >> "$REPORT"
append_cmd "SARIF and output references" "rg -n 'SARIF|sarif|Code Scanning|upload-sarif|startColumn|fingerprint|fingerprints|results' src/output src/rules README.md docs action.yml $RG_SAFE_GLOBS | head -280"
append_decision_table "Output Compatibility Decisions"

{
  echo
  echo "## Trust Workflow Surface"
  echo
  echo "Review baseline, suppression, certification, egress, and runtime wrap behavior."
} >> "$REPORT"
append_cmd "Trust workflow references" "rg -n -i 'baseline|suppress|certify|egress|wrap|DSSE|attestation|operator override|policy' src README.md docs action.yml .github $RG_SAFE_GLOBS | head -280"
append_decision_table "Trust Workflow Decisions"

{
  echo
  echo "## Release, Action, And VS Code Surface"
  echo
  echo "Review distribution surfaces for compatibility drift."
} >> "$REPORT"
append_cmd "Release workflow features and targets" "rg -n -- '--features full|wrap|target:|agentshield-' .github/workflows/release.yml docs/RELEASE_CHECKLIST.md README.md $RG_SAFE_GLOBS | head -240"
append_cmd "GitHub Action behavior" "rg -n 'ignore-tests|upload-sarif|AGENTSHIELD_EXIT|finding-count|sarif-file|fail-on|format' action.yml README.md docs $RG_SAFE_GLOBS | head -240"
append_cmd "VS Code extension behavior" "rg -n 'agentshield|scan|ignoreTests|timeout|Diagnostic|diagnostic|json' vscode/package.json vscode/src vscode/README.md vscode/CHANGELOG.md 2>/dev/null | head -240"
append_decision_table "Distribution Surface Decisions"

{
  echo
  echo "## Harness And Verification Discipline"
  echo
  echo "Review generated evidence volume, known-issue exclusions, and skipped verification conventions."
} >> "$REPORT"
append_cmd "Harness generated artifacts volume" "find docs/harness/reviews docs/harness/progress docs/harness/audits docs/harness/canvas -maxdepth 1 -type f 2>/dev/null | sort | wc -l | tr -d ' '"
append_cmd "Known issue and verification references" "rg -n 'known-issue|exclude-sensor|harness_verify|skipped_reason|REVIEW_VERDICT|HARNESS_SCRIPT_REVIEW_EVIDENCE' docs/harness $RG_SAFE_GLOBS | head -260"
append_decision_table "Harness Discipline Decisions"

{
  echo
  echo "## Dependencies And Feature Gates"
  echo
  echo "Review optional features, parser dependencies, runtime dependencies, and package manager drift."
} >> "$REPORT"
append_cmd "Cargo dependency declarations" "rg -n '^([a-zA-Z0-9_-]+\\s*=|\\[dependencies|\\[dev-dependencies|\\[features\\])' Cargo.toml $RG_SAFE_GLOBS | head -240"
append_cmd "Optional/runtime/parser dependency references" "rg -n -i 'optional = true|tree-sitter|runtime|tokio|parking_lot|ed25519|features =|default-features' Cargo.toml src docs $RG_SAFE_GLOBS | head -260"
append_cmd "VS Code package dependencies" "rg -n 'dependencies|devDependencies|typescript|vscode|vsce' vscode/package.json vscode/package-lock.json 2>/dev/null | head -240"
append_decision_table "Dependency Decisions"

{
  echo
  echo "## Review Discipline Candidates"
  echo
  echo "Use the Review Canvas for changes that match the complex-change triggers in \`docs/harness/GATES.md\`."
} >> "$REPORT"
append_cmd "Large recent commits" "git log --since='120 days ago' --shortstat --pretty='%h %ad %s' --date=short | awk 'NF { print }' | head -180"
append_decision_table "Review Discipline Follow-ups"

{
  echo
  echo "## Human Review Notes"
  echo
  echo "- Decisions:"
  echo "- Follow-up issues:"
  echo "- Exceptions approved:"
  echo "- Next audit date:"
} >> "$REPORT"

printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REPORT" > "$LAST_FILE"

echo "Quarterly audit evidence written to $REPORT"
echo "Last-audit pointer updated at $LAST_FILE"
