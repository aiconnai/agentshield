# AgentShield Huly Issues Parallel Worktrees Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Huly issues AGENT-1 through AGENT-7 using isolated git worktrees and parallel agents without causing documentation or code conflicts.

**Architecture:** Split the work by ownership boundary, not by issue count. Agents that would touch the same high-conflict files are grouped or sequenced behind a coordinator merge step. Independent agents work in separate worktrees from the same base branch, then the coordinator integrates final README/CHANGELOG references after parallel work lands.

**Tech Stack:** Rust CLI, Cargo, Clap, Markdown docs, GitHub Actions YAML, VS Code extension TypeScript, Huly issue IDs AGENT-1 through AGENT-7.

---

## Execution Model

Use one coordinator session plus five implementation agents.

| Agent | Huly scope | Branch | Worktree path | Conflict risk |
|---|---|---|---|---|
| Coordinator | Integration only | `coord/huly-roadmap-integration` | `.worktrees/coord-huly-roadmap-integration` | High: README/CHANGELOG merge owner |
| Release Docs Agent | AGENT-1, AGENT-2, AGENT-7 | `docs/release-state-0.8` | `.worktrees/docs-release-state-0.8` | High, but self-contained |
| Trust Workflows Agent | AGENT-3 | `docs/trust-workflows` | `.worktrees/docs-trust-workflows` | Low if it creates dedicated docs files |
| Runtime Release Agent | AGENT-4 | `ci/runtime-release-flags` | `.worktrees/ci-runtime-release-flags` | Medium: release workflow |
| VS Code Agent | AGENT-5 | `vscode/current-cli-compat` | `.worktrees/vscode-current-cli-compat` | Low: `vscode/` only |
| Doctor Agent | AGENT-6 | `feat/doctor-command` | `.worktrees/feat-doctor-command` | Medium: CLI code |

## Worktree Setup Procedure

Run from the repository root.

- [ ] **Step 1: Check current workspace isolation**

```bash
GIT_DIR=$(cd "$(git rev-parse --git-dir)" 2>/dev/null && pwd -P)
GIT_COMMON=$(cd "$(git rev-parse --git-common-dir)" 2>/dev/null && pwd -P)
BRANCH=$(git branch --show-current)
git rev-parse --show-superproject-working-tree 2>/dev/null
printf 'git_dir=%s\ngit_common=%s\nbranch=%s\n' "$GIT_DIR" "$GIT_COMMON" "$BRANCH"
```

Expected: normal repo checkout unless already inside a linked worktree. If already inside a linked worktree, do not create nested worktrees.

- [ ] **Step 2: Ensure project-local worktree directory and local env file are ignored**

```bash
git check-ignore -q .worktrees || printf '\n.worktrees/\n' >> .gitignore
git check-ignore -q .env || printf '\n.env\n' >> .gitignore
```

If this modifies `.gitignore`, commit it before creating worktrees:

```bash
git add .gitignore
git commit -m "chore: ignore local worktrees and env files"
```

- [ ] **Step 3: Create isolated worktrees**

```bash
git worktree add .worktrees/docs-release-state-0.8 -b docs/release-state-0.8
git worktree add .worktrees/docs-trust-workflows -b docs/trust-workflows
git worktree add .worktrees/ci-runtime-release-flags -b ci/runtime-release-flags
git worktree add .worktrees/vscode-current-cli-compat -b vscode/current-cli-compat
git worktree add .worktrees/feat-doctor-command -b feat/doctor-command
git worktree add .worktrees/coord-huly-roadmap-integration -b coord/huly-roadmap-integration
```

- [ ] **Step 4: Baseline each worktree before edits**

For Rust worktrees:

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

For the VS Code worktree:

```bash
cd vscode
npm install
npm test --if-present
npm run compile --if-present
```

If baseline checks fail, record the failure in the agent summary and ask before proceeding.

---

## Agent Prompt: Release Docs Agent

### Task 1: Implement AGENT-1, AGENT-2, and AGENT-7

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `action.yml`
- Create: `docs/releases/0.8.0.md`
- Create: `docs/RELEASE_CHECKLIST.md`

- [ ] **Step 1: Inspect current implemented scope**

Read these files once:

```bash
sed -n '1,240p' Cargo.toml
sed -n '1,260p' README.md
sed -n '1,260p' CHANGELOG.md
sed -n '1,220p' src/adapter/mod.rs
sed -n '1,220p' src/bin/cli.rs
sed -n '1,220p' action.yml
```

Expected findings:
- `Cargo.toml` version is `0.8.0`.
- README and CHANGELOG still stop at `0.2.4`.
- `src/adapter/mod.rs` registers MCP, OpenClaw, CrewAI, LangChain, GPT Actions, and Cursor Rules.
- `src/bin/cli.rs` exposes scan, list-rules, init, suppress, list-suppressions, certify, and feature-gated wrap.

- [ ] **Step 2: Update README to avoid drift-prone exact counts**

Replace exact phrases like `12 built-in detectors` with stable phrasing unless the section is a generated table. If README contains exact framework totals, remove those too; if it does not, treat that part as already satisfied.

Use this wording pattern:

```markdown
AgentShield ships with built-in detectors for command execution, credential handling, network access, filesystem access, runtime installs, prompt-injection surfaces, permission mismatch, and supply-chain risk.
```

- [ ] **Step 3: Update supported frameworks table**

README framework table must include:

```markdown
| Framework | Status | Adapter |
|-----------|--------|---------|
| MCP (Model Context Protocol) | Supported | Auto-detects MCP SDK projects and Python/TypeScript sources |
| OpenClaw | Supported | Auto-detects `SKILL.md` files |
| CrewAI | Supported | Auto-detects CrewAI dependencies and Python imports |
| LangChain / LangGraph | Supported | Auto-detects LangChain dependencies, imports, and `langgraph.json` |
| GPT Actions | Supported | Auto-detects OpenAPI/action schema artifacts |
| Cursor Rules | Supported | Auto-detects Cursor rule files |
```

- [ ] **Step 4: Add current CLI command summary to README**

Add a concise command table:

```markdown
| Command | Purpose |
|---------|---------|
| `agentshield scan` | Scan a target and render console, JSON, SARIF, or HTML output |
| `agentshield list-rules` | List registered detection rules |
| `agentshield init` | Generate starter `.agentshield.toml` |
| `agentshield suppress` | Add a fingerprint suppression with a required reason |
| `agentshield list-suppressions` | List configured suppressions and expiry status |
| `agentshield certify` | Generate a DSSE attestation envelope for scan results |
| `agentshield wrap` | Enforce egress policy around a command when built with `runtime` or `full` |
```

- [ ] **Step 5: Create `docs/releases/0.8.0.md`**

Write this structure:

```markdown
# AgentShield 0.8.0 Release Notes

## Scope

AgentShield 0.8.0 expands the scanner from static report generation into a broader agent-security workflow: suppression management, baselines, DSSE certification, egress policy generation, optional runtime egress enforcement, and additional adapters.

## Notable changes since 0.2.4

- Baseline file support for filtering known findings.
- Suppression management with required reasons and optional expiry dates.
- DSSE attestation generation through `agentshield certify`.
- Egress policy generation through `agentshield scan --emit-egress-policy`.
- Optional runtime egress enforcement through `agentshield wrap` when built with `runtime` or `full`.
- GPT Actions adapter.
- Cursor Rules adapter.
- Expanded public CLI surface and configuration examples.

## Release readiness checklist

- README describes current adapters and commands.
- CHANGELOG includes 0.8.0.
- Release binaries intentionally include or exclude runtime wrapping.
- GitHub Action docs match CLI behavior.
- VS Code extension compatibility is documented.
```

- [ ] **Step 6: Create `docs/RELEASE_CHECKLIST.md`**

Include this release checklist:

```markdown
# AgentShield Release Checklist

- Confirm `Cargo.toml` version.
- Update `CHANGELOG.md` with the release date and user-visible changes.
- Update README command examples if CLI flags changed.
- Confirm supported adapter list against `src/adapter/mod.rs`.
- Confirm release workflow feature flags.
- Confirm GitHub Action inputs and marketplace description.
- Confirm VS Code extension compatibility notes.
- Run `cargo test`.
- Run `cargo clippy -- -D warnings`.
- Run `cargo fmt --check`.
```

- [ ] **Step 7: Update CHANGELOG**

Add a top section:

```markdown
## [0.8.0] - 2026-06-05

### Added

- Baseline file support for filtering known findings.
- Suppression management commands with required reasons and optional expiry dates.
- DSSE attestation generation for scan results.
- Egress policy generation from static scan targets.
- Optional runtime egress enforcement behind the `runtime` feature.
- GPT Actions adapter.
- Cursor Rules adapter.

### Changed

- Documentation now reflects the current CLI and adapter surface.
- README avoids exact counts where implementation state changes frequently.
```

- [ ] **Step 8: Update `action.yml` description**

Change the action description from MCP/OpenClaw-only language to:

```yaml
description: 'Scan AI agent extensions for security vulnerabilities across supported AgentShield adapters'
```

- [ ] **Step 9: Validate docs-only changes**

```bash
cargo fmt --check
```

Expected: PASS, or no Rust formatting changes required.

- [ ] **Step 10: Commit**

```bash
git add README.md CHANGELOG.md action.yml docs/releases/0.8.0.md docs/RELEASE_CHECKLIST.md
git commit -m "docs: align release docs with 0.8.0 scope"
```

Return summary:
- Huly issues covered: AGENT-1, AGENT-2, AGENT-7.
- Files changed.
- Any unresolved release readiness questions.

---

## Agent Prompt: Trust Workflows Agent

### Task 2: Implement AGENT-3

**Files:**
- Create: `docs/BASELINES.md`
- Create: `docs/SUPPRESSIONS.md`
- Create: `docs/CERTIFICATION.md`
- Create: `docs/EGRESS.md`
- Modify: `README.md` only if the Release Docs Agent has already landed; otherwise return the README snippet for the coordinator.

- [ ] **Step 1: Inspect implementation points**

```bash
sed -n '1,220p' src/baseline.rs
sed -n '1,260p' src/rules/policy.rs
sed -n '1,240p' src/certify/envelope.rs
sed -n '1,260p' src/egress/policy.rs
sed -n '1,320p' src/bin/cli.rs
```

- [ ] **Step 2: Create `docs/BASELINES.md`**

Include exact commands:

```markdown
# Baselines

Use baselines to acknowledge existing findings while still failing on new findings.

Create a baseline from current findings:

```bash
agentshield scan . --write-baseline .agentshield-baseline.json
```

Filter known findings during later scans:

```bash
agentshield scan . --baseline .agentshield-baseline.json
```

Recommended CI pattern:

```bash
agentshield scan . --ignore-tests --baseline .agentshield-baseline.json --format sarif --output agentshield.sarif
```
```

- [ ] **Step 3: Create `docs/SUPPRESSIONS.md`**

Include exact commands:

```markdown
# Suppressions

Suppressions live in `.agentshield.toml` and require a reason.

Find the fingerprint:

```bash
agentshield scan . --format json
```

Add a suppression:

```bash
agentshield suppress <fingerprint> --reason "False positive: input is validated by middleware" --expires 2026-12-31
```

List suppressions:

```bash
agentshield list-suppressions
```

Expired suppressions are shown as expired and should be removed or renewed after review.
```

- [ ] **Step 4: Create `docs/CERTIFICATION.md`**

Include exact commands:

```markdown
# Certification

Generate an unsigned DSSE envelope:

```bash
agentshield certify . --output agentshield-attestation.dsse.json
```

Generate a signed envelope with a raw 32-byte Ed25519 private key:

```bash
agentshield certify . --sign-key ./ed25519.key --output agentshield-attestation.dsse.json
```

The attestation contains scanner metadata, findings, suppressions, and scan target metadata.
```

- [ ] **Step 5: Create `docs/EGRESS.md`**

Include exact commands:

```markdown
# Egress Policies

Generate a starter egress policy from static scan targets:

```bash
agentshield scan . --emit-egress-policy agentshield.egress.toml
```

Runtime enforcement is available only when the binary is built with `runtime` or `full`:

```bash
cargo build --features full --release
./target/release/agentshield wrap --policy agentshield.egress.toml -- npm test
```

Operator override policies can restrict generated policies further:

```bash
agentshield wrap --policy agentshield.egress.toml --override-policy operator.egress.toml -- npm test
```
```

- [ ] **Step 6: Return README integration snippet**

If README is not safe to edit in this branch, return this snippet to the coordinator:

```markdown
### Trust workflows

AgentShield also supports baseline filtering, fingerprint suppressions with reasons and expiry dates, DSSE attestations, and generated egress policies. See `docs/BASELINES.md`, `docs/SUPPRESSIONS.md`, `docs/CERTIFICATION.md`, and `docs/EGRESS.md`.
```

- [ ] **Step 7: Commit**

```bash
git add docs/BASELINES.md docs/SUPPRESSIONS.md docs/CERTIFICATION.md docs/EGRESS.md
git commit -m "docs: document trust workflow commands"
```

Return summary:
- Huly issue covered: AGENT-3.
- Whether README was modified or snippet returned.

---

## Agent Prompt: Runtime Release Agent

### Task 3: Implement AGENT-4

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `README.md` only if safe; otherwise return install snippet for coordinator.
- Modify: `docs/RELEASE_CHECKLIST.md` only if Release Docs Agent has landed; otherwise return checklist snippet.

- [ ] **Step 1: Inspect release workflow and features**

```bash
sed -n '1,260p' Cargo.toml
sed -n '1,320p' .github/workflows/release.yml
sed -n '1,260p' src/bin/cli.rs
```

- [ ] **Step 2: Decide release feature policy**

Use this decision unless contradicted by maintainer direction:

```text
Release binaries should be built with --features full so users get Python, TypeScript, and runtime wrap support in one binary.
```

- [ ] **Step 3: Update release workflow build commands**

The real release workflow has native and cross-compile build steps. Update both. Any native release build command that currently runs:

```bash
cargo build --release --target $TARGET
```

must become:

```bash
cargo build --release --features full --target $TARGET
```

Any cross release build command that currently runs:

```bash
cross build --release --target $TARGET
```

must become:

```bash
cross build --release --features full --target $TARGET
```

In the current workflow, this means patching both the native `cargo build --release --target ${{ matrix.target }}` line and the cross `cross build --release --target ${{ matrix.target }}` line. If the workflow has since been refactored to use a shared cargo args variable, update the shared variable instead of duplicating logic.

- [ ] **Step 4: Add release smoke check for wrap command**

Add a smoke check only for binaries that can execute on the current runner. Do not run the `aarch64-unknown-linux-gnu` cross-compiled binary on `ubuntu-latest`; that produces an exec format error.

For native Unix targets, add a workflow step equivalent to:

```bash
./target/${TARGET}/release/agentshield --help | grep -q "wrap"
```

Gate this step with the workflow's matrix metadata so it runs only when `matrix.cross` is false and `runner.os` is not Windows.

For native Windows targets, add a separate PowerShell step equivalent to:

```powershell
.\target\${{ matrix.target }}\release\agentshield.exe --help | Select-String -Quiet "wrap"
```

Gate this step with `matrix.cross == false` and `runner.os == 'Windows'`.

- [ ] **Step 5: Return README install snippet**

If README is not safe to edit in this branch, return:

```markdown
Release binaries are built with the `full` feature set, including Python and TypeScript parsing plus runtime egress enforcement through `agentshield wrap`.
```

- [ ] **Step 6: Return release checklist snippet**

If `docs/RELEASE_CHECKLIST.md` is not safe to edit in this branch, return:

```markdown
- Confirm release binaries are built with `--features full` and `agentshield --help` includes `wrap`.
```

- [ ] **Step 7: Validate workflow syntax by inspection only unless coordinator approves CI run**

Do not run release workflow locally. Run only formatting-safe checks:

```bash
cargo fmt --check
```

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build release binaries with full feature set"
```

Return summary:
- Huly issue covered: AGENT-4.
- Exact workflow build lines changed.
- Whether README/checklist snippets need coordinator integration.

---

## Agent Prompt: VS Code Agent

### Task 4: Implement AGENT-5

**Files:**
- Modify: `vscode/README.md`
- Modify: `vscode/CHANGELOG.md`
- Inspect: `vscode/src/scanner.ts`
- Inspect: `vscode/src/diagnostics.ts`
- Inspect: `vscode/src/types.ts`
- Optional Modify: `vscode/src/types.ts` if current JSON finding shape includes fields not represented.

- [ ] **Step 1: Inspect extension docs and JSON types**

```bash
sed -n '1,260p' vscode/README.md
sed -n '1,220p' vscode/CHANGELOG.md
sed -n '1,260p' vscode/src/types.ts
sed -n '1,260p' vscode/src/scanner.ts
sed -n '1,260p' vscode/src/diagnostics.ts
```

- [ ] **Step 2: Update supported framework docs**

Change framework wording to list:

```markdown
MCP, OpenClaw, CrewAI, LangChain/LangGraph, GPT Actions, and Cursor Rules.
```

- [ ] **Step 3: Update CLI compatibility section**

Add:

```markdown
## CLI Compatibility

The extension shells out to `agentshield scan --format json`. Use an AgentShield binary compatible with the extension's expected JSON output. If diagnostics do not appear, run the same command in a terminal and confirm the JSON includes `findings` with rule IDs, severity, location, message, remediation, and fingerprint fields.
```

- [ ] **Step 4: Add suppression UX note**

Add:

```markdown
## Suppressions

Suppressions are managed by the CLI. Run `agentshield scan . --format json` to get a finding fingerprint, then run `agentshield suppress <fingerprint> --reason "..."`. Future extension scans honor suppressions through the CLI configuration.
```

- [ ] **Step 5: Check `Finding` type compatibility**

If `vscode/src/types.ts` lacks an optional fingerprint field, add:

```typescript
fingerprint?: string;
```

on the finding interface that mirrors CLI JSON output.

- [ ] **Step 6: Update VS Code changelog**

Add:

```markdown
## Unreleased

### Changed

- Documentation now reflects the current AgentShield framework support.
- Added CLI compatibility and suppression workflow notes.
```

- [ ] **Step 7: Validate extension if package scripts exist**

```bash
cd vscode
npm install
npm run compile --if-present
npm test --if-present
```

- [ ] **Step 8: Commit**

```bash
git add vscode/README.md vscode/CHANGELOG.md vscode/src/types.ts
git commit -m "docs: update vscode extension compatibility notes"
```

Return summary:
- Huly issue covered: AGENT-5.
- Whether code type changes were needed.
- Validation command results.

---

## Agent Prompt: Doctor Agent

### Task 5: Implement AGENT-6

**Files:**
- Modify: `src/bin/cli.rs`
- Modify: `src/lib.rs` only if shared public types are needed.
- Create: `src/doctor.rs`
- Modify: `src/output/json.rs` only if reusing output helpers is clearly better than direct JSON serialization.
- Add tests in `src/doctor.rs` under `#[cfg(test)]`.

- [ ] **Step 1: Inspect CLI and public scan options**

```bash
sed -n '1,380p' src/bin/cli.rs
sed -n '1,220p' src/lib.rs
sed -n '1,220p' src/config/mod.rs
sed -n '1,220p' src/adapter/mod.rs
sed -n '1,180p' Cargo.toml
```

- [ ] **Step 2: Add doctor module export**

In `src/lib.rs`, add:

```rust
pub mod doctor;
```

near the other public modules.

- [ ] **Step 3: Create `src/doctor.rs`**

Use this implementation skeleton:

```rust
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::adapter::all_adapters;
use crate::config::Config;
use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub version: &'static str,
    pub target: PathBuf,
    pub config_path: PathBuf,
    pub config_found: bool,
    pub fail_on: String,
    pub ignore_tests: bool,
    pub enabled_features: EnabledFeatures,
    pub detected_adapters: Vec<String>,
    pub available_adapters: Vec<String>,
    pub runtime_wrap_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnabledFeatures {
    pub python: bool,
    pub typescript: bool,
    pub runtime: bool,
}

pub fn run_doctor(target: &Path, config_path: Option<PathBuf>, ignore_tests_override: bool) -> Result<DoctorReport> {
    let resolved_config_path = config_path.unwrap_or_else(|| target.join(".agentshield.toml"));
    let config_found = resolved_config_path.exists();
    let config = Config::load(&resolved_config_path)?;
    let ignore_tests = ignore_tests_override || config.scan.ignore_tests;

    let adapters = all_adapters();
    let available_adapters = adapters
        .iter()
        .map(|adapter| adapter.framework().to_string())
        .collect::<Vec<_>>();
    let detected_adapters = adapters
        .iter()
        .filter(|adapter| adapter.detect(target))
        .map(|adapter| adapter.framework().to_string())
        .collect::<Vec<_>>();

    Ok(DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        target: target.to_path_buf(),
        config_path: resolved_config_path,
        config_found,
        fail_on: config.policy.fail_on.to_string(),
        ignore_tests,
        enabled_features: EnabledFeatures {
            python: cfg!(feature = "python"),
            typescript: cfg!(feature = "typescript"),
            runtime: cfg!(feature = "runtime"),
        },
        detected_adapters,
        available_adapters,
        runtime_wrap_available: cfg!(feature = "runtime"),
    })
}
```

- [ ] **Step 4: Add CLI command enum variant**

In `src/bin/cli.rs`, add to `Commands`:

```rust
    /// Print environment, config, feature, and adapter diagnostics
    Doctor {
        /// Path to inspect
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Config file path
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Output JSON instead of console text
        #[arg(long)]
        json: bool,

        /// Include test-file ignore state as enabled even if only requested via CLI
        #[arg(long)]
        ignore_tests: bool,
    },
```

- [ ] **Step 5: Wire command dispatch**

Add match arm:

```rust
        Commands::Doctor {
            path,
            config,
            json,
            ignore_tests,
        } => cmd_doctor(path, config, json, ignore_tests),
```

- [ ] **Step 6: Add command handler**

Add to `src/bin/cli.rs`:

```rust
fn cmd_doctor(
    path: PathBuf,
    config: Option<PathBuf>,
    json: bool,
    ignore_tests: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    let report = agentshield::doctor::run_doctor(&path, config, ignore_tests)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!("AgentShield doctor");
    println!("  version: {}", report.version);
    println!("  target: {}", report.target.display());
    println!("  config: {} ({})", report.config_path.display(), if report.config_found { "found" } else { "not found" });
    println!("  fail_on: {}", report.fail_on);
    println!("  ignore_tests: {}", report.ignore_tests);
    println!("  features: python={}, typescript={}, runtime={}", report.enabled_features.python, report.enabled_features.typescript, report.enabled_features.runtime);
    println!("  wrap available: {}", report.runtime_wrap_available);
    println!("  detected adapters: {}", if report.detected_adapters.is_empty() { "none".to_string() } else { report.detected_adapters.join(", ") });
    println!("  available adapters: {}", report.available_adapters.join(", "));

    Ok(0)
}
```

- [ ] **Step 7: Add tests for doctor report**

In `src/doctor.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn doctor_reports_config_absence_and_features() {
        let tmp = TempDir::new().unwrap();
        let report = run_doctor(tmp.path(), None, false).unwrap();

        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert!(!report.config_found);
        assert!(!report.ignore_tests);
        assert_eq!(report.enabled_features.python, cfg!(feature = "python"));
        assert_eq!(report.enabled_features.typescript, cfg!(feature = "typescript"));
        assert_eq!(report.enabled_features.runtime, cfg!(feature = "runtime"));
    }

    #[test]
    fn doctor_applies_ignore_tests_override() {
        let tmp = TempDir::new().unwrap();
        let report = run_doctor(tmp.path(), None, true).unwrap();
        assert!(report.ignore_tests);
    }
}
```

- [ ] **Step 8: Validate targeted tests**

```bash
cargo test doctor
cargo fmt --check
cargo clippy -- -D warnings
```

- [ ] **Step 9: Commit**

```bash
git add src/doctor.rs src/lib.rs src/bin/cli.rs
git commit -m "feat: add doctor diagnostics command"
```

Return summary:
- Huly issue covered: AGENT-6.
- CLI output examples.
- Test command results.

---

## Coordinator Integration Plan

### Task 6: Merge parallel branches safely

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/RELEASE_CHECKLIST.md`
- Resolve conflicts from all branches.

- [ ] **Step 1: Merge low-conflict branches first**

```bash
git checkout coord/huly-roadmap-integration
git merge --no-ff docs/trust-workflows
git merge --no-ff vscode/current-cli-compat
git merge --no-ff feat/doctor-command
git merge --no-ff ci/runtime-release-flags
git merge --no-ff docs/release-state-0.8
```

If README conflicts occur, prefer the Release Docs Agent's structure and add links/snippets from other agents.

- [ ] **Step 2: Add trust workflow links to README**

Add:

```markdown
### Trust workflows

AgentShield supports baseline filtering, fingerprint suppressions with reasons and expiry dates, DSSE attestations, and generated egress policies. See `docs/BASELINES.md`, `docs/SUPPRESSIONS.md`, `docs/CERTIFICATION.md`, and `docs/EGRESS.md`.
```

- [ ] **Step 3: Add doctor command to README command table**

Add row:

```markdown
| `agentshield doctor` | Print environment, config, compile-feature, and adapter diagnostics |
```

- [ ] **Step 4: Add runtime feature note to README**

Add:

```markdown
Release binaries are built with the `full` feature set when runtime wrapping is enabled for distribution. If building from source, use `cargo build --features full --release` to include `agentshield wrap`.
```

- [ ] **Step 5: Final validation**

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
cd vscode && npm install && npm run compile --if-present && npm test --if-present
```

- [ ] **Step 6: Final commit**

```bash
git add README.md CHANGELOG.md docs/RELEASE_CHECKLIST.md
git commit -m "docs: integrate 0.8.0 roadmap work"
```

Return summary:
- Merged branches.
- Huly issues closed by implementation.
- Validation results.

---

## Parallel Dispatch Order

Start these agents concurrently after worktrees are ready:

```text
Dispatch Release Docs Agent to .worktrees/docs-release-state-0.8
Dispatch Trust Workflows Agent to .worktrees/docs-trust-workflows
Dispatch Runtime Release Agent to .worktrees/ci-runtime-release-flags
Dispatch VS Code Agent to .worktrees/vscode-current-cli-compat
Dispatch Doctor Agent to .worktrees/feat-doctor-command
```

Do not dispatch the Coordinator until all five agents return.

## Agent Completion Contract

Each agent must return:

```text
Huly issue(s): AGENT-N
Branch:
Commit(s):
Files changed:
Validation commands run:
Validation result:
Coordinator snippets needed:
Risks or follow-ups:
```

## Merge Risk Controls

- Only the Coordinator owns final README integration.
- Agents should avoid editing README if their branch would conflict; return snippets instead.
- The Doctor Agent owns Rust CLI code.
- The VS Code Agent owns `vscode/`.
- The Runtime Release Agent owns `.github/workflows/release.yml`.
- The Trust Workflows Agent owns dedicated docs pages.
- The Release Docs Agent owns release narrative and count-drift cleanup.
