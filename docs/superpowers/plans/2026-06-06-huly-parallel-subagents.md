# AgentShield Huly Parallel Subagents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the open Huly `AGENT` project issues into safe parallel worktree lanes that can be implemented by separate coding agents without trampling each other's files.

**Architecture:** Use one Git worktree per independent lane, with clear file ownership and a merge order that keeps runtime contracts ahead of runtime implementation. Runtime work is split into a schema/model lane, a redaction lane, and a guard CLI lane; release automation, docs/design, and static scanner hardening run separately.

**Tech Stack:** Rust, Cargo, Clap CLI, Serde JSON, shell scripts, GitHub Actions, Docker Buildx, Markdown docs, Huly Platform API.

---

## Source Inputs

Huly project lookup was performed with the repository-local skill at `skills/huly/SKILL.md` using project `AGENT`.

Open Huly issues to plan:

| Issue | Status | Priority | Title |
|---|---|---:|---|
| `AGENT-9` | Todo | High | Optimize Docker multi-arch release build time |
| `AGENT-10` | Todo | High | Automate release checklist beyond tag/version guard |
| `AGENT-11` | Todo | High | Publish agent-shield crate version 0.8.3 to crates.io |
| `AGENT-12` | Backlog | High | Clarify AgentShield positioning in docs |
| `AGENT-13` | Backlog | Medium | Add runtime guard roadmap section |
| `AGENT-14` | Backlog | High | Design shared policy event model |
| `AGENT-15` | Backlog | High | Add secret detection and redaction helpers |
| `AGENT-16` | Backlog | High | Add experimental agentshield guard --stdin |
| `AGENT-17` | Backlog | Medium | Add runtime JSON output schema |
| `AGENT-18` | Backlog | Medium | Design MCP proxy guard mode |
| `AGENT-19` | Backlog | Medium | Improve static scanner before broader runtime work |

Repository root:

```bash
/Users/ronaldo/Projects/_aiconnai/agentshield
```

Huly skill path:

```bash
/Users/ronaldo/Projects/_aiconnai/agentshield/skills/huly/SKILL.md
```

Huly environment file:

```bash
/Users/ronaldo/Projects/_aiconnai/agentshield/.env
```

Do not print Huly token values. The repo currently uses `HULY_APY_TOKEN`; the Huly skill explicitly treats that typo as a supported compatibility fallback.

---

## Global Execution Rules for All Coding Agents

- Work in the assigned worktree only.
- Do not edit files outside the lane ownership list unless the coordinator approves the conflict.
- Do not use `git add .` or `git add -A`.
- Use explicit `git add <file>` paths only.
- Do not use destructive Git commands such as `git reset --hard` or `git checkout --`.
- Keep commits small and mention the Huly issue identifier in the commit body or subject.
- Before a lane starts, run the harness issue boundary command from that worktree.
- Before a lane is marked complete, create version-control evidence with an explicit commit or a current `jj` description that mentions the issue.
- Use raw output for final JSON, SARIF, HTML, and console artifacts consumed by users, clients, CI, or GitHub Code Scanning.
- `rtk` may be used only to filter noisy local check output.

Harness commands available in each worktree:

```bash
bash docs/harness/bin/vc-gate.sh status
bash docs/harness/bin/vc-gate.sh start AGENT-9
bash docs/harness/bin/review-gate.sh pre AGENT-9
bash docs/harness/bin/sensors.sh
bash docs/harness/bin/review-gate.sh post AGENT-9
bash docs/harness/bin/check-commit-msg.sh --message "feat(runtime): add shared policy event model"
bash docs/harness/bin/vc-gate.sh done AGENT-9
```

Use the actual issue identifier for each lane.

---

## Worktree Topology

Run these commands from the base repository only after the coordinator confirms the current worktree is ready for issue work:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield

git worktree add ../agentshield-agent-9-10-release-ci -b feat/agent-9-10-release-ci

git worktree add ../agentshield-agent-12-13-18-docs -b docs/agent-12-13-18-positioning-roadmap

git worktree add ../agentshield-agent-14-17-runtime-model -b feat/agent-14-17-runtime-model

git worktree add ../agentshield-agent-19-static-hardening -b feat/agent-19-static-hardening
```

After `feat/agent-14-17-runtime-model` is merged or explicitly approved as the base for dependent work, create these dependent worktrees from that branch or from the updated mainline:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield

git worktree add ../agentshield-agent-15-redaction -b feat/agent-15-secret-redaction

git worktree add ../agentshield-agent-16-guard-stdin -b feat/agent-16-guard-stdin
```

Do not create a worktree for `AGENT-11` until the release gate is green and a human confirms publishing is allowed.

---

## Merge Order

1. Merge `feat/agent-14-17-runtime-model` first among runtime branches.
2. Merge `feat/agent-15-secret-redaction` after the runtime model exists.
3. Merge `feat/agent-16-guard-stdin` after the runtime model and redaction helpers exist.
4. Merge `feat/agent-19-static-hardening` independently unless it edits runtime files.
5. Merge `docs/agent-12-13-18-positioning-roadmap` after runtime naming is stable.
6. Merge `feat/agent-9-10-release-ci` independently, but before publishing.
7. Execute `AGENT-11` only after all intended `0.8.3` release changes are merged.

---

## File Ownership Matrix

| Lane | Owns | Must Avoid |
|---|---|---|
| `AGENT-9/10` release CI | `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `Dockerfile`, `docs/RELEASE_CHECKLIST.md`, `docs/harness/bin/release-checklist.sh`, `docs/harness/GATES.md` | `src/runtime/*`, `src/rules/*` |
| `AGENT-12/13/18` docs/design | `README.md`, `docs/NEXT_STEPS.md`, `docs/ARCHITECTURE.md`, `docs/RUNTIME_GUARD.md`, `docs/BLOG_POST.md` | `.github/workflows/*`, `Dockerfile`, `src/runtime/*` |
| `AGENT-14/17` runtime model/schema | `src/runtime/mod.rs`, `src/runtime/event.rs`, `src/runtime/schema.rs`, `src/lib.rs`, `tests/runtime_event.rs`, `tests/runtime_schema.rs`, `docs/RUNTIME_JSON_SCHEMA.md` | `src/bin/cli.rs`, `.github/workflows/*` |
| `AGENT-15` redaction | `src/runtime/redaction.rs`, `src/runtime/mod.rs`, `tests/runtime_redaction.rs`, `docs/RUNTIME_GUARD.md` | release workflows, static detector files unless coordinator approves |
| `AGENT-16` guard CLI | `src/runtime/guard.rs`, `src/runtime/mod.rs`, `src/bin/cli.rs`, `tests/runtime_guard.rs`, `docs/RUNTIME_GUARD.md` | release workflows, static detector files |
| `AGENT-19` scanner hardening | `src/analysis/cross_file.rs`, `src/parser/typescript.rs`, `src/parser/python.rs`, `src/rules/builtin/credential_exfil.rs`, `src/rules/builtin/secret_leakage.rs`, `tests/fixtures/mcp_servers/safe_redacted_logging/*`, `tests/fixtures/mcp_servers/vuln_cred_exfil/*` | runtime guard CLI files unless coordinator approves |
| `AGENT-11` publish | `Cargo.toml`, `CHANGELOG.md`, `docs/releases/0.8.3.md`, release tag `v0.8.3` | any unrelated code |

---

## Task 0: Coordinator Setup and Dispatch

**Files:**
- Read: `skills/huly/SKILL.md`
- Read: `.env`
- No product source files modified by this task.

- [ ] **Step 1: Confirm Huly access without printing secrets**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
set -a
. ./.env
set +a
printf 'HULY_URL=%s\nHULY_WORKSPACE=%s\nHULY_PROJECT=%s\n' "$HULY_URL" "$HULY_WORKSPACE" "$HULY_PROJECT"
if [ -n "${HULY_API_TOKEN:-${HULY_TOKEN:-${HULY_APY_TOKEN:-}}}" ]; then printf 'HULY_TOKEN=<set>\n'; else printf 'HULY_TOKEN=<missing>\n'; fi
```

Expected output shape:

```text
HULY_URL=https://huly.app/workbench/<workspace>/
HULY_WORKSPACE=<workspace>
HULY_PROJECT=AGENT
HULY_TOKEN=<set>
```

- [ ] **Step 2: Create the wave-one worktrees**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield

git worktree add ../agentshield-agent-9-10-release-ci -b feat/agent-9-10-release-ci

git worktree add ../agentshield-agent-12-13-18-docs -b docs/agent-12-13-18-positioning-roadmap

git worktree add ../agentshield-agent-14-17-runtime-model -b feat/agent-14-17-runtime-model

git worktree add ../agentshield-agent-19-static-hardening -b feat/agent-19-static-hardening
```

Expected: each command creates a new worktree directory under `/Users/ronaldo/Projects/_aiconnai/`.

- [ ] **Step 3: Dispatch wave-one subagents**

Use these exact worktree roots:

```text
/Users/ronaldo/Projects/_aiconnai/agentshield-agent-9-10-release-ci
/Users/ronaldo/Projects/_aiconnai/agentshield-agent-12-13-18-docs
/Users/ronaldo/Projects/_aiconnai/agentshield-agent-14-17-runtime-model
/Users/ronaldo/Projects/_aiconnai/agentshield-agent-19-static-hardening
```

Each subagent receives the matching task section from this document and the global execution rules.

---

## Task 1: `AGENT-9/10` Release CI and Release Checklist Automation

**Worktree:** `/Users/ronaldo/Projects/_aiconnai/agentshield-agent-9-10-release-ci`

**Goal:** Reduce Docker multi-arch release build time and automate release readiness checks beyond the existing version/tag guard.

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/ci.yml`
- Modify: `Dockerfile`
- Modify: `docs/RELEASE_CHECKLIST.md`
- Create: `docs/harness/bin/release-checklist.sh`
- Modify: `docs/harness/GATES.md`

- [ ] **Step 1: Start the Huly issue boundary**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield-agent-9-10-release-ci
bash docs/harness/bin/vc-gate.sh start AGENT-9
bash docs/harness/bin/review-gate.sh pre AGENT-9
```

Expected: the harness allows issue work to start or prints the dirty work that must be assigned before continuing.

- [ ] **Step 2: Inspect only the release-owned files**

Run:

```bash
sed -n '1,260p' .github/workflows/release.yml
sed -n '1,220p' .github/workflows/ci.yml
sed -n '1,220p' Dockerfile
sed -n '1,220p' docs/RELEASE_CHECKLIST.md
sed -n '1,220p' docs/harness/GATES.md
```

Expected: enough local context to edit only this lane's owned files.

- [ ] **Step 3: Optimize Docker multi-arch build time**

Implement these concrete workflow requirements in `.github/workflows/release.yml`:

```yaml
- Use docker/setup-qemu-action@v3 only for Docker multi-arch jobs.
- Use docker/setup-buildx-action@v3 before Docker builds.
- Use docker/build-push-action@v6 for Docker image builds.
- Add GitHub Actions cache to buildx with cache-from and cache-to.
- Keep Rust binary release artifacts separate from Docker image publishing.
- Avoid rebuilding identical Cargo dependencies separately for each Docker platform when the workflow can use buildx layer caching.
```

The Docker build step should include this cache shape unless the workflow already has a stronger equivalent:

```yaml
cache-from: type=gha,scope=agentshield-docker
cache-to: type=gha,mode=max,scope=agentshield-docker
```

If `.github/workflows/release.yml` uses a platform matrix, collapse Docker image publishing to a single Buildx invocation with:

```yaml
platforms: linux/amd64,linux/arm64
```

Do not remove existing release artifacts for macOS, Linux, or Windows binaries.

- [ ] **Step 4: Add release checklist automation script**

Create `docs/harness/bin/release-checklist.sh` with executable permissions and this behavior:

```bash
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash docs/harness/bin/release-checklist.sh <version> [--allow-untagged]

Runs the local release readiness checklist for AgentShield.

Checks:
- Git worktree state through vc-gate release
- Cargo.toml version gate
- release tag gate, unless --allow-untagged is supplied
- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test
- cargo publish --dry-run
EOF
}

version="${1:-}"
allow_untagged="${2:-}"

if [[ -z "$version" || "$version" == "-h" || "$version" == "--help" ]]; then
  usage
  exit 2
fi

if [[ -n "$allow_untagged" && "$allow_untagged" != "--allow-untagged" ]]; then
  usage
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

release_args=("$version")
if [[ "$allow_untagged" == "--allow-untagged" ]]; then
  release_args+=("--allow-untagged")
fi

bash docs/harness/bin/vc-gate.sh release "${release_args[@]}"

cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo publish --dry-run
```

Then run:

```bash
chmod +x docs/harness/bin/release-checklist.sh
```

- [ ] **Step 5: Document the new release command**

Update `docs/RELEASE_CHECKLIST.md` to include this exact local pre-publish flow:

```bash
git status --short
bash docs/harness/bin/release-checklist.sh 0.8.3 --allow-untagged

git tag -a v0.8.3 -m "Release v0.8.3"

bash docs/harness/bin/release-checklist.sh 0.8.3
```

Clarify that `cargo publish` is a human-approved final action and must not run from a dirty worktree.

- [ ] **Step 6: Document the release gate in harness docs**

Update `docs/harness/GATES.md` with a section named `Release checklist gate` that lists:

```text
- vc-gate release <version>
- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test
- cargo publish --dry-run
- tag v<version> points to HEAD before final publish
```

- [ ] **Step 7: Validate this lane only**

Run:

```bash
bash docs/harness/bin/release-checklist.sh 0.8.3 --allow-untagged
```

Expected: all checks pass, or the output identifies the next concrete release-blocking failure.

- [ ] **Step 8: Commit explicitly**

Run:

```bash
git add .github/workflows/release.yml .github/workflows/ci.yml Dockerfile docs/RELEASE_CHECKLIST.md docs/harness/bin/release-checklist.sh docs/harness/GATES.md
git commit -m "ci(release): automate AGENT-9 AGENT-10 release checks"
bash docs/harness/bin/vc-gate.sh done AGENT-9
```

---

## Task 2: `AGENT-12/13/18` Documentation Positioning and Runtime Roadmap

**Worktree:** `/Users/ronaldo/Projects/_aiconnai/agentshield-agent-12-13-18-docs`

**Goal:** Make AgentShield's current static-scanner position clear while documenting the runtime guard roadmap and MCP proxy guard design.

**Files:**
- Modify: `README.md`
- Modify: `docs/NEXT_STEPS.md`
- Modify: `docs/ARCHITECTURE.md`
- Create: `docs/RUNTIME_GUARD.md`
- Modify: `docs/BLOG_POST.md`

- [ ] **Step 1: Start the Huly issue boundary**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield-agent-12-13-18-docs
bash docs/harness/bin/vc-gate.sh start AGENT-12
bash docs/harness/bin/review-gate.sh pre AGENT-12
```

Expected: the harness allows docs work to start or identifies unassigned dirty work.

- [ ] **Step 2: Inspect docs-owned files**

Run:

```bash
sed -n '1,260p' README.md
sed -n '1,260p' docs/NEXT_STEPS.md
sed -n '1,260p' docs/ARCHITECTURE.md
sed -n '1,220p' docs/BLOG_POST.md
```

- [ ] **Step 3: Add positioning language to `README.md`**

Add a section near the top of `README.md` named `What AgentShield is today` with this content adapted to the surrounding style:

```markdown
## What AgentShield is today

AgentShield is an offline-first static security scanner for AI agent extensions. It analyzes MCP servers, OpenClaw skills, CrewAI tools, LangChain tools, and related agent extension surfaces before they run, then reports findings through console, JSON, SARIF, and HTML outputs.

AgentShield is not a hosted monitoring service, a runtime sandbox, or an allowlist marketplace. Runtime guard work is tracked as an experimental roadmap item; the current stable contract remains static scanning plus policy evaluation.
```

Add a short `Runtime guard roadmap` pointer that links to `docs/RUNTIME_GUARD.md`.

- [ ] **Step 4: Add the roadmap to `docs/NEXT_STEPS.md`**

Add a section named `Runtime guard roadmap` with these stages:

```markdown
## Runtime guard roadmap

1. Shared policy event model: define one JSON event shape for static scanner findings, runtime guard observations, and future MCP proxy decisions.
2. Secret redaction helpers: detect and redact common credentials before runtime events are written to logs or JSON output.
3. Experimental `agentshield guard --stdin`: accept one runtime event from standard input and emit a machine-readable allow, warn, or block result.
4. MCP proxy guard mode: design a local proxy that can observe tool calls and apply policy before tool execution.
5. Production hardening: add stable policy configuration, integration tests, and compatibility guarantees before runtime mode is considered stable.
```

- [ ] **Step 5: Update `docs/ARCHITECTURE.md`**

Add a runtime roadmap subsection that states:

```markdown
Runtime guard components must consume the same policy concepts as static detection, but they must not change SARIF, JSON, HTML, or console scanner output contracts unless a versioned output schema explicitly opts in. Runtime data should flow through a redaction layer before logs or structured output are emitted.
```

- [ ] **Step 6: Create `docs/RUNTIME_GUARD.md`**

Create the file with these sections:

```markdown
# AgentShield Runtime Guard Roadmap

## Status

Runtime guard support is experimental roadmap work. The stable AgentShield contract remains offline static scanning and policy evaluation.

## Shared policy event model

Runtime components should represent observations as versioned policy events. A policy event records the action, source framework, tool name, arguments, redaction state, and optional static-finding correlation.

## Experimental stdin guard

The first executable runtime entrypoint should be `agentshield guard --stdin`. It reads one JSON policy event from standard input and writes one JSON guard result to standard output.

## MCP proxy guard mode

A future MCP proxy guard can sit between a client and an MCP server. It should inspect tool calls, apply configured policy, redact secrets before logging, and return allow, warn, or block decisions.

## Non-goals

- No hosted telemetry requirement.
- No network dependency for local guard decisions.
- No mutation of SARIF output used by GitHub Code Scanning.
- No bypass of existing static scanner policy controls.
```

- [ ] **Step 7: Update `docs/BLOG_POST.md`**

Ensure the blog language distinguishes current capabilities from future runtime work. Use this wording where appropriate:

```markdown
AgentShield starts with static analysis because agent extensions often reveal their risk surface in code, manifests, schemas, dependencies, and tool definitions before execution. Runtime guard work is planned as an incremental extension, not a replacement for offline scanning.
```

- [ ] **Step 8: Commit explicitly**

Run:

```bash
git add README.md docs/NEXT_STEPS.md docs/ARCHITECTURE.md docs/RUNTIME_GUARD.md docs/BLOG_POST.md
git commit -m "docs(runtime): clarify AGENT-12 AGENT-13 AGENT-18 roadmap"
bash docs/harness/bin/vc-gate.sh done AGENT-12
```

---

## Task 3: `AGENT-14/17` Shared Runtime Policy Event Model and JSON Schema

**Worktree:** `/Users/ronaldo/Projects/_aiconnai/agentshield-agent-14-17-runtime-model`

**Goal:** Add a small, versioned runtime policy event model and JSON output/result schema that later guard and redaction work can consume.

**Files:**
- Create: `src/runtime/mod.rs`
- Create: `src/runtime/event.rs`
- Create: `src/runtime/schema.rs`
- Modify: `src/lib.rs`
- Create: `tests/runtime_event.rs`
- Create: `tests/runtime_schema.rs`
- Create: `docs/RUNTIME_JSON_SCHEMA.md`

- [ ] **Step 1: Start the Huly issue boundary**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield-agent-14-17-runtime-model
bash docs/harness/bin/vc-gate.sh start AGENT-14
bash docs/harness/bin/review-gate.sh pre AGENT-14
```

- [ ] **Step 2: Inspect only runtime export context**

Run:

```bash
sed -n '1,220p' src/lib.rs
sed -n '1,220p' src/output/json.rs
sed -n '1,220p' src/rules/finding.rs
```

- [ ] **Step 3: Create `src/runtime/mod.rs`**

Create the module with this public surface:

```rust
pub mod event;
pub mod schema;

pub use event::{
    RuntimeAction, RuntimeEvent, RuntimeEventSource, RuntimeGuardFinding, RuntimeGuardResult,
    RuntimeSchemaVersion, RuntimeSeverity, RuntimeVerdict,
};
pub use schema::{runtime_event_schema_json, runtime_guard_result_schema_json};
```

Do not add `redaction` or `guard` modules in this task; those are owned by later lanes.

- [ ] **Step 4: Create `src/runtime/event.rs`**

Define these serializable types:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSchemaVersion {
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAction {
    ToolCall,
    Command,
    FileRead,
    FileWrite,
    NetworkRequest,
    SecretObserved,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventSource {
    Mcp,
    OpenClaw,
    CrewAi,
    LangChain,
    Stdin,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeVerdict {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeEvent {
    pub schema_version: RuntimeSchemaVersion,
    pub source: RuntimeEventSource,
    pub action: RuntimeAction,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub arguments: serde_json::Value,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeGuardFinding {
    pub rule_id: String,
    pub severity: RuntimeSeverity,
    pub message: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeGuardResult {
    pub schema_version: RuntimeSchemaVersion,
    pub verdict: RuntimeVerdict,
    pub findings: Vec<RuntimeGuardFinding>,
    pub redacted: bool,
}
```

If the project already has a no-direct-`serde` style, follow the existing style while preserving the exact field names above.

- [ ] **Step 5: Create `src/runtime/schema.rs`**

Provide hard-coded JSON schema helper functions for external docs and tests:

```rust
pub fn runtime_event_schema_json() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AgentShield Runtime Event",
        "type": "object",
        "required": ["schema_version", "source", "action", "arguments", "redacted"],
        "properties": {
            "schema_version": { "enum": ["v1"] },
            "source": { "type": "string" },
            "action": { "type": "string" },
            "tool_name": { "type": ["string", "null"] },
            "command": { "type": ["string", "null"] },
            "url": { "type": ["string", "null"] },
            "path": { "type": ["string", "null"] },
            "arguments": { "type": ["object", "array", "string", "number", "boolean", "null"] },
            "redacted": { "type": "boolean" }
        }
    })
}

pub fn runtime_guard_result_schema_json() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AgentShield Runtime Guard Result",
        "type": "object",
        "required": ["schema_version", "verdict", "findings", "redacted"],
        "properties": {
            "schema_version": { "enum": ["v1"] },
            "verdict": { "enum": ["allow", "warn", "block"] },
            "findings": { "type": "array" },
            "redacted": { "type": "boolean" }
        }
    })
}
```

- [ ] **Step 6: Export the runtime module from `src/lib.rs`**

Add:

```rust
pub mod runtime;
```

Keep existing public API exports intact.

- [ ] **Step 7: Add serialization tests**

Create `tests/runtime_event.rs` with tests that assert:

```text
RuntimeSchemaVersion::V1 serializes as "v1".
RuntimeVerdict::Allow serializes as "allow".
A RuntimeEvent round-trips through serde_json.
A RuntimeGuardResult with zero findings serializes with an empty findings array.
```

- [ ] **Step 8: Add schema tests**

Create `tests/runtime_schema.rs` with tests that assert:

```text
runtime_event_schema_json() has title "AgentShield Runtime Event".
runtime_guard_result_schema_json() has title "AgentShield Runtime Guard Result".
Both schemas include schema_version in required fields.
```

- [ ] **Step 9: Document the JSON schema**

Create `docs/RUNTIME_JSON_SCHEMA.md` with sections:

```markdown
# AgentShield Runtime JSON Schema

## RuntimeEvent

A runtime event is an observation supplied to experimental guard components. Version `v1` includes source, action, optional command/url/path/tool fields, arbitrary JSON arguments, and a boolean redaction marker.

## RuntimeGuardResult

A guard result is the machine-readable decision emitted by experimental runtime guard components. Version `v1` returns `allow`, `warn`, or `block`, plus zero or more findings.

## Compatibility

Runtime JSON is experimental. It must not change stable scanner JSON, SARIF, HTML, or console output contracts.
```

- [ ] **Step 10: Validate and commit**

Run:

```bash
cargo test runtime_event runtime_schema
```

Then commit explicitly:

```bash
git add src/runtime/mod.rs src/runtime/event.rs src/runtime/schema.rs src/lib.rs tests/runtime_event.rs tests/runtime_schema.rs docs/RUNTIME_JSON_SCHEMA.md
git commit -m "feat(runtime): add AGENT-14 AGENT-17 policy event schema"
bash docs/harness/bin/vc-gate.sh done AGENT-14
```

---

## Task 4: `AGENT-15` Secret Detection and Redaction Helpers

**Worktree:** `/Users/ronaldo/Projects/_aiconnai/agentshield-agent-15-redaction`

**Dependency:** Start after `AGENT-14/17` runtime model is merged or rebased into this worktree.

**Goal:** Add deterministic secret detection and redaction helpers for runtime events without exposing raw secret values in guard output.

**Files:**
- Create: `src/runtime/redaction.rs`
- Modify: `src/runtime/mod.rs`
- Create: `tests/runtime_redaction.rs`
- Modify: `docs/RUNTIME_GUARD.md`

- [ ] **Step 1: Start the Huly issue boundary**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield-agent-15-redaction
bash docs/harness/bin/vc-gate.sh start AGENT-15
bash docs/harness/bin/review-gate.sh pre AGENT-15
```

- [ ] **Step 2: Add module export**

Modify `src/runtime/mod.rs` to add:

```rust
pub mod redaction;

pub use redaction::{redact_runtime_event, redact_text, Redaction, RedactionKind, RedactionReport};
```

Keep the existing `event` and `schema` exports.

- [ ] **Step 3: Create `src/runtime/redaction.rs`**

Implement these public types and functions:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    OpenAiApiKey,
    GitHubToken,
    AwsAccessKeyId,
    BearerToken,
    GenericSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Redaction {
    pub kind: RedactionKind,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedactionReport {
    pub redacted_text: String,
    pub redactions: Vec<Redaction>,
}

pub fn redact_text(input: &str) -> RedactionReport {
    // implementation must scan for known secret patterns and return redacted_text
}

pub fn redact_runtime_event(event: crate::runtime::RuntimeEvent) -> (crate::runtime::RuntimeEvent, Vec<Redaction>) {
    // implementation must redact command, url, path, tool_name, and string values in arguments
}
```

Replace the comments with working code. Use focused pattern matching and avoid storing matched secret text in `Redaction`.

Required redaction replacements:

```text
OpenAI key: [REDACTED:openai_api_key]
GitHub token: [REDACTED:github_token]
AWS access key id: [REDACTED:aws_access_key_id]
Bearer token: Bearer [REDACTED:bearer_token]
Generic key/value secret: <key>=[REDACTED:generic_secret]
```

Recognize at least these patterns:

```text
sk-[A-Za-z0-9_-]{20,}
ghp_[A-Za-z0-9_]{20,}
AKIA[0-9A-Z]{16}
Bearer [A-Za-z0-9._~+/=-]{20,}
(api_key|apikey|token|secret|password)=<non-empty-value>
```

- [ ] **Step 4: Add tests**

Create `tests/runtime_redaction.rs` with tests for:

```text
OpenAI API key redaction does not contain the original key.
GitHub token redaction does not contain the original token.
Bearer token redaction preserves the word Bearer but removes the token value.
Generic api_key=value redaction removes the value.
RuntimeEvent argument redaction marks the event as redacted.
Redaction ranges do not include raw secret text.
```

- [ ] **Step 5: Document redaction behavior**

Update `docs/RUNTIME_GUARD.md` with:

```markdown
## Secret redaction

Runtime guard code must redact secrets before writing events or findings to stdout, stderr, logs, JSON files, or future proxy traces. Redaction reports include secret kind and byte offsets only; they must not include the raw secret text.
```

- [ ] **Step 6: Validate and commit**

Run:

```bash
cargo test runtime_redaction
```

Then commit explicitly:

```bash
git add src/runtime/redaction.rs src/runtime/mod.rs tests/runtime_redaction.rs docs/RUNTIME_GUARD.md
git commit -m "feat(runtime): add AGENT-15 secret redaction helpers"
bash docs/harness/bin/vc-gate.sh done AGENT-15
```

---

## Task 5: `AGENT-16` Experimental `agentshield guard --stdin`

**Worktree:** `/Users/ronaldo/Projects/_aiconnai/agentshield-agent-16-guard-stdin`

**Dependency:** Start after `AGENT-14/17` and `AGENT-15` are merged or rebased into this worktree.

**Goal:** Add an experimental CLI entrypoint that reads a runtime event from stdin and writes a runtime guard result as JSON.

**Files:**
- Create: `src/runtime/guard.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/bin/cli.rs`
- Create: `tests/runtime_guard.rs`
- Modify: `docs/RUNTIME_GUARD.md`

- [ ] **Step 1: Start the Huly issue boundary**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield-agent-16-guard-stdin
bash docs/harness/bin/vc-gate.sh start AGENT-16
bash docs/harness/bin/review-gate.sh pre AGENT-16
```

- [ ] **Step 2: Inspect CLI shape**

Run:

```bash
sed -n '1,320p' src/bin/cli.rs
sed -n '1,220p' src/error.rs
sed -n '1,220p' src/runtime/mod.rs
```

- [ ] **Step 3: Add guard module export**

Modify `src/runtime/mod.rs` to add:

```rust
pub mod guard;

pub use guard::evaluate_runtime_event;
```

- [ ] **Step 4: Create `src/runtime/guard.rs`**

Implement `evaluate_runtime_event(event: RuntimeEvent) -> RuntimeGuardResult` with this behavior:

```text
- Redact the incoming event with redact_runtime_event before inspecting or returning evidence.
- Return verdict warn if any secret redaction occurred.
- Return verdict block for network_request events where url contains 169.254.169.254.
- Return verdict allow when no finding is present.
- Include rule_id AGENTSHIELD-RUNTIME-SECRET for secret redaction findings.
- Include rule_id AGENTSHIELD-RUNTIME-METADATA-SSRF for metadata endpoint findings.
- Never include raw secret values in finding evidence.
```

Required finding messages:

```text
Secret material observed in runtime event
Runtime network request targets cloud metadata endpoint
```

Severity mapping:

```text
secret observed -> high
metadata SSRF -> critical
allow/no finding -> no findings
```

- [ ] **Step 5: Add CLI subcommand**

Modify `src/bin/cli.rs` to support:

```bash
agentshield guard --stdin
```

Behavior:

```text
- Reads all stdin as UTF-8 JSON.
- Parses it as RuntimeEvent.
- Calls evaluate_runtime_event.
- Prints pretty JSON RuntimeGuardResult to stdout.
- Exits 0 for allow and warn.
- Exits 3 for block.
- Exits 2 for malformed input or unsupported invocation.
- Marks the subcommand experimental in help text.
```

- [ ] **Step 6: Add tests**

Create `tests/runtime_guard.rs` with tests for:

```text
allow event returns verdict allow.
secret event returns verdict warn and redacted true.
metadata endpoint network_request returns verdict block.
secret evidence never includes the raw original secret.
```

If the project already has CLI integration test helpers, use them. Otherwise test `evaluate_runtime_event` directly and add one process-level smoke test for the binary only if existing integration tests already spawn the CLI.

- [ ] **Step 7: Document CLI usage**

Update `docs/RUNTIME_GUARD.md` with:

```markdown
## Experimental CLI

Example:

```bash
printf '%s\n' '{"schema_version":"v1","source":"stdin","action":"network_request","tool_name":null,"command":null,"url":"http://169.254.169.254/latest/meta-data/","path":null,"arguments":{},"redacted":false}' \
  | agentshield guard --stdin
```

A blocked event exits with code `3`. Malformed input exits with code `2`. This command is experimental and does not alter static scanner output contracts.
```

- [ ] **Step 8: Validate and commit**

Run:

```bash
cargo test runtime_guard
cargo run -- guard --stdin <<'EOF'
{"schema_version":"v1","source":"stdin","action":"network_request","tool_name":null,"command":null,"url":"http://169.254.169.254/latest/meta-data/","path":null,"arguments":{},"redacted":false}
EOF
```

Expected: test pass; the command prints a JSON guard result with `"verdict": "block"` and exits with code `3`.

Commit explicitly:

```bash
git add src/runtime/guard.rs src/runtime/mod.rs src/bin/cli.rs tests/runtime_guard.rs docs/RUNTIME_GUARD.md
git commit -m "feat(runtime): add AGENT-16 experimental stdin guard"
bash docs/harness/bin/vc-gate.sh done AGENT-16
```

---

## Task 6: `AGENT-19` Static Scanner Hardening Before Runtime Work

**Worktree:** `/Users/ronaldo/Projects/_aiconnai/agentshield-agent-19-static-hardening`

**Goal:** Add regression coverage and sanitizer recognition so static scanning treats explicit redaction helpers as safe where appropriate while preserving true credential exfiltration detections.

**Files:**
- Modify: `src/analysis/cross_file.rs`
- Modify: `src/parser/typescript.rs`
- Modify: `src/parser/python.rs`
- Modify: `src/rules/builtin/credential_exfil.rs`
- Modify: `src/rules/builtin/secret_leakage.rs`
- Create: `tests/fixtures/mcp_servers/safe_redacted_logging/package.json`
- Create: `tests/fixtures/mcp_servers/safe_redacted_logging/index.ts`
- Modify or extend: `tests/fixtures/mcp_servers/vuln_cred_exfil/*`

- [ ] **Step 1: Start the Huly issue boundary**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield-agent-19-static-hardening
bash docs/harness/bin/vc-gate.sh start AGENT-19
bash docs/harness/bin/review-gate.sh pre AGENT-19
```

- [ ] **Step 2: Inspect only static scanner files**

Run:

```bash
sed -n '1,260p' src/analysis/cross_file.rs
sed -n '1,260p' src/parser/typescript.rs
sed -n '1,260p' src/parser/python.rs
sed -n '1,260p' src/rules/builtin/credential_exfil.rs
sed -n '1,260p' src/rules/builtin/secret_leakage.rs
```

- [ ] **Step 3: Extend sanitizer recognition**

In `src/analysis/cross_file.rs`, extend the sanitizer registry so these helper names are treated as sanitizers when cross-file analysis sees them:

```text
redactSecret
redactSecrets
redactToken
redactCredentials
maskSecret
maskToken
maskCredentials
scrubSecret
scrubToken
scrubCredentials
```

Preserve existing sanitizer behavior for `validate*Path`, `sanitize*`, `path.resolve`, `os.path.realpath`, `parseInt`, and `URL.parse`.

- [ ] **Step 4: Add safe redacted logging fixture**

Create `tests/fixtures/mcp_servers/safe_redacted_logging/package.json`:

```json
{
  "name": "safe-redacted-logging-fixture",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0"
  }
}
```

Create `tests/fixtures/mcp_servers/safe_redacted_logging/index.ts`:

```typescript
function redactSecret(value: string): string {
  return value.replace(/sk-[A-Za-z0-9_-]+/g, '[REDACTED]')
}

export async function handleLogSecret(args: { token: string }) {
  const safeToken = redactSecret(args.token)
  console.log(`token=${safeToken}`)
  return { ok: true }
}
```

- [ ] **Step 5: Preserve vulnerable credential exfiltration fixture**

Ensure `tests/fixtures/mcp_servers/vuln_cred_exfil/` still contains a fixture where a secret or environment credential reaches a network sink without redaction. If it lacks a TypeScript path, add one that sends `process.env.OPENAI_API_KEY` through `fetch` or an equivalent network call without calling a redaction helper.

- [ ] **Step 6: Add or update tests in the relevant detector modules**

In `src/rules/builtin/credential_exfil.rs` and `src/rules/builtin/secret_leakage.rs`, add tests that assert:

```text
safe_redacted_logging has no credential exfiltration finding.
vuln_cred_exfil still has a credential exfiltration finding.
redactSecret, maskToken, and scrubCredentials are recognized as sanitizers through cross-file analysis.
```

Use the project's existing fixture-loading helpers if those modules already have tests. If the modules use inline unit tests instead of integration fixtures, keep the style consistent and add the fixture checks there.

- [ ] **Step 7: Validate and commit**

Run:

```bash
cargo test credential_exfil secret_leakage cross_file
```

Commit explicitly:

```bash
git add src/analysis/cross_file.rs src/parser/typescript.rs src/parser/python.rs src/rules/builtin/credential_exfil.rs src/rules/builtin/secret_leakage.rs tests/fixtures/mcp_servers/safe_redacted_logging/package.json tests/fixtures/mcp_servers/safe_redacted_logging/index.ts
git commit -m "fix(scanner): harden AGENT-19 redacted secret analysis"
bash docs/harness/bin/vc-gate.sh done AGENT-19
```

---

## Task 7: `AGENT-11` Publish `agent-shield` 0.8.3

**Worktree:** use the clean canonical release worktree only after human approval.

**Goal:** Publish `agent-shield` crate version `0.8.3` to crates.io after release gates pass.

**Files:**
- Verify: `Cargo.toml`
- Verify: `CHANGELOG.md`
- Verify: `docs/releases/0.8.3.md`
- Create Git tag: `v0.8.3`

This task is not suitable for a fully autonomous coding subagent because it can publish an irreversible crate release.

- [ ] **Step 1: Confirm clean canonical worktree**

Run:

```bash
cd /Users/ronaldo/Projects/_aiconnai/agentshield
git status --short
```

Expected: no output.

- [ ] **Step 2: Confirm release metadata**

Run:

```bash
sed -n '1,80p' Cargo.toml
sed -n '1,180p' CHANGELOG.md
sed -n '1,220p' docs/releases/0.8.3.md
```

Expected:

```text
Cargo.toml package version is 0.8.3.
CHANGELOG.md has an entry for 0.8.3.
docs/releases/0.8.3.md exists and matches the planned release.
```

- [ ] **Step 3: Run pre-tag release checklist**

Run:

```bash
bash docs/harness/bin/vc-gate.sh release 0.8.3 --allow-untagged
cargo publish --dry-run
```

Expected: both commands pass.

- [ ] **Step 4: Create the release tag**

Run only after human approval:

```bash
git tag -a v0.8.3 -m "Release v0.8.3"
```

- [ ] **Step 5: Run final release gate**

Run:

```bash
bash docs/harness/bin/vc-gate.sh release 0.8.3
```

Expected: clean worktree, version match, and `v0.8.3` points to `HEAD`.

- [ ] **Step 6: Publish**

Run only after final human confirmation:

```bash
cargo publish
```

- [ ] **Step 7: Record completion**

If Huly updates are requested, use `skills/huly/SKILL.md` and perform a read-only project lookup before any write. Do not print Huly tokens.

---

## Subagent Prompts

### Prompt for `AGENT-9/10`

```text
You are coding in /Users/ronaldo/Projects/_aiconnai/agentshield-agent-9-10-release-ci.
Implement Task 1 from docs/superpowers/plans/2026-06-06-huly-parallel-subagents.md.
Work only on AGENT-9 and AGENT-10.
Own only .github/workflows/release.yml, .github/workflows/ci.yml, Dockerfile, docs/RELEASE_CHECKLIST.md, docs/harness/bin/release-checklist.sh, and docs/harness/GATES.md.
Do not edit runtime or scanner detector files.
Use explicit git add paths and commit when complete.
```

### Prompt for `AGENT-12/13/18`

```text
You are coding in /Users/ronaldo/Projects/_aiconnai/agentshield-agent-12-13-18-docs.
Implement Task 2 from docs/superpowers/plans/2026-06-06-huly-parallel-subagents.md.
Work only on AGENT-12, AGENT-13, and AGENT-18.
Own README.md, docs/NEXT_STEPS.md, docs/ARCHITECTURE.md, docs/RUNTIME_GUARD.md, and docs/BLOG_POST.md.
Do not edit workflows, Dockerfile, runtime Rust files, or scanner detector files.
Use explicit git add paths and commit when complete.
```

### Prompt for `AGENT-14/17`

```text
You are coding in /Users/ronaldo/Projects/_aiconnai/agentshield-agent-14-17-runtime-model.
Implement Task 3 from docs/superpowers/plans/2026-06-06-huly-parallel-subagents.md.
Work only on AGENT-14 and AGENT-17.
Own src/runtime/mod.rs, src/runtime/event.rs, src/runtime/schema.rs, src/lib.rs, tests/runtime_event.rs, tests/runtime_schema.rs, and docs/RUNTIME_JSON_SCHEMA.md.
Do not edit src/bin/cli.rs or release workflow files.
Use explicit git add paths and commit when complete.
```

### Prompt for `AGENT-15`

```text
You are coding in /Users/ronaldo/Projects/_aiconnai/agentshield-agent-15-redaction.
Start only after the AGENT-14/17 runtime model is merged or rebased into this worktree.
Implement Task 4 from docs/superpowers/plans/2026-06-06-huly-parallel-subagents.md.
Work only on AGENT-15.
Own src/runtime/redaction.rs, src/runtime/mod.rs, tests/runtime_redaction.rs, and docs/RUNTIME_GUARD.md.
Do not edit release workflows or scanner detectors.
Use explicit git add paths and commit when complete.
```

### Prompt for `AGENT-16`

```text
You are coding in /Users/ronaldo/Projects/_aiconnai/agentshield-agent-16-guard-stdin.
Start only after AGENT-14/17 and AGENT-15 are merged or rebased into this worktree.
Implement Task 5 from docs/superpowers/plans/2026-06-06-huly-parallel-subagents.md.
Work only on AGENT-16.
Own src/runtime/guard.rs, src/runtime/mod.rs, src/bin/cli.rs, tests/runtime_guard.rs, and docs/RUNTIME_GUARD.md.
Do not edit release workflows or scanner detector files.
Use explicit git add paths and commit when complete.
```

### Prompt for `AGENT-19`

```text
You are coding in /Users/ronaldo/Projects/_aiconnai/agentshield-agent-19-static-hardening.
Implement Task 6 from docs/superpowers/plans/2026-06-06-huly-parallel-subagents.md.
Work only on AGENT-19.
Own src/analysis/cross_file.rs, src/parser/typescript.rs, src/parser/python.rs, src/rules/builtin/credential_exfil.rs, src/rules/builtin/secret_leakage.rs, tests/fixtures/mcp_servers/safe_redacted_logging/*, and tests/fixtures/mcp_servers/vuln_cred_exfil/*.
Do not edit runtime guard CLI files unless the coordinator approves a cross-lane dependency.
Use explicit git add paths and commit when complete.
```

---

## Coordinator Review Checklist

After each subagent returns:

- Check that changed files match the lane ownership matrix.
- Check that commit messages mention the relevant Huly issue identifiers.
- Check that no token values or credentials were printed into files.
- Check that runtime branches merge in the required order.
- Check that docs do not claim runtime guard support is stable.
- Check that static scanner output contracts remain unchanged unless explicitly versioned.
- Check that no subagent used `git add .` or `git add -A` in the recorded commands.

Recommended lane-level validation commands after merge, if the coordinator chooses to run validation:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo run -- list-rules
cargo run -- scan tests/fixtures/mcp_servers/vuln_cred_exfil --format json
```

Use raw command output for JSON artifacts that may be consumed by users or CI.

---

## Self-Review Notes

Spec coverage:

```text
AGENT-9: Task 1 Docker Buildx/cache workflow requirements.
AGENT-10: Task 1 release-checklist.sh and harness docs.
AGENT-11: Task 7 human-gated publish flow.
AGENT-12: Task 2 README positioning.
AGENT-13: Task 2 runtime roadmap.
AGENT-14: Task 3 shared runtime event model.
AGENT-15: Task 4 redaction helpers.
AGENT-16: Task 5 guard --stdin.
AGENT-17: Task 3 runtime JSON schema.
AGENT-18: Task 2 MCP proxy guard mode design.
AGENT-19: Task 6 static scanner hardening.
```

Placeholder scan:

```text
No unresolved placeholder sections are intentionally left in this plan. Any implementation detail that depends on existing code style is constrained by exact public behavior, exact file paths, and exact test expectations.
```

Type consistency:

```text
RuntimeEvent, RuntimeGuardResult, RuntimeVerdict, RuntimeSeverity, Redaction, RedactionKind, and RedactionReport are defined before dependent guard/redaction tasks use them.
```
