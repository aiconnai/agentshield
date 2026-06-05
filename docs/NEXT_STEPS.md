# Next Steps — Post v0.1.0

Status: v0.8.3 complete. 6 framework adapters (MCP, OpenClaw, CrewAI, LangChain, GPT Actions, Cursor Rules), 212 tests, 18 detectors (SHIELD-001..018), VS Code extension. Fingerprints, suppressions, baseline diffing, taint path analysis, egress policy generation, DSSE attestation (`certify`), operator override layering, Node 24-ready workflows, full-feature release binaries, and multi-arch GHCR image. TypeScript tree-sitter parser, crates.io, Homebrew, GitHub Action e2e, real-world validation, cross-file validation tracking, PR inline annotations — all done.

---

## ~~1. Real-World Validation~~ — Done

Completed Feb 20, 2026. Scanned 7 Anthropic reference MCP servers. See `docs/VALIDATION_REPORT.md` for full results.

### Results Summary

- **170 total findings** across 7 servers (everything, fetch, filesystem, git, memory, sequentialthinking, time)
- **0 false negatives** remaining (2 critical P1 issues found and fixed)
- **~53% false positives** (mostly test files — ~~need `--ignore-tests` flag~~ **done v0.2.3**)
- **1 parser panic** found and fixed (single-char string literals)

### Bugs Found and Fixed

1. **P0: Parser panic** on single-char strings (`typescript.rs`) — fixed with length guard
2. **P1: Async HTTP client detection** — `httpx.AsyncClient`/`aiohttp.ClientSession` context manager method calls now detected via `HTTP_CLIENT_CTX_RE` + `HTTP_CLIENT_METHODS` + `PARTIAL_CALL_RE` (multi-line support)
3. **P1: GitPython command detection** — `repo.git.*` dynamic dispatchers now detected via `GITPYTHON_RE`
4. **P2: vitest typosquat FP** — added `KNOWN_SAFE` allowlist to typosquat detector

### Remaining Improvements

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| ~~**P2**~~ | ~~Test file exclusion (`--ignore-tests`)~~ | ~~Done v0.2.3~~ | ~~Done~~ |
| ~~**P3**~~ | ~~Cross-file validation tracking~~ | ~~Done v0.2.2 (IBVI-482)~~ | ~~Done~~ |

---

## ~~2. Test GitHub Action End-to-End~~ — Done

Tested Feb 20, 2026. Test repo: [`limaronaldo/agentshield-test`](https://github.com/limaronaldo/agentshield-test)

### Results

- [x] Action downloads correct binary for ubuntu-latest (x86_64-unknown-linux-gnu)
- [x] Scan finds SHIELD-001, SHIELD-002, SHIELD-003, SHIELD-004, SHIELD-007 (7 total findings)
- [x] SARIF uploads to Code Scanning tab (5 alerts with source locations)
- [x] Action fails with exit code 1 (findings above `high` threshold)
- [x] Creating a PR shows annotations inline — **verified** (7 annotations on `tools.py`)

### SARIF bugs found and fixed

Three SARIF validation issues were discovered during e2e testing and fixed:

1. **`startColumn` must be >= 1** — parser emits 0-based columns, SARIF 2.1.0 requires 1-based. Fixed with `.max(1)`.
2. **`fixes[]` requires `artifactChanges`** — removed invalid `fixes` array, moved remediation text to `result.properties.remediation`.
3. **Location-less results rejected** — supply-chain findings (SHIELD-009, SHIELD-012) have no source location; GitHub Code Scanning requires at least one. Fixed by filtering them from SARIF output (still appear in console/JSON/HTML).

---

## 3. ~~Publish to crates.io~~ — Done

Published as [`agent-shield`](https://crates.io/crates/agent-shield) v0.2.0 on Feb 20, 2026.
(`agentshield` name was taken by an unrelated crate; binary name remains `agentshield`.)

### Pre-publish checklist

- [x] Cargo.toml has: name, version, description, license, repository, readme
- [x] README.md exists
- [x] LICENSE exists
- [x] `cargo publish --dry-run` succeeds
- [x] No private/internal dependencies
- [x] Published to crates.io as `agent-shield`

---

## 4. v0.2.0 Roadmap

Features deferred from v0.1.0:

| Feature | Linear | Effort | Impact |
|---------|--------|--------|--------|
| ~~TypeScript parser (tree-sitter)~~ | ~~RML-1078~~ | ~~Done v0.2.0~~ | ~~High~~ |
| ~~Homebrew formula~~ | — | ~~Done v0.2.0~~ | ~~Medium~~ |
| ~~GitHub Action e2e test~~ | ~~IBVI-488~~ | ~~Done v0.2.0~~ | ~~High~~ |
| ~~Real-world validation~~ | ~~[IBVI-481](https://linear.app/mbras/issue/IBVI-481)~~ | ~~Done v0.2.0~~ | ~~High — 170 findings, 4 bugs fixed~~ |
| ~~Cross-file taint analysis~~ | ~~[IBVI-482](https://linear.app/mbras/issue/IBVI-482)~~ | ~~Done v0.2.2~~ | ~~Done — eliminates filesystem FPs~~ |
| ~~GitHub Marketplace submission~~ | ~~[IBVI-483](https://linear.app/mbras/issue/IBVI-483)~~ | ~~Done v0.2.1~~ | ~~High — [listed](https://github.com/marketplace/actions/agentshield-security-scanner)~~ |
| Blog post / announcement | [IBVI-484](https://linear.app/mbras/issue/IBVI-484) | Medium | High — launch content |
| ~~VS Code extension~~ | ~~[IBVI-485](https://linear.app/mbras/issue/IBVI-485)~~ | ~~Done v0.2.4~~ | ~~Done — inline diagnostics, auto-scan, status bar~~ |
| ~~LangChain adapter~~ | ~~[IBVI-486](https://linear.app/mbras/issue/IBVI-486)~~ | ~~Done v0.2.4~~ | ~~Done — 4 adapters (MCP, OpenClaw, CrewAI, LangChain), 95 tests~~ |
| ~~CrewAI adapter~~ | ~~[IBVI-487](https://linear.app/mbras/issue/IBVI-487)~~ | ~~Done v0.2.4~~ | ~~Done — 3 adapters (MCP, OpenClaw, CrewAI), 89 tests~~ |
| ~~PR annotation test~~ | ~~[IBVI-488](https://linear.app/mbras/issue/IBVI-488)~~ | ~~Done v0.2.3~~ | ~~Done — [PR #1](https://github.com/limaronaldo/agentshield-test/pull/1), 7 inline annotations~~ |

---

## 5. v0.2.2 — Cross-File Validation Tracking — Done

Completed Feb 20, 2026. See [IBVI-482](https://linear.app/mbras/issue/IBVI-482).

### What it does

Post-parsing analysis phase that recognizes sanitizer function calls (`validatePath`, `path.resolve`, etc.), tracks which variables hold sanitized results, and when a function is only called with sanitized arguments, downgrades its parameters from tainted to `Sanitized`. Detectors already check `is_tainted()` — `Sanitized` returns `false` — so **zero detector changes were needed**.

### Implementation

- `ArgumentSource::Sanitized { sanitizer }` variant in `src/ir/mod.rs`
- `FunctionDef`, `CallSite`, `sanitized_vars` in `src/parser/mod.rs`
- TypeScript + Python parsers extract these structures
- `apply_cross_file_sanitization()` in `src/analysis/cross_file.rs`
- 3-phase adapter pipeline (parse → cross-file analysis → merge) in MCP and OpenClaw adapters
- `safe_filesystem` test fixture (3 TypeScript files mimicking Anthropic's filesystem MCP server)
- 14 new tests (83 total, up from 69)

### Impact

Eliminates false positives from internal helper functions that receive already-validated input — the primary source of noise in the filesystem MCP server scan (54 SHIELD-004 + 33 SHIELD-006 findings were all false positives).

### Post-v0.2.2 Roadmap

| Feature | Linear | Effort | Impact |
|---------|--------|--------|--------|
| ~~Test file exclusion (`--ignore-tests`)~~ | — | ~~Done v0.2.3~~ | ~~Done~~ |
| ~~Re-scan 7 Anthropic servers with v0.2.3~~ | — | ~~Done v0.2.3~~ | ~~Done — 170 → 69 findings (59% reduction)~~ |
| ~~PR annotation test~~ | ~~[IBVI-488](https://linear.app/mbras/issue/IBVI-488)~~ | ~~Done v0.2.3~~ | ~~Done — [PR #1](https://github.com/limaronaldo/agentshield-test/pull/1)~~ |
| Blog post / announcement | [IBVI-484](https://linear.app/mbras/issue/IBVI-484) | Medium | High — launch content |
| ~~VS Code extension~~ | ~~[IBVI-485](https://linear.app/mbras/issue/IBVI-485)~~ | ~~Done v0.2.4~~ | ~~Done — inline diagnostics, auto-scan, status bar~~ |
| ~~LangChain adapter~~ | ~~[IBVI-486](https://linear.app/mbras/issue/IBVI-486)~~ | ~~Done v0.2.4~~ | ~~Done — 4 adapters (MCP, OpenClaw, CrewAI, LangChain), 95 tests~~ |
| ~~CrewAI adapter~~ | ~~[IBVI-487](https://linear.app/mbras/issue/IBVI-487)~~ | ~~Done v0.2.4~~ | ~~Done~~ |

---

## 7. v0.2.3 — Test File Exclusion (`--ignore-tests`) — Done

Completed Feb 20, 2026.

### What it does

Filters out test files at the file-walking stage (before parsing) via `is_test_file()` in `src/adapter/mcp.rs`. Available through CLI flag (`--ignore-tests`), config file (`[scan] ignore_tests = true`), GitHub Action input (`ignore-tests: true`), and library API (`ScanOptions { ignore_tests: true }`).

### Test file patterns matched

- **Directories:** `test/`, `tests/`, `__tests__/`, `__pycache__/`
- **Suffixes:** `.test.{ts,js,tsx,jsx,py}`, `.spec.{ts,js,tsx,jsx}`
- **Prefixes:** `test_*.py` (pytest convention)
- **Config files:** `conftest.py`, `jest.config.*`, `vitest.config.*`, `pytest.ini`, `setup.cfg`

### Implementation

- `is_test_file()` helper in `src/adapter/mcp.rs` (shared by OpenClaw adapter)
- `ignore_tests: bool` parameter added to `Adapter::load()` and `auto_detect_and_load()`
- `ScanConfig` struct with `ignore_tests` field in `src/config/mod.rs`
- CLI flag OR's with config: `options.ignore_tests || config.scan.ignore_tests`
- `ignore-tests` input added to `action.yml` GitHub Action

### Measured Impact (v0.2.3 Re-Scan)

Re-scanned all 7 Anthropic reference servers with v0.2.3. Combined with cross-file analysis (v0.2.2):

| Metric | v0.2.0 | v0.2.3 (`--ignore-tests`) |
|--------|--------|---------------------------|
| Total findings | 170 | **69** (59% reduction) |
| Signal-to-noise ratio | 0.53 | **0.99** |
| False positives | ~90 (53%) | ~1 (1%) |

Biggest impact: filesystem (93 → 20, -78%), memory (24 → 10, -58%). See `docs/VALIDATION_REPORT.md` for full breakdown.

---

## 8. v0.2.3 — PR Annotation Test (IBVI-488) — Done

Completed Feb 20, 2026. See [IBVI-488](https://linear.app/mbras/issue/IBVI-488).

### What was tested

Created [PR #1](https://github.com/limaronaldo/agentshield-test/pull/1) on `limaronaldo/agentshield-test` with `src/tools.py` containing intentional vulnerabilities (SHIELD-001, -002, -003, -004, -006, -007, -011).

### Results

- [x] Action downloads v0.2.3 binary for ubuntu-latest (x86_64-unknown-linux-gnu)
- [x] Scan detects 12 findings (5 in `server.py`, 7 in `tools.py`)
- [x] SARIF uploads to Code Scanning — "AgentShield" check passes
- [x] 12 Code Scanning alerts visible on PR branch
- [x] 7 inline annotations on `tools.py` in Files changed tab (all on lines within PR diff)
- [x] Action fails with exit code 1 (findings above `high` threshold)

### v0.2.3 Release

Created as part of this test. 5-platform binary release:
- `agentshield-v0.2.3-x86_64-unknown-linux-gnu.tar.gz`
- `agentshield-v0.2.3-aarch64-unknown-linux-gnu.tar.gz`
- `agentshield-v0.2.3-x86_64-apple-darwin.tar.gz`
- `agentshield-v0.2.3-aarch64-apple-darwin.tar.gz`
- `agentshield-v0.2.3-x86_64-pc-windows-msvc.zip`

Release: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.3

---

## 9. v0.2.4 — CrewAI Adapter (IBVI-487) — Done

Completed Feb 20, 2026. See [IBVI-487](https://linear.app/mbras/issue/IBVI-487).

### What it does

Detects CrewAI Python projects and feeds their source files through the existing 3-phase adapter pipeline. CrewAI tools are defined as `BaseTool` subclasses (with `_run()` method) or `@tool("name")` decorated functions — both patterns contain the same security-relevant operations (subprocess, requests, eval, file IO) that the existing Python parser and all 12 detectors already handle.

### Detection

Checks for ANY of:
- `pyproject.toml` containing `crewai` in dependencies or `[tool.crewai]` section
- `requirements.txt` containing `crewai` or `crewai-tools`
- Python files importing `from crewai` / `import crewai` / `from crewai_tools`

### Implementation

- **`src/adapter/crewai.rs`** — `CrewAiAdapter` with `detect()` and `load()` using `Framework::CrewAi`
- **`src/adapter/mod.rs`** — registered in `all_adapters()`
- **`src/adapter/mcp.rs`** — `collect_source_files()`, `parse_dependencies()`, `parse_provenance()` promoted to `pub(super)` for reuse
- **`tests/fixtures/crewai_project/`** — test fixture with `pyproject.toml`, `requirements.txt`, `vuln_tool.py` (SHIELD-001), `fetch_tool.py` (SHIELD-003)
- 6 new tests (89 total, up from 83)
- CLI scan produces 7 findings on fixture: SHIELD-001, -003, -007, -009 x3, -012

### Key design decisions

- **Python-only filtering**: `load()` collects all source files via `collect_source_files()` then retains only Python files, since CrewAI is a Python-only framework
- **Reuses shared helpers**: `parse_dependencies()` and `parse_provenance()` from `mcp.rs` handle `pyproject.toml` and `requirements.txt` — no duplication
- **No parser changes needed**: the existing Python parser already detects all security patterns (subprocess, requests, eval, file ops, GitPython, async HTTP clients)
- **No detector changes needed**: `Framework::CrewAi` was already in the IR enum; detectors operate on `ScanTarget` regardless of framework

---

## 10. v0.2.4 — LangChain Adapter (IBVI-486) — Done

Completed Feb 20, 2026. See [IBVI-486](https://linear.app/mbras/issue/IBVI-486).

### What it does

Detects LangChain Python projects and feeds their source files through the existing 3-phase adapter pipeline. LangChain tools are defined as `BaseTool` subclasses (with `_run()` method), `@tool`-decorated functions, or `StructuredTool.from_function()` calls. Also detects LangGraph projects via `langgraph.json`. Same design as CrewAI adapter — no parser or detector changes needed.

### Detection

Checks for ANY of:
- `pyproject.toml` containing `langchain` or `langgraph` in dependencies
- `requirements.txt` containing lines starting with `langchain` or `langgraph`
- `langgraph.json` configuration file
- Python files importing `from langchain` / `from langchain_core` / `from langgraph`

### Implementation

- **`src/adapter/langchain.rs`** — `LangChainAdapter` with `detect()` and `load()` using `Framework::LangChain`
- **`src/adapter/mod.rs`** — registered in `all_adapters()`
- **`tests/fixtures/langchain_project/`** — test fixture with `pyproject.toml`, `requirements.txt`, `langgraph.json`, `shell_tool.py` (SHIELD-001), `fetch_tool.py` (SHIELD-003)
- 6 new tests (95 total, up from 89)
- CLI scan produces 7 findings on fixture: SHIELD-001, -003, -007, -009 x3, -012

---

## 11. v0.2.4 — VS Code Extension (IBVI-485) — Done

Completed Feb 20, 2026. See [IBVI-485](https://linear.app/mbras/issue/IBVI-485).

### What it does

VS Code extension that runs AgentShield on save, maps findings to inline diagnostics (squiggles), and shows results in the Problems panel with a status bar indicator.

### Architecture

Spawns `agentshield scan <workspace> --format json --ignore-tests` as a child process, parses JSON stdout, and creates `vscode.Diagnostic` entries grouped by file.

### Features

- **Inline diagnostics** — severity-colored underlines (Error for Critical/High, Warning for Medium, Info for Low)
- **Auto-scan on save** — debounced 2s, configurable
- **Auto-scan on open** — runs when workspace is first opened
- **Manual scan** — `Cmd+Shift+P` → "AgentShield: Scan Workspace"
- **Status bar** — shows scan state (spinning, pass, N findings, error)
- **Clickable rule IDs** — link to docs/RULES.md
- **Remediation** — shown as related diagnostic information
- **Configurable** — binary path, ignore-tests, scan-on-save, scan-on-open, timeout

### Implementation

- **`vscode/src/extension.ts`** — activate, commands, debounced save handler, status bar
- **`vscode/src/scanner.ts`** — `findBinary()`, `runScan()` (spawn + JSON parse)
- **`vscode/src/diagnostics.ts`** — `updateDiagnostics()` (Finding → vscode.Diagnostic)
- **`vscode/src/types.ts`** — TypeScript interfaces mirroring Rust JSON output
- **`vscode/package.json`** — extension manifest with settings and activation events
- Total: ~350 lines of TypeScript, compiles cleanly

---

## 12. v0.3.0 — Stable Finding Fingerprints — Done

Completed March 21, 2026.

### What it does

Every finding now includes a stable SHA-256 fingerprint derived from rule ID, file path, line number, and code snippet. Fingerprints are deterministic across runs, enabling baseline diffing and suppression by ID.

### Implementation

- Versioned baseline file schema with serialization
- Fingerprints included in all 4 output formats (console, JSON, SARIF, HTML)
- `--write-baseline <path>` writes all current findings as a baseline file
- `--baseline <path>` filters out findings that match a previously written baseline

---

## 13. v0.4.0 — Suppressions — Done

Completed March 21, 2026.

### What it does

`suppress` and `list-suppressions` CLI subcommands for managing finding suppressions in `.agentshield.toml`. Suppressions use fingerprints to target specific findings, with required reason and optional expiration.

### CLI

```bash
agentshield suppress SHIELD-001 src/tools.py:42 --reason "accepted risk"
agentshield list-suppressions
```

---

## 14. v0.5.0 — Taint Paths & Egress Policy — Done

Completed March 21, 2026.

### What it does

- Upgraded `credential_exfil` and `prompt_injection` detectors with full taint path evidence
- Dependency findings (SHIELD-009, SHIELD-012) now include manifest locations for SARIF output parity
- `--emit-egress-policy <path>` analyzes scan results and generates a starter egress policy file
- Egress policy schema for the `wrap` command

---

## 15. v0.6.0 — GPT Actions & Cursor Rules Adapters — Done

Completed March 21, 2026.

### What it does

Two new framework adapters bringing the total to 6:

- **GPT Actions** (`gpt_actions.rs`) — detects OpenAPI specs used in GPT Custom Actions
- **Cursor Rules** (`cursor_rules.rs`) — detects `.cursorrules` configuration files

Both use the standard 3-phase adapter pipeline and reuse shared helpers.

---

## 16. v0.7.0 — Egress Policy Operator Override — Done

Completed March 21, 2026.

### What it does

Adds operator override policy layering to the `wrap` command, allowing operators to enforce egress restrictions that cannot be bypassed by individual tool configurations.

---

## 17. v0.8.0 — Certify & New Detectors — Done

Completed March 21, 2026.

### What it does

- **`certify` command** — generates DSSE (Dead Simple Signing Envelope) attestation envelopes for scan results, with optional Ed25519 signing
- **6 new detectors** (18 total):
  - SHIELD-013: Metadata SSRF (cloud metadata endpoint access, critical)
  - SHIELD-014: Download-Write-Execute Chain (supply chain attack pattern, critical)
  - SHIELD-015: Overbroad Filesystem Scope (unrestricted path access, high)
  - SHIELD-016: Unsafe Deserialization (pickle/yaml.load/eval, critical)
  - SHIELD-017: Archive Traversal / Zip Slip (path traversal via archives, high)
  - SHIELD-018: Secret Leakage (credentials in logs/responses, high)

### CLI

```bash
agentshield certify .
agentshield certify . --sign-key key.bin --output attestation.json
```

---

## 6. Launch / Promotion

### Blog post outline: "We scanned N MCP servers — here's what we found"

1. Intro: AI agents are getting powerful tools, but who's checking the tools?
2. Methodology: scanned X open-source MCP servers with AgentShield
3. Findings breakdown: N command injections, N SSRF, N credential leaks
4. Case studies: 2-3 interesting real findings with code snippets
5. How to protect yourself: add AgentShield to your CI
6. CTA: GitHub Action link, star the repo

### Distribution channels

- Hacker News (Show HN)
- Reddit r/MachineLearning, r/rust
- Twitter/X (AI security community)
- MCP Discord / community channels
- Dev.to / Hashnode blog post

---

## Linear Project Reference

- Project: AgentShield - Security Scanner for AI Agent Extensions
- Project ID: bafa5ae7-f48a-4a45-8ec8-14f49fcac779 (IBVI org)
- Team: IBVI (e792ad0a-a7d5-4927-b7ef-4fe22dde0fd4)
- Repo: https://github.com/limaronaldo/agentshield
- v0.1.0 issues: Done (RML-1062..1091, migrated from MBRAS IBVI-311..340)
- v0.2.0 issues: IBVI-481..488 (created Feb 20, 2026)
