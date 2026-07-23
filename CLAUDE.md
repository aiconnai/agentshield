# AGENTS.md

This file provides guidance to AI coding agents when working with this repository.

## Project Overview

**AgentShield** is a Rust-based, offline-first security scanner for AI agent extensions
(MCP servers, OpenClaw skills, CrewAI tools, LangChain tools, GPT Actions, Cursor Rules,
and Hermes Agent projects).
It produces SARIF output compatible with GitHub Code Scanning, supports DSSE attestation,
and includes baseline diffing, suppressions, and egress policy generation.

## Repository Structure

```
agentshield/
├── src/
│   ├── lib.rs                    # Public API: scan(), render_report()
│   ├── error.rs                  # ShieldError (thiserror)
│   ├── bin/cli.rs                # Clap CLI: scan, list-rules, init, suppress, list-suppressions, certify
│   ├── ir/                       # Intermediate Representation (ScanTarget)
│   │   ├── mod.rs                # ScanTarget, Framework, SourceFile, ArgumentSource
│   │   ├── tool_surface.rs       # Tool definitions, permissions
│   │   ├── execution_surface.rs  # Commands, file IO, network IO
│   │   ├── data_surface.rs       # Sources, sinks, taint paths
│   │   ├── dependency_surface.rs # Dependencies, lockfiles
│   │   └── provenance_surface.rs # Author, repo, license
│   ├── adapter/                  # Framework → IR (3-phase pipeline)
│   │   ├── mod.rs                # Adapter trait, auto_detect_and_load(root, ignore_tests)
│   │   ├── mcp.rs                # MCP server adapter + is_test_file() + shared helpers
│   │   ├── openclaw.rs           # OpenClaw SKILL.md adapter
│   │   ├── crewai.rs             # CrewAI adapter (BaseTool, @tool)
│   │   ├── langchain.rs          # LangChain adapter (@tool, BaseTool, langgraph)
│   │   ├── gpt_actions.rs        # GPT Actions adapter (OpenAPI specs)
│   │   ├── cursor_rules.rs       # Cursor Rules adapter (.cursorrules files)
│   │   └── hermes.rs             # Hermes Agent config, context, and skills adapter
│   ├── parser/                   # Language parsers
│   │   ├── mod.rs                # Parser trait, ParsedFile, FunctionDef, CallSite
│   │   ├── python.rs             # tree-sitter Python + regex patterns
│   │   ├── typescript.rs         # tree-sitter TypeScript/TSX + regex fallback
│   │   ├── shell.rs              # Regex-based shell parser
│   │   └── json_schema.rs        # JSON Schema → ToolSurface
│   ├── analysis/                 # Static analysis
│   │   ├── mod.rs                # Module exports
│   │   ├── cross_file.rs         # Cross-file sanitizer-aware validation (v0.2.2)
│   │   └── sensitivity.rs        # Sensitive-name heuristics (pub(crate))
│   ├── rules/                    # Detection engine
│   │   ├── mod.rs                # RuleEngine, Detector trait
│   │   ├── finding.rs            # Finding, Severity, Evidence structs
│   │   ├── registry.rs           # Rule metadata registry
│   │   ├── policy.rs             # Policy evaluation (.agentshield.toml)
│   │   └── builtin/              # 19 built-in detectors (SHIELD-001..019)
│   ├── output/                   # Report formatters
│   │   ├── mod.rs                # OutputFormat enum, render()
│   │   ├── console.rs            # Plain text
│   │   ├── json.rs               # JSON
│   │   ├── sarif.rs              # SARIF 2.1.0
│   │   └── html.rs               # Self-contained HTML
│   └── config/                   # .agentshield.toml parsing (policy + scan sections)
├── tests/fixtures/               # Test fixtures (safe + vulnerable)
│   ├── mcp_servers/
│   │   ├── safe_calculator/      # Zero-finding baseline
│   │   ├── safe_filesystem/      # Cross-file validation test (v0.2.2)
│   │   ├── vuln_cmd_inject/      # SHIELD-001 true positive
│   │   ├── vuln_ssrf/            # SHIELD-003 true positive
│   │   └── vuln_cred_exfil/      # SHIELD-002 true positive
│   ├── crewai_project/           # CrewAI adapter test (v0.2.4)
│   ├── langchain_project/        # LangChain adapter test (v0.2.4)
│   └── hermes_agent/             # Hermes Agent adapter fixtures
├── vscode/                       # VS Code extension (v0.1.0)
│   ├── package.json              # Extension manifest
│   ├── tsconfig.json             # TypeScript config
│   └── src/                      # Extension source (TypeScript)
│       ├── extension.ts          # Activate, commands, auto-scan
│       ├── scanner.ts            # Spawn binary, parse JSON
│       ├── diagnostics.ts        # Finding → vscode.Diagnostic
│       └── types.ts              # JSON interfaces (mirrors Rust)
├── .github/workflows/
│   ├── ci.yml                    # Test + clippy + fmt + smoke
│   ├── feature-matrix.yml        # Supported Cargo feature configurations
│   ├── vscode.yml                # Extension compile, test, audit, and package
│   ├── release.yml               # 5-platform binary builds
│   └── docker.yml                # Canonical multi-architecture GHCR publisher
└── action.yml                    # GitHub Action (composite)
```

## Common Commands

```bash
# Build
cargo build --release

# Test (295 Rust tests under the default feature set, including all targets)
cargo test --workspace --all-targets --locked

# Lint
cargo clippy -- -D warnings
cargo fmt --check

# Run CLI
cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
cargo run -- scan . --ignore-tests --format html --output report.html
cargo run -- scan . --write-baseline baseline.json
cargo run -- scan . --baseline baseline.json
cargo run -- list-rules
cargo run -- suppress SHIELD-001 src/tools.py:42 --reason "accepted risk"
cargo run -- list-suppressions
cargo run -- certify . --output attestation.json
cargo run -- certify . --sign-key key.bin --output attestation.json

# VS Code extension
cd vscode
npm ci
npm run compile
npm test
npm audit --audit-level=moderate
npm run package
```

The Rust test count is the number of entries ending in `: test` emitted by
`cargo test --workspace --all-targets --locked -- --list`. The dedicated VS Code
workflow runs clean installation, compilation, unit tests, dependency auditing,
and VSIX packaging. Docker images for version tags are published only by
`.github/workflows/docker.yml`; `release.yml` owns the platform binary release.

## Supported Cargo Feature Configurations

The default feature set enables both language parsers (`python` and `typescript`).
CI also verifies these supported configurations independently:

```bash
cargo test --no-default-features --locked
cargo check --no-default-features --features python --locked
cargo check --no-default-features --features typescript --locked
cargo check --no-default-features --features runtime --locked
cargo check --no-default-features --features runtime,runtime-guard --locked
```

Use `runtime-guard` together with `runtime` for the supported runtime-guard
configuration. The existing primary Rust CI continues to exercise the complete
all-features build.

## Architecture Principles

1. **Adapters produce IR, detectors consume IR.** Adding a new framework never changes any detector.
2. **All adapters run.** `auto_detect_and_load()` runs every matching adapter, not just the first.
3. **ArgumentSource is the taint abstraction.** Detectors check `is_tainted()` — no full dataflow needed.
4. **Policy is separate from detection.** Detectors always run; policy decides what to report and whether to fail.
5. **Cross-file analysis runs between parsing and detection.** Downgrades taint for functions that only receive sanitized input.

## Key Types

- `ScanTarget` — unified IR with 5 surfaces (tool, execution, data, dependency, provenance)
- `Finding` — detector output with severity, confidence, location, evidence, remediation
- `ArgumentSource` — `Literal` (safe), `Parameter` (tainted), `EnvVar`, `Interpolated`, `Unknown`, `Sanitized` (safe, v0.2.2)
- `Detector` trait — `metadata() -> RuleMetadata`, `run(&ScanTarget) -> Vec<Finding>`
- `PolicyVerdict` — pass/fail with threshold and highest severity
- `ScanConfig` — `[scan]` config section with `ignore_tests` bool
- `ParsedFile` — parser output with `commands`, `file_operations`, `network_operations`, `function_defs`, `call_sites`, `sanitized_vars`
- `FunctionDef` — extracted function definition with name, params, `is_exported`
- `CallSite` — function call with callee name, classified arguments, caller context

## Adapter Pipeline (3-phase, v0.2.2)

Adapters use a 3-phase pipeline:

```
Phase 1: Parse     — each source file → ParsedFile (with FunctionDef, CallSite, sanitized_vars)
Phase 2: Analyze   — apply_cross_file_sanitization() downgrades tainted params to Sanitized
Phase 3: Merge     — combine all ParsedFiles into ScanTarget surfaces
```

This eliminates false positives from internal helpers that receive already-validated input:

```typescript
// index.ts — handler validates input
const validPath = await validatePath(args.path);  // sanitizer detected
const content = await readFileContent(validPath);  // CallSite with Sanitized arg

// operations.ts — helper uses validated input
export async function readFileContent(filePath: string) {
    return fs.readFile(filePath, 'utf-8');  // Parameter downgraded → no SHIELD-004
}
```

## Cross-File Analysis (`src/analysis/cross_file.rs`)

The `apply_cross_file_sanitization()` function:

1. **Phase 1:** Builds function def map (`name → file_index, params, is_exported`)
2. **Phase 2:** Builds call-site map (`callee → Vec<argument_sources>`)
3. **Phase 3:** For each function, checks if ALL call sites pass safe args (Literal or Sanitized) per parameter
4. **Phase 4:** If all-safe, downgrades matching `ArgumentSource::Parameter` to `Sanitized` in the callee's operations

**Conservative rules:**
- Exported functions with zero discovered call sites stay tainted
- If ANY call site passes a tainted argument, the parameter stays tainted
- Only one level deep (caller → callee, not recursive)

**Sanitizer registry** (`is_sanitizer()`): recognizes `validatePath`, `path.resolve`, `os.path.realpath`, `parseInt`, `URL.parse`, and pattern-based matches like `validate*Path`, `sanitize*`.

## Test File Exclusion (`--ignore-tests`)

The `--ignore-tests` flag skips test files at the file-walking stage (before parsing). Available via:
- **CLI:** `agentshield scan . --ignore-tests`
- **Config:** `[scan] ignore_tests = true` in `.agentshield.toml`
- **GitHub Action:** `ignore-tests: true` input
- **Library:** `ScanOptions { ignore_tests: true, .. }`

CLI flag overrides config (`options.ignore_tests || config.scan.ignore_tests`).

`is_test_file()` in `src/adapter/mcp.rs` matches:
- Directories: `test/`, `tests/`, `__tests__/`, `__pycache__/`
- Suffixes: `.test.{ts,js,tsx,jsx,py}`, `.spec.{ts,js,tsx,jsx}`
- Prefixes: `test_*.py` (pytest)
- Config: `conftest.py`, `jest.config.*`, `vitest.config.*`, `pytest.ini`, `setup.cfg`

## Adding a New Detector

1. Create `src/rules/builtin/your_detector.rs`
2. Implement `Detector` trait (`metadata()` + `run()`)
3. Register in `src/rules/builtin/mod.rs` → `all_detectors()`
4. Add tests in the same file
5. Add fixture in `tests/fixtures/` if applicable
6. Run `cargo test && cargo clippy -- -D warnings`

## Adding a New Adapter

1. Create `src/adapter/your_framework.rs`
2. Implement `Adapter` trait (`framework()`, `detect()`, `load()`)
3. Register in `src/adapter/mod.rs` → `all_adapters()`
4. `detect()` checks for framework-specific files
5. `load()` uses the 3-phase pipeline (parse → cross-file analysis → merge)
6. Reuse shared helpers from `mcp.rs`: `collect_source_files()`, `parse_dependencies()`, `parse_provenance()`

**Existing adapters:** MCP (`mcp.rs`), OpenClaw (`openclaw.rs`), CrewAI (`crewai.rs`), LangChain (`langchain.rs`), GPT Actions (`gpt_actions.rs`), Cursor Rules (`cursor_rules.rs`), Hermes Agent (`hermes.rs`)

## Conventions

- `thiserror` for error types, `?` operator everywhere
- No `unwrap()` in production paths
- tree-sitter for AST parsing, regex for pattern matching and fallback
- Tests use real fixture files under `tests/fixtures/`
- Conventional Commits for git messages
- Parsers extract `FunctionDef`, `CallSite`, and `sanitized_vars` for cross-file analysis
- `ArgumentSource::Sanitized` is the safe variant for cross-file validated params — `is_tainted()` returns `false`
- Findings include stable fingerprints (SHA-256 hash of rule+file+line+snippet) for baseline diffing and suppression
- `--baseline` / `--write-baseline` for CI noise reduction — only report new findings
- `suppress` / `list-suppressions` CLI commands manage `.agentshield.toml` suppressions
- `certify` command generates DSSE attestation envelopes with optional Ed25519 signing
- `--emit-egress-policy` analyzes scan results and generates a starter egress policy
- PR inline annotations verified via [agentshield-test PR #1](https://github.com/limaronaldo/agentshield-test/pull/1) (IBVI-488)

## Version History

| Version | Tests | Key Feature |
|---------|-------|-------------|
| 0.1.0 | 46 | 12 detectors, Python parser, MCP/OpenClaw adapters |
| 0.2.0 | 69 | TypeScript tree-sitter parser, Homebrew, GitHub Action |
| 0.2.1 | 69 | Async HTTP detection, GitPython, typosquat allowlist, Marketplace |
| 0.2.2 | 83 | Cross-file validation tracking (IBVI-482) |
| 0.2.3 | 83 | `--ignore-tests` flag, `[scan]` config section, 5-platform release, PR annotations verified |
| 0.2.4 | 95 | CrewAI + LangChain adapters (IBVI-486, -487) — 4 adapters total, shared helpers |
| 0.3.0 | ~120 | Stable finding fingerprints (SHA-256), versioned baseline file schema |
| 0.4.0 | ~140 | `suppress` + `list-suppressions` CLI, `.agentshield.toml` suppression entries |
| 0.5.0 | ~160 | Taint path upgrades (credential_exfil, prompt_injection), egress policy schema, `--emit-egress-policy`, `--baseline`/`--write-baseline` |
| 0.6.0 | ~180 | GPT Actions + Cursor Rules adapters — 6 adapters total |
| 0.7.0 | ~195 | Egress policy operator override layering for `wrap` command |
| 0.8.0 | 212 | `certify` command (DSSE attestation + Ed25519), 6 new detectors (SHIELD-013..018) |
