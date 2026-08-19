# AGENTS.md

This file provides guidance to AI coding agents when working with this repository.

## Project Overview

**AgentShield** is a Rust-based, offline-first security scanner and runtime guard for AI agent extensions
(MCP servers, OpenClaw skills, CrewAI tools, LangChain tools, GPT Actions, Cursor Rules,
Hermes Agent projects, Vercel AI SDK, AutoGen, LlamaIndex, and Semantic Kernel).
Official Website: https://aiconnai.github.io/agentshield/

It produces SARIF output compatible with GitHub Code Scanning, supports DSSE attestation,
and includes baseline diffing, suppressions, egress policy generation, auto-remediation, and MCP runtime proxying.

## Repository Structure

```
agentshield/
├── src/
│   ├── lib.rs                    # Public API: scan(), render_report()
│   ├── error.rs                  # ShieldError (thiserror)
│   ├── bin/cli.rs                # Clap CLI: discover, scan, setup, reporting, runtime
│   ├── discovery/                # CLI-private registry, parsers, and safe filesystem reads
│   ├── ir/                       # Intermediate Representation (ScanTarget)
│   │   ├── mod.rs                # ScanTarget, Framework, SourceFile, ArgumentSource
│   │   ├── tool_surface.rs       # Tool definitions, permissions
│   │   ├── execution_surface.rs  # Commands, file IO, network IO
│   │   ├── data_surface.rs       # Sources, sinks, taint paths
│   │   ├── dependency_surface.rs # Dependencies, lockfiles
│   │   ├── provenance_surface.rs # Author, repo, license
│   │   ├── capability/           # Capability projection & NL inference (modularized)
│   │   │   ├── mod.rs            # Module re-exports, test suite
│   │   │   ├── types.rs          # Token enums, phrase table, macro phrase!
│   │   │   ├── inference.rs      # NL description capability inference & negation
│   │   │   └── projection.rs     # Permission and execution surface capability projection
│   │   └── taint_builder/        # DataSurface & 1-hop taint path builder (modularized)
│   │       ├── mod.rs            # build_data_surface(), test suite
│   │       ├── sources.rs        # Tool parameters & env var source extraction
│   │       ├── sinks.rs          # Process, HTTP, file write & eval sink collection
│   │       └── paths.rs          # 1-hop taint paths and source resolution
│   ├── adapter/                  # Framework → IR (3-phase pipeline)
│   │   ├── mod.rs                # Adapter trait, auto_detect_and_load(root, ignore_tests)
│   │   ├── mcp/                   # MCP server adapter (modularized)
│   │   │   ├── mod.rs             # Adapter trait impl, lifecycle, test helpers
│   │   │   ├── loader.rs          # Target loading, file collection, composite analysis
│   │   │   ├── filter.rs          # Test file heuristics and filtering
│   │   │   ├── tools/             # Tool extraction (modularized)
│   │   │   │   ├── mod.rs         # McpToolDeclaration, extract_mcp_tools_from_source
│   │   │   │   ├── scan.rs        # JS/TS lexical scanner, delimiters & string parsing
│   │   │   │   └── python.rs      # Python @mcp.tool & FastMCP decorator extraction
│   │   │   ├── binding.rs         # Handler resolution and scope binding
│   │   │   ├── dependencies.rs    # Lockfile parsing (npm, uv, poetry, pip)
│   │   │   ├── provenance.rs      # Author, license, repository metadata
│   │   │   └── tests.rs           # Comprehensive MCP adapter unit tests
│   │   ├── openclaw.rs           # OpenClaw SKILL.md adapter
│   │   ├── crewai.rs             # CrewAI adapter (BaseTool, @tool)
│   │   ├── langchain.rs          # LangChain adapter (@tool, BaseTool, langgraph)
│   │   ├── vercel_ai.rs          # Vercel AI SDK adapter (tool(), @ai-sdk/*)
│   │   ├── autogen.rs            # Microsoft AutoGen adapter (register_function, @register_tool)
│   │   ├── llama_index.rs        # LlamaIndex adapter (FunctionTool, QueryEngineTool)
│   │   ├── semantic_kernel.rs    # Microsoft Semantic Kernel adapter (@kernel_function)
│   │   ├── gpt_actions/          # GPT Actions adapter (OpenAPI specs, modularized)
│   │   │   ├── mod.rs            # GptActionsAdapter struct, Adapter impl, test suite
│   │   │   ├── openapi.rs        # Spec discovery & YAML/JSON deserialization
│   │   │   ├── endpoints.rs      # Endpoint tool extraction & server URL collection
│   │   │   └── auth.rs           # Security scheme & authentication resolution
│   │   ├── cursor_rules.rs       # Cursor Rules adapter (.cursorrules files)
│   │   └── hermes/               # Hermes Agent config, context, and skills adapter
│   │       ├── mod.rs            # Adapter trait impl, lifecycle, test helpers
│   │       ├── config.rs         # YAML config parsing & MCP server extraction
│   │       └── discovery.rs      # Skill tree, catalog & profile discovery
│   ├── parser/                   # Language parsers
│   │   ├── mod.rs                # Parser trait, ParsedFile, FunctionDef, CallSite
│   │   ├── python/               # Python parser (modularized)
│   │   │   ├── mod.rs            # PythonParser struct, LanguageParser impl
│   │   │   ├── defs.rs           # Function definition & context manager extractors
│   │   │   ├── scanner.rs        # Token & AST line-by-line / multiline scanner
│   │   │   ├── patterns.rs       # Static patterns and Lazy<Regex> definitions
│   │   │   └── classify.rs       # Argument classification and sanitizer helpers
│   │   ├── typescript/           # TypeScript/TSX parser (modularized)
│   │   │   ├── mod.rs            # TypeScriptParser struct, LanguageParser impl
│   │   │   ├── ast.rs            # Tree-sitter AST traversal (cfg feature)
│   │   │   ├── classify.rs       # Argument and sanitizer resolution
│   │   │   ├── patterns.rs       # Static sink/source pattern arrays
│   │   │   ├── fallback.rs       # Regex-based fallback parser (no-feature)
│   │   │   └── tests.rs          # Comprehensive parser unit tests
│   │   ├── shell/                # Shell script parser (modularized)
│   │   │   ├── mod.rs            # ShellParser struct, LanguageParser impl, tests
│   │   │   ├── patterns.rs       # Static Lazy<Regex> invocations & variables
│   │   │   ├── quote.rs          # Quote state machine & tokenization
│   │   │   └── classify.rs       # Argument classification & range derivation
│   │   └── json_schema.rs        # JSON Schema → ToolSurface
│   ├── analysis/                 # Static analysis
│   │   ├── mod.rs                # Module exports
│   │   ├── interprocedural/      # Interprocedural call-graph & multi-hop taint (modularized)
│   │   │   ├── mod.rs            # propagate_interprocedural_taint, unit tests
│   │   │   ├── types.rs          # CallGraph, CallSite, FunctionNode
│   │   │   ├── python.rs         # Python function definition & call site extraction
│   │   │   ├── typescript.rs     # TypeScript/JS function definition & call site extraction
│   │   │   └── propagate.rs      # DFS taint propagation & cycle handling
│   │   ├── composite_flow/       # Deep value-flow & semantic taint engine (modularized)
│   │   │   ├── mod.rs            # build_composite_flow_candidates entry point
│   │   │   ├── ast.rs            # Tree-sitter AST helpers and normalization
│   │   │   ├── guard.rs          # Control-flow & containment guards
│   │   │   ├── types.rs          # ValueId, ScopeId, FlowEdge, SemanticAnchor
│   │   │   ├── tests.rs          # Comprehensive composite flow unit tests
│   │   │   └── builder/          # AST walker & candidate graph builder (modularized)
│   │   │       ├── mod.rs        # build(), exports
│   │   │       ├── types.rs      # ParsedUnit, Imports, Lineage, Analyzer
│   │   │       ├── parse.rs      # Source parser & relative import resolution
│   │   │       ├── anchors.rs    # Semantic anchor generators
│   │   │       ├── trace.rs      # Analyzer::analyze_function, evaluate_expression
│   │   │       ├── helper.rs     # Interprocedural helper return tracing
│   │   │       └── resolve.rs    # Lineage resolution, assign, read/network APIs
│   │   ├── cross_file/           # Cross-file sanitizer-aware validation (modularized)
│   │   │   ├── mod.rs            # Public exports, test suite
│   │   │   ├── engine.rs         # apply_cross_file_sanitization, CrossFileResult
│   │   │   ├── sanitizer.rs      # SanitizerCategory, pattern tables, categorization
│   │   │   └── sink_policy.rs    # Sink safety logic, sanitizer_allows_sink
│   │   └── sensitivity.rs        # Sensitive-name heuristics (pub(crate))
│   ├── discovery/                # Local client discovery & config parsing (modularized)
│   │   ├── mod.rs                # Module re-exports, test suite
│   │   ├── types.rs              # ClientId, DiscoveryEnvelope, DiscoveryEntry, limits
│   │   ├── registry.rs           # Descriptor registry & path prefix validation
│   │   ├── parser.rs             # Config parsing (Cursor, Claude Code, VSCode)
│   │   ├── envelope.rs           # Envelope builder, deterministic sorting, budget caps
│   │   └── filesystem/           # Safe filesystem boundary & traversal
│   ├── egress/                   # Egress network filtering & proxy (modularized)
│   │   ├── mod.rs                # Egress policy and proxy exports
│   │   ├── policy/               # Egress policy schema & merge engine (modularized)
│   │   │   ├── mod.rs            # Re-exports, test suite
│   │   │   ├── types.rs          # EgressPolicy struct, load/save, rate limits
│   │   │   ├── infer.rs          # from_scan_targets domain extraction
│   │   │   ├── domain.rs         # Domain allow/deny rules & glob matching
│   │   │   ├── network.rs        # IP/CIDR blocking (private, loopback, link-local)
│   │   │   └── merge.rs          # Operator override restrict-only merge engine
│   │   └── proxy.rs              # HTTP/HTTPS forward proxy & rate limiter
│   ├── rules/                    # Detection engine
│   │   ├── mod.rs                # RuleEngine, Detector trait
│   │   ├── finding.rs            # Finding, Severity, Evidence structs
│   │   ├── registry.rs           # Rule metadata registry
│   │   ├── policy.rs             # Policy evaluation (.agentshield.toml)
│   │   └── builtin/              # 35 built-in detectors (SHIELD-001..035)
│   │       └── capability_mismatch/ # SHIELD-019 detector & eval engine (modularized)
│   ├── risk/                     # Deterministic risk assessment model (modularized)
│   │   ├── mod.rs                # assess(), render_experimental(), property tests
│   │   ├── types.rs              # RiskAssessment, RiskContribution, CoverageDescriptor
│   │   ├── scoring.rs            # Mathematical saturation, point calculation, fingerprinting
│   │   └── render.rs             # Console and JSON report renderers
│   ├── output/                   # Report formatters
│   │   ├── mod.rs                # OutputFormat enum, render()
│   │   ├── console.rs            # Plain text
│   │   ├── json.rs               # JSON
│   │   ├── sarif.rs              # SARIF 2.1.0
│   │   └── html.rs               # Self-contained HTML
│   ├── runtime/                  # Runtime guard & MCP proxy (modularized)
│   │   ├── mod.rs                # Runtime action, event, guard and redaction exports
│   │   ├── event.rs              # RuntimeEvent, RuntimeGuardFinding, RuntimeVerdict
│   │   ├── guard.rs              # Policy evaluation engine (evaluate_runtime_event)
│   │   ├── mcp_proxy.rs          # Decision engine (ProxyDecision, decide)
│   │   ├── mcp_proxy_stdio.rs    # Stdio-based MCP proxy loop & JSON-RPC interceptor
│   │   ├── mcp_proxy_http/       # HTTP/SSE MCP proxy server (modularized)
│   │   │   ├── mod.rs            # run_http_sse_proxy(), tests
│   │   │   ├── types.rs          # ProxyMetrics, AtomicMetrics, HttpAuditEvent
│   │   │   ├── sse.rs            # SSE stream tunnel & live data redaction
│   │   │   ├── forward.rs        # HTTP request forwarding & audit logging
│   │   │   └── server.rs         # TCP listener & request dispatcher
│   │   ├── redaction/            # Secret redaction engine (modularized)
│   │   │   ├── mod.rs            # redact_text(), redact_runtime_event()
│   │   │   ├── types.rs          # RedactionKind, Redaction, RedactionReport
│   │   │   ├── patterns.rs       # Static regexes (OpenAI, AWS, GitHub, JWT, Stripe)
│   │   │   ├── engine.rs         # Text scanning, key-value collectors, overlap resolution
│   │   │   └── json.rs           # JSON tree walking, depth cap, key normalizer
│   │   └── schema.rs             # JSON Schema definitions for events and results
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
├── benches/                      # Criterion benchmarks
│   └── scan.rs                   # Parser, rules, composite flow, and taint benchmarks
├── fuzz/                         # Continuous fuzzing targets (libfuzzer-sys / cargo-fuzz)
│   ├── Cargo.toml                # Fuzz workspace config
│   └── fuzz_targets/
│       ├── fuzz_ts_parser.rs     # TypeScript AST & fallback fuzzing
│       ├── fuzz_py_parser.rs     # Python parser fuzzing
│       ├── fuzz_mcp_tools.rs     # MCP tools extractor fuzzing
│       └── fuzz_composite_flow.rs # Composite flow engine fuzzing
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

# Test (587 Rust tests under the default feature set, including all targets)
cargo test --workspace --all-targets --locked

# Benchmarks
cargo bench --no-run
cargo bench --bench scan

# Lint
cargo clippy -- -D warnings
cargo fmt --check

# Run CLI
cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
cargo run -- scan . --ignore-tests --format html --output report.html
cargo run -- scan . --experimental-risk
cargo run -- scan . --format json --experimental-risk
cargo run -- scan . --write-baseline baseline.json
cargo run -- scan . --baseline baseline.json
cargo run -- discover --no-default-paths --root .
cargo run -- quickstart --force
cargo run -- ci install --output .github/workflows/agentshield.yml
cargo run -- guard --stdin
cargo run -- wrap --policy agentshield.egress.toml -- command
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
- **GitHub Action:** `ignore-tests: true` and `strict: true` (default), where `strict: false` makes only
  no-adapter discovery errors non-blocking; other scan errors still fail the check
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
6. Reuse shared helpers from the `mcp` module submodules: `collect_source_files()`, `parse_dependencies()`, `parse_provenance()`

**Existing adapters:** MCP (`mcp/`), OpenClaw (`openclaw.rs`), CrewAI (`crewai.rs`), LangChain (`langchain.rs`), GPT Actions (`gpt_actions/`), Cursor Rules (`cursor_rules.rs`), Hermes Agent (`hermes/`)

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
- PR inline annotations verified via [agentshield-test PR #1](https://github.com/aiconnai/agentshield-test/pull/1) (IBVI-488)

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
| 1.0.0 | 588 | 35 detectors (SHIELD-001..035), 11 adapters, criterion benchmarks, cargo-fuzz + proptest harnesses, Windows cross-compilation, SHIELD-034 (agent checkpoint CWE-502), SHIELD-035 (unauthenticated MCP SSE CWE-346), v1.0.0 launch kit |
