# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-06-05

### Added

- GPT Actions and Cursor Rules are now part of the documented supported adapter scope alongside MCP, OpenClaw, CrewAI, and LangChain/LangGraph.
- Documentation for the current CLI command surface: `scan`, `list-rules`, `init`, `suppress`, `list-suppressions`, `certify`, and feature-gated `wrap`.
- `agentshield doctor` diagnostics for version, config, compile features, and adapter detection.
- Release notes for 0.8.0 in `docs/releases/0.8.0.md`.
- General release checklist in `docs/RELEASE_CHECKLIST.md`.

### Changed

- README now aligns with the 0.8.0 release scope and avoids stale exact framework or detector counts.
- GitHub Action metadata now describes the scanner as covering supported AI agent extension frameworks rather than MCP/OpenClaw only.


## [0.2.4] - 2026-02-20

### Added

- **CrewAI adapter (IBVI-487)** — auto-detects CrewAI Python projects via `pyproject.toml`, `requirements.txt`, or Python imports; reuses existing Python parser and all 12 detectors
- **LangChain adapter (IBVI-486)** — auto-detects LangChain/LangGraph projects via `pyproject.toml`, `requirements.txt`, `langgraph.json`, or Python imports
- **Shared adapter helpers** — `collect_source_files()`, `parse_dependencies()`, `parse_provenance()` promoted to `pub(super)` in `mcp.rs` for reuse across adapters
- Test fixtures: `crewai_project/` (SHIELD-001, -003) and `langchain_project/` (SHIELD-001, -003)
- 12 new tests (95 total, up from 83)

### Changed

- Version bump: 0.2.3 → 0.2.4
- 4 framework adapters total: MCP, OpenClaw, CrewAI, LangChain

## [0.2.3] - 2026-02-20

### Added

- **Test file exclusion (`--ignore-tests`)** — filters test files at file-walking stage before parsing
  - `is_test_file()` matches directories (`test/`, `tests/`, `__tests__/`, `__pycache__/`), suffixes (`.test.*`, `.spec.*`), prefixes (`test_*.py`), and config files (`conftest.py`, `jest.config.*`)
  - Available via CLI flag, `.agentshield.toml` `[scan] ignore_tests = true`, GitHub Action input, and library API
  - `ignore_tests: bool` parameter added to `Adapter::load()` and `auto_detect_and_load()`
- **PR inline annotations verified (IBVI-488)** — tested on [`agentshield-test` PR #1](https://github.com/limaronaldo/agentshield-test/pull/1) with 7 inline annotations on `tools.py`
- 5-platform release binaries

### Changed

- Version bump: 0.2.2 → 0.2.3
- Re-scan of 7 Anthropic reference servers: 170 → 69 findings (59% reduction), signal-to-noise ratio 0.53 → 0.99

## [0.2.2] - 2026-02-20

### Added

- **Cross-file validation tracking (IBVI-482)** — post-parsing analysis phase that eliminates false positives from helper functions receiving already-validated input
  - New `Sanitized { sanitizer }` variant in `ArgumentSource` — `is_tainted()` returns `false`, zero detector changes needed
  - Sanitizer registry recognizes `validatePath`, `path.resolve`, `os.path.realpath`, `parseInt`, `URL.parse`, and pattern-based matches (`validate*Path`, `sanitize*`)
  - TypeScript parser extracts `FunctionDef`, `CallSite`, and `sanitized_vars` from both tree-sitter and regex paths
  - Python parser extracts same structures with Python-specific conventions (`_` prefix = non-exported)
  - `apply_cross_file_sanitization()` algorithm: when ALL call sites pass sanitized arguments, downgrades callee parameters from tainted to sanitized
  - Conservative: exported functions with zero discovered call sites stay tainted
  - 3-phase adapter pipeline (parse → cross-file analysis → merge) in both MCP and OpenClaw adapters
  - New `safe_filesystem` test fixture (3 TypeScript files mimicking Anthropic's filesystem MCP server pattern)
  - Integration test verifying 0 SHIELD-004 findings on the safe filesystem fixture
  - 14 new tests (83 total, up from 69)

### Changed

- Version bump: 0.2.1 → 0.2.2

## [0.2.1] - 2026-02-20

### Fixed

- **Python parser: async HTTP client detection** — `httpx.AsyncClient` / `aiohttp.ClientSession` context manager method calls (`client.get(url)`) now detected as SSRF sinks (SHIELD-003)
- **Python parser: multi-line call support** — function calls spanning multiple lines now detected via `PARTIAL_CALL_RE` with next-line lookahead
- **Python parser: GitPython command detection** — `repo.git.*` dynamic method dispatchers now detected as command injection sinks (SHIELD-001)
- **Typosquat allowlist** — known-safe packages (`vitest`, `nuxt`, `vite`, etc.) no longer flagged as typosquats (SHIELD-010)

### Changed

- Version bump: 0.2.0 → 0.2.1
- License: MIT → MIT OR Apache-2.0 (dual license)
- Published to [GitHub Marketplace](https://github.com/marketplace/actions/agentshield-security-scanner)
- Validation: 0 false negatives remaining across 7 Anthropic MCP reference servers (170 total findings)

## [0.2.0] - 2026-02-20

### Added

- **TypeScript tree-sitter parser** — AST-based parsing replaces regex for TypeScript/JavaScript
  - Multi-line call expression detection (regex parser missed calls spanning multiple lines)
  - Accurate line/column source locations from AST node positions
  - Proper scope-aware parameter tracking across nested callbacks and closures
  - Destructured parameter support (`{ url }` patterns now tracked for taint analysis)
  - TSX/JSX file support via `LANGUAGE_TSX` grammar
  - Feature-gated: `typescript` feature (enabled by default)
  - Regex fallback preserved when feature is disabled (`--no-default-features`)
- **Homebrew formula** — `brew tap limaronaldo/engram && brew install agentshield`
- **Pre-built binaries** — 5-platform release (Linux x86/arm64, macOS x86/arm64, Windows)

### Changed

- Default features now include `typescript` alongside `python`
- `full` feature includes both `python` and `typescript`
- Crate renamed to `agent-shield` on crates.io (binary name unchanged: `agentshield`)
- Version bump: 0.1.0 → 0.2.0

### Fixed

- **Python parser: async HTTP client detection** — `httpx.AsyncClient` / `aiohttp.ClientSession` context manager method calls (`client.get(url)`) now detected as SSRF sinks (SHIELD-003)
- **Python parser: multi-line call support** — function calls spanning multiple lines now detected (e.g., `client.get(\n    url,\n    ...`)
- **Python parser: GitPython command detection** — `repo.git.*` dynamic method dispatchers now detected as command injection sinks (SHIELD-001)
- **Typosquat allowlist** — known-safe packages like `vitest` and `nuxt` no longer flagged as typosquats (SHIELD-010)
- SARIF `startColumn` now 1-based (was 0-based, rejected by GitHub Code Scanning)
- SARIF `fixes[]` replaced with `properties.remediation` (missing required `artifactChanges`)
- SARIF skips location-less findings (supply-chain rules SHIELD-009, -012 have no source location)
- Dockerfile now copies `benches/` directory (build failed when Cargo.toml referenced missing bench)
- Dockerfile bumped to `rust:1.85-slim` (tree-sitter-typescript requires edition2024)

## [0.1.0] - 2026-02-13

### Added

- **12 built-in security detectors**
  - SHIELD-001: Command Injection (Critical, CWE-78)
  - SHIELD-002: Credential Exfiltration (Critical, CWE-522)
  - SHIELD-003: SSRF (High, CWE-918)
  - SHIELD-004: Arbitrary File Access (High, CWE-22)
  - SHIELD-005: Runtime Package Install (High, CWE-829)
  - SHIELD-006: Self-Modification (High, CWE-506)
  - SHIELD-007: Prompt Injection Surface (Medium)
  - SHIELD-008: Excessive Permissions (Medium, CWE-250)
  - SHIELD-009: Unpinned Dependencies (Medium, CWE-1104)
  - SHIELD-010: Typosquat Detection (Medium, CWE-506)
  - SHIELD-011: Dynamic Code Execution (Critical, CWE-95)
  - SHIELD-012: No Lockfile (Low)

- **Framework adapters**
  - MCP (Model Context Protocol) server auto-detection
  - OpenClaw SKILL.md adapter

- **Language parsers**
  - Python (tree-sitter AST + regex source/sink detection)
  - Shell (regex-based command extraction)
  - JSON Schema (MCP tool input parsing)

- **Output formats**
  - Console (plain text with severity badges)
  - JSON (structured findings + verdict)
  - SARIF 2.1.0 (GitHub Code Scanning compatible)
  - HTML (self-contained dark-themed report)

- **Policy system**
  - `.agentshield.toml` configuration
  - Configurable fail-on severity threshold
  - Rule ignore list and severity overrides

- **CLI**
  - `agentshield scan` — scan with format/threshold/output options
  - `agentshield list-rules` — display all rules (table or JSON)
  - `agentshield init` — generate starter config

- **CI/CD**
  - GitHub Action (`action.yml`) with SARIF upload
  - CI workflow (test, clippy, fmt, smoke test on 3 OS)
  - Release workflow (5-platform binary builds with SHA256 checksums)

- **Supply chain analysis**
  - Lockfile detection (pip, poetry, uv, npm, yarn, pnpm)
  - Typosquat detection via Levenshtein distance against popular packages
  - Unpinned dependency version detection

[0.2.4]: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.4
[0.2.3]: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.3
[0.2.2]: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.2
[0.2.1]: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.1
[0.2.0]: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/limaronaldo/agentshield/releases/tag/v0.1.0
