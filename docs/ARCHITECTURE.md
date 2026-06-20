# Architecture

This document describes the internal architecture of AgentShield.

## Overview

AgentShield is a **static analysis tool** that scans AI agent extensions for security
vulnerabilities. It follows a pipeline architecture:

```
Input Files → Adapter (parse → cross-file analysis → merge) → Unified IR → Detectors → Findings → Policy → Output
```

The key design principle is **separation of concerns**: adapters handle
framework-specific parsing, cross-file analysis eliminates false positives
from validated helper functions, detectors operate only on the unified IR,
and output formatters produce different report formats.

## Runtime Guard Roadmap

AgentShield's stable architecture is the offline static scanning pipeline described in this document. Runtime guard components are experimental and must preserve the scanner's existing contracts while reusing the same policy vocabulary.

Runtime guard components must consume the same policy concepts as static detection: severity thresholds, rule identity, suppression intent, operator decisions, and pass/warn/block verdicts should map cleanly to the static policy model instead of creating a separate policy dialect.

Runtime guard work must not change the SARIF, JSON, HTML, or console scanner output contracts unless those contracts are explicitly versioned. SARIF output used by GitHub Code Scanning is especially sensitive and should remain a static scanner artifact unless a future versioned format says otherwise.

Runtime observations can contain prompts, tool arguments, URLs, paths, headers, or environment-derived values. Runtime data should flow through secret redaction before it is written to logs or structured output.

## Pipeline Stages

### 1. Adapter (Framework Detection)

```
src/adapter/mod.rs       — Adapter trait, auto_detect_and_load()
src/adapter/mcp.rs       — MCP server adapter + shared helpers (pub(super))
src/adapter/openclaw.rs  — OpenClaw SKILL.md adapter
src/adapter/hermes.rs    — Hermes Agent config, MCP server, and skill adapter
src/adapter/crewai.rs    — CrewAI Python adapter
src/adapter/langchain.rs — LangChain / LangGraph Python adapter
```

Each adapter implements:

```rust
pub trait Adapter: Send + Sync {
    fn framework(&self) -> Framework;
    fn detect(&self, root: &Path) -> bool;
    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>>;
}
```

- `detect()` checks for framework-specific files (e.g., `package.json` with MCP SDK)
- `load()` uses parsers to populate a `ScanTarget`; when `ignore_tests` is true, test files are filtered out before parsing via `is_test_file()`
- **All matching adapters run** — a project can be both an MCP server and contain OpenClaw skills
- **Shared helpers** — `collect_source_files()`, `parse_dependencies()`, `parse_provenance()` in `mcp.rs` are `pub(super)` and reused by CrewAI and LangChain adapters
- **Client config adapters** (Hermes Agent, Cursor Rules) turn configured MCP servers and agent guidance files into the same IR used by source-framework adapters
- **Python-only adapters** (CrewAI, LangChain) collect all source files then filter to `.py` only

### 2. Parser (Language Analysis)

```
src/parser/mod.rs         — Parser trait, ParsedFile, FunctionDef, CallSite
src/parser/python.rs      — compiled regex source/sink extraction
src/parser/typescript.rs  — tree-sitter TypeScript/TSX + regex fallback
src/parser/shell.rs       — regex-based command extraction
src/parser/json_schema.rs — JSON Schema → ToolSurface
```

Parsers extract structured information from source files into `ParsedFile`:

- **Function calls** with argument sources (literal, parameter, interpolated, env var, sanitized)
- **Environment variable access** patterns
- **File operations** with path sources
- **Network operations** with URL sources
- **Shell commands** (pip install, curl, eval)
- **Function definitions** (`FunctionDef`) — name, parameters, `is_exported` (v0.2.2)
- **Call sites** (`CallSite`) — callee name, classified arguments, caller context (v0.2.2)
- **Sanitized variables** (`sanitized_vars`) — variables holding return values of sanitizer functions (v0.2.2)

Python uses compiled regex patterns for source/sink extraction. TypeScript uses
tree-sitter AST parsing with compiled regex patterns, plus a regex fallback when
the `typescript` feature is disabled.

### 2.5. Cross-File Analysis (v0.2.2)

```
src/analysis/cross_file.rs — Sanitizer-aware call-site analysis
```

Runs **after parsing, before detection** as part of the adapter pipeline. Eliminates
false positives from internal helper functions that receive already-validated input.

#### The Problem

```typescript
// index.ts — public handler
const validPath = await validatePath(args.path);  // sanitizer
const content = await readFileContent(validPath);  // passes sanitized value

// operations.ts — internal helper
export async function readFileContent(filePath: string) {
    return fs.readFile(filePath, 'utf-8');  // ← was flagged as SHIELD-004 (false positive)
}
```

Without cross-file analysis, the scanner sees `filePath` as a `Parameter` (tainted)
and flags the `fs.readFile` call. But the caller always validates input first.

#### The Algorithm

`apply_cross_file_sanitization(&mut [(PathBuf, ParsedFile)])` runs in 4 phases:

1. **Build function def map** — `HashMap<name, Vec<(file_idx, params, is_exported)>>`
2. **Build call-site map** — `HashMap<callee, Vec<argument_sources>>`
3. **Check each function** — if ALL call sites pass `Sanitized` or `Literal` for a parameter, mark it for downgrade
4. **Downgrade operations** — replace `ArgumentSource::Parameter { name }` with `ArgumentSource::Sanitized { sanitizer }` in the callee's commands, file ops, network ops, and dynamic exec

**Conservative rules:**
- Exported functions with zero discovered call sites stay tainted (can't prove safety)
- If ANY call site passes a tainted argument, the parameter stays tainted
- One level deep only (caller → callee, not recursive)

#### Sanitizer Registry

`is_sanitizer(name)` recognizes functions by exact name, method part after dot, or pattern:

| Category | Names |
|----------|-------|
| Path | `validatePath`, `sanitizePath`, `normalizePath`, `resolvePath`, `canonicalizePath`, `realpath` |
| Node.js | `resolve`, `normalize` (method part of `path.resolve`, `path.normalize`) |
| Python | `abspath`, `normpath` (method part of `os.path.abspath`, `os.path.normpath`) |
| URL | `parseUrl`, `urlparse` |
| Type coercion | `parseInt`, `parseFloat`, `Number`, `int`, `float`, `str` |
| Pattern-based | anything matching `*validate*path*` or `*validate*url*` |

### 3. Unified IR (Intermediate Representation)

```
src/ir/mod.rs                — ScanTarget, Framework, SourceFile
src/ir/tool_surface.rs       — Tool definitions, permissions
src/ir/execution_surface.rs  — Commands, file IO, network IO, env vars
src/ir/data_surface.rs       — Sources, sinks, taint paths
src/ir/dependency_surface.rs — Dependencies, lockfiles, issues
src/ir/provenance_surface.rs — Author, repo, license
```

Every adapter produces a `ScanTarget` with 5 surfaces:

```rust
pub struct ScanTarget {
    pub name: String,
    pub framework: Framework,
    pub root_path: PathBuf,
    pub tools: Vec<ToolSurface>,
    pub execution: ExecutionSurface,
    pub data: DataSurface,
    pub dependencies: DependencySurface,
    pub provenance: ProvenanceSurface,
    pub source_files: Vec<SourceFile>,
}
```

#### ArgumentSource (Taint Abstraction)

The core insight: detectors don't need full dataflow analysis. They need to know
**where a function argument came from**:

```rust
pub enum ArgumentSource {
    Literal(String),              // Safe — hardcoded value
    Parameter { name: String },   // Dangerous — from tool input
    EnvVar { name: String },      // Context-dependent
    Interpolated,                 // Dangerous — string concatenation
    Unknown,                      // Conservative — flag with lower confidence
    Sanitized { sanitizer: String }, // Safe — validated by cross-file analysis (v0.2.2)
}
```

`is_tainted()` returns `true` for everything except `Literal` and `Sanitized`.
The `Sanitized` variant was added in v0.2.2 and is produced by `apply_cross_file_sanitization()` — zero detector changes were needed since detectors already check `is_tainted()`.

### 4. Detector Engine

```
src/rules/mod.rs          — RuleEngine, Detector trait
src/rules/finding.rs      — Finding, Severity, Confidence, Evidence
src/rules/builtin/        — 18 built-in detectors
```

Each detector implements:

```rust
pub trait Detector: Send + Sync {
    fn metadata(&self) -> RuleMetadata;
    fn run(&self, target: &ScanTarget) -> Vec<Finding>;
}
```

The `RuleEngine` collects all registered detectors and runs them against each target:

```rust
pub fn run(&self, target: &ScanTarget) -> Vec<Finding> {
    self.detectors.iter().flat_map(|d| d.run(target)).collect()
}
```

Detectors read only from the IR — they never access the filesystem directly.

### 5. Policy Evaluation

```
src/rules/policy.rs — PolicyConfig, PolicyVerdict
src/config/mod.rs   — .agentshield.toml parsing (policy + scan sections)
```

Policy is separate from detection:

- **Detectors always run** and produce all findings
- **Policy filters**: ignore rules, apply severity overrides
- **Policy evaluates**: compare highest severity against threshold
- **Verdict**: pass/fail with metadata (threshold, highest severity)

### 6. Output

```
src/output/mod.rs     — OutputFormat enum, render()
src/output/console.rs — Plain text with severity badges
src/output/json.rs    — Structured JSON
src/output/sarif.rs   — SARIF 2.1.0 (GitHub Code Scanning)
src/output/html.rs    — Self-contained HTML report
```

All formatters receive `(&[Finding], &PolicyVerdict)` and produce a `String`.

## Data Flow

```
                    ┌──────────────────────────────────────────┐
                    │  auto_detect_and_load(path, ignore_tests) │
                    └──────────┬───────────────────────────────┘
                               │
              ┌───────────┬────────────┬────────────┐
              ▼           ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐
        │   MCP    │ │ OpenClaw │ │  CrewAI  │ │ LangChain │
        │ Adapter  │ │ Adapter  │ │ Adapter  │ │  Adapter  │
        └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘
             │             │            │             │
             │  3-phase pipeline per adapter:
             │
             │  Phase 0: Walk files (skip test files if ignore_tests)
             │  Phase 1: Parse each source file
             │           ↓ Vec<(PathBuf, ParsedFile)>
             │
             │  Phase 2: apply_cross_file_sanitization()
             │           ↓ downgrades tainted → Sanitized
             │
             │  Phase 3: Merge into ScanTarget
             │
             ▼
        Vec<ScanTarget>
             │
             ▼
     ┌───────────────┐
     │  RuleEngine   │
     │  18 detectors │
     └───────┬───────┘
             │
        Vec<Finding>
             │
      ┌──────▼───────┐
      │    Policy     │
      │ filter/eval   │
      └──────┬───────┘
             │
    (Vec<Finding>, PolicyVerdict)
             │
      ┌──────▼───────┐
      │    Output     │
      │ format/render │
      └──────────────┘
```

## Error Handling

```
src/error.rs — ShieldError enum
```

All public APIs return `Result<T, ShieldError>`. Error variants:

- `NoAdapter` — no framework detected at the given path
- `Config` — invalid `.agentshield.toml`
- `Parse` — source file parsing failure
- `Io` — filesystem errors
- `Serialization` — JSON/SARIF output errors

Exit codes: `0` = pass, `1` = findings above threshold, `2` = scan error.

## Test File Exclusion

```
src/adapter/mcp.rs — is_test_file() helper (shared by all adapters)
```

When `--ignore-tests` is enabled (via CLI flag, `.agentshield.toml`, or `ScanOptions`), test files
are excluded at the file-walking stage — before parsing. This is the earliest possible point in the
pipeline and avoids wasting time parsing files that will be ignored.

`is_test_file(path)` matches:
- **Directories:** `test/`, `tests/`, `__tests__/`, `__pycache__/`
- **Suffixes:** `.test.{ts,js,tsx,jsx,py}`, `.spec.{ts,js,tsx,jsx}`
- **Prefixes:** `test_*.py` (pytest convention)
- **Config files:** `conftest.py`, `jest.config.*`, `vitest.config.*`, `pytest.ini`, `setup.cfg`

The flag can be set via three channels (OR'd together):
1. CLI: `--ignore-tests`
2. Config: `[scan] ignore_tests = true`
3. Library: `ScanOptions { ignore_tests: true, .. }`

## Performance Characteristics

- Single-threaded pipeline (detectors are fast enough)
- tree-sitter parsing is the heaviest operation
- Cross-file analysis is O(functions × call_sites) — negligible overhead
- Regex patterns are compiled once via `once_cell::Lazy`
- No network I/O — fully offline
- Typical scan: < 50ms for a single MCP server

## Extension Points

### Adding a Framework

1. Implement `Adapter` trait in `src/adapter/`
2. Register in `all_adapters()`
3. Reuse existing parsers or add new ones

### Adding a Language Parser

1. Add tree-sitter grammar as an optional dependency
2. Feature-gate it in `Cargo.toml`
3. Implement extraction → `ExecutionSurface` / `DataSurface`

### Adding a Detector

1. Implement `Detector` trait in `src/rules/builtin/`
2. Register in `all_detectors()`
3. Operate only on `ScanTarget` — never access files directly

### Adding an Output Format

1. Implement `render()` function in `src/output/`
2. Add variant to `OutputFormat` enum
3. Wire into `output::render()` match
