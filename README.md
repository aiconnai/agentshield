# AgentShield

**Find risky behavior in MCP and AI agent extensions before they ship.**

[![CI](https://github.com/limaronaldo/agentshield/actions/workflows/ci.yml/badge.svg)](https://github.com/limaronaldo/agentshield/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Crates.io](https://img.shields.io/crates/v/agent-shield.svg)](https://crates.io/crates/agent-shield)
[![docs.rs](https://img.shields.io/docsrs/agent-shield)](https://docs.rs/agent-shield)

AgentShield is an offline Rust scanner for teams shipping tool-enabled agents
across the current agent stack. Native adapters cover MCP servers, OpenClaw
skills, Hermes Agent configs, CrewAI, LangChain/LangGraph, GPT Actions, and
Cursor Rules; the same checks help harden repos built around OpenAI Agents SDK,
Claude Code, Claude Desktop MCP setups, Browser Use, FastMCP, GitHub MCP Server,
Playwright MCP, and other MCP-heavy workflows. It catches command injection,
credential exfiltration, SSRF, unsafe file access, runtime package installs,
prompt-injection surfaces, and dependency hygiene issues before an agent can
call those tools.

It runs as a CLI, GitHub Action, or library, keeps source code on your machine,
and emits console, JSON, SARIF for GitHub Code Scanning, and standalone HTML
reports. The current release line is `0.8.7`.

## At a glance

| Area | What AgentShield does |
|------|------------------------|
| Scanner surface | Normalizes seven framework/client families into one IR: MCP, OpenClaw, Hermes Agent, CrewAI, LangChain/LangGraph, GPT Actions, and Cursor Rules. |
| Detection | Runs 18 built-in rules for command execution, credential exfiltration, SSRF, filesystem risk, runtime installs, prompt surfaces, dependency hygiene, unsafe deserialization, secret leakage, and more. |
| Workflow fit | Works locally, in CI, and in GitHub Code Scanning without sending source code to a hosted service. |
| Boundary | AgentShield is not a hosted monitoring service, runtime sandbox, or allowlist marketplace. Experimental runtime guard entrypoints are available behind opt-in feature flags; the stable contract is static scanning plus policy evaluation. |

For runtime guard scope and roadmap, see [docs/RUNTIME_GUARD.md](docs/RUNTIME_GUARD.md).

## Works With

AgentShield is useful anywhere an agent can call local tools, remote APIs,
browser automation, file operations, shell commands, or MCP servers.

| Ecosystem | How AgentShield helps |
|-----------|-----------------------|
| Claude Desktop and Claude Code | Scan MCP servers and tool repositories before adding them to Claude MCP configs or coding-agent workflows. |
| Cursor and Cursor Rules | Detect risky agent guidance, MCP server definitions, and tool code that can reach files, commands, or the network. |
| OpenAI Agents SDK | Scan tool implementations, OpenAPI/GPT Actions surfaces, and MCP-connected repos used by OpenAI agent apps. |
| LangGraph and LangChain | Analyze Python/TypeScript tool code and dependency surfaces before agents execute tools. |
| CrewAI | Check Python CrewAI tool projects for command execution, credential exfiltration, SSRF, and unsafe file access. |
| FastMCP, GitHub MCP Server, and Playwright MCP | Scan MCP server code, manifests, schemas, dependencies, and provenance before publishing or installing. |
| Browser Use and browser automation agents | Catch risky command, network, file, and dependency patterns in tool-enabled automation repos. |

Runnable examples live under [examples/](examples/README.md), with focused
guides for [Claude MCP security](docs/claude-mcp-security.md),
[MCP security scanning](docs/mcp-security-scanner.md), and
[OpenAI Agents security](docs/openai-agents-security.md).

---

## Why AgentShield?

AI agents are being connected to tools that can execute commands, read and write files, make HTTP requests, install packages, and call external services. A single malicious or poorly-written extension can:

- **Exfiltrate credentials** by reading environment variables or local secret files and sending them to an attacker-controlled endpoint.
- **Execute arbitrary commands** by passing user-controlled input into shell or process APIs.
- **Install backdoors at runtime** through package manager calls inside tool handlers.
- **Proxy SSRF requests** by fetching URLs derived from tool arguments.
- **Leak sensitive data to model context** through unguarded prompts, tool results, or rule files.

AgentShield catches these patterns with static analysis, framework adapters, policy evaluation, suppressions, baselines, egress policy generation, attestations, and SARIF output for GitHub Code Scanning.

### How it compares

| Feature | AgentShield | mcp-scan | Invariant Labs |
|---------|:-----------:|:--------:|:--------------:|
| Rust single binary | Yes | No | No |
| Offline / local-first | Yes | Partial | No |
| Multi-framework adapters | Yes | MCP-focused | MCP-focused |
| Static analysis | tree-sitter + targeted parsers | Regex-oriented | Runtime/cloud-oriented |
| Cross-file sanitizer analysis | Yes | No | No |
| SARIF output | Yes | No | No |
| GitHub Action | Yes | No | No |

---

## Quick Start

### GitHub Action

Add to `.github/workflows/security.yml`:

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: aiconnai/agentshield@main
        with:
          path: '.'
          fail-on: 'high'
          ignore-tests: true
          upload-sarif: true
```

Findings appear as PR annotations and in the repository's **Security > Code scanning** tab when SARIF upload is enabled.

### CLI

```bash
# Install the current release from GitHub with the full feature set
cargo install --git https://github.com/limaronaldo/agentshield --tag v0.8.7 --features full --force

# First-run setup: config + explained first scan
agentshield quickstart

# Understand the gate, coverage, confidence, and next actions
agentshield scan . --ignore-tests --fail-on high --explain

# Add a GitHub Actions workflow
agentshield ci install

# Adopt in an existing repo without blocking on known findings
agentshield scan --write-baseline .agentshield-baseline.json
agentshield ci install --baseline .agentshield-baseline.json

# Generate a standalone HTML report
agentshield scan ./my-agent-extension --format html --output report.html

# List all rules
agentshield list-rules

# Create starter config
agentshield init
```

If you only need static scanning in a published crates.io version, `cargo
install agent-shield` is also supported. Use the GitHub tag command above when
you need the latest release line before crates.io has been updated.

### Pre-built binaries

Download from the [latest release](https://github.com/limaronaldo/agentshield/releases/latest) for Linux, macOS, and Windows targets.

For container consumers, the release image tag is:

```text
ghcr.io/aiconnai/agentshield:0.8.7
```

### Docker

The GHCR image is built with the `full` feature set, including runtime `wrap` support and experimental runtime guard commands. The image is published for `linux/amd64` and `linux/arm64`.

```bash
docker pull ghcr.io/aiconnai/agentshield:0.8.7
docker run --rm -v "$PWD:/scan" ghcr.io/aiconnai/agentshield:0.8.7 scan .
docker run --rm ghcr.io/aiconnai/agentshield:0.8.7 --version
```

If the GHCR package is private in your organization, authenticate first:

```bash
gh auth refresh -h github.com -s read:packages
gh auth token | docker login ghcr.io -u "$(gh api user --jq .login)" --password-stdin
```

### From source

```bash
git clone https://github.com/limaronaldo/agentshield.git
cd agentshield
cargo build --release
./target/release/agentshield scan /path/to/agent-extension
```

## Token-Optimized Local Checks with RTK

AgentShield can produce noisy command output during local development, especially from `cargo test`, `cargo clippy`, and scanner runs that emit JSON or SARIF. If `rtk` is installed, use the optional wrapper to reduce output shown to humans and coding agents:

```bash
scripts/rtk-check.sh quick
scripts/rtk-check.sh test
scripts/rtk-check.sh clippy
scripts/rtk-check.sh scan-fixture
```

The wrapper is intentionally local-only. RTK filters local command output only. It must not alter AgentShield JSON, SARIF, HTML, or console output contracts consumed by users, clients, CI, or GitHub Code Scanning.

Use raw output for debugging, audit, and security decisions:

```bash
scripts/rtk-check.sh raw -- cargo test
scripts/rtk-check.sh raw -- cargo run -- scan tests/fixtures/mcp_servers/safe_calculator --format sarif --output target/agentshield/scan.sarif
```

Policy:

- Use filtered output for fast local feedback.
- Use raw output when investigating test failures, parser bugs, detector behavior, or security-sensitive findings.
- Always write complete `json` and `sarif` reports to files when clients or CI consume them.

---

## Supported Frameworks

AgentShield runs all matching adapters in a repository instead of stopping at the first match.

| Framework | Status | Adapter coverage |
|-----------|--------|------------------|
| MCP (Model Context Protocol) | Supported | MCP server manifests, Python/TypeScript/JavaScript source, tool schemas, dependencies, provenance |
| OpenClaw | Supported | `SKILL.md` skill files plus related source/dependency surfaces |
| Hermes Agent | Supported | Hermes config/profile files, `mcp_servers`, `.hermes.md`, skill trees, optional MCP manifests |
| CrewAI | Supported | Python projects detected from dependency metadata or imports |
| LangChain / LangGraph | Supported | LangChain/LangGraph dependency metadata, imports, and `langgraph.json` |
| GPT Actions | Supported | Action/OpenAPI-style surfaces for custom GPT integrations |
| Cursor Rules | Supported | Cursor rule files and related agent guidance surfaces |

---

## CLI Commands

| Command | Purpose |
|---------|---------|
| `agentshield scan [path]` | Scan an agent extension directory and emit console, JSON, SARIF, or HTML output. |
| `agentshield scan [path] --explain` | Print a console-only gate, coverage, confidence, grouped findings, next-actions, and limits summary. |
| `agentshield quickstart [path]` | Create first-run config, suggest CI setup, run the first scan, and explain the result. |
| `agentshield ci install` | Generate a GitHub Actions workflow for AgentShield. |
| `agentshield ci install --baseline <path>` | Generate a workflow that filters known findings through a baseline file. |
| `agentshield list-rules` | List available detection rules as a table or JSON. |
| `agentshield doctor [path]` | Print environment, config, compile-feature, and adapter diagnostics. |
| `agentshield init` | Generate a starter `.agentshield.toml` config file. |
| `agentshield suppress <fingerprint>` | Add a suppression entry with a required reason and optional expiry. |
| `agentshield list-suppressions` | Show suppressions configured in `.agentshield.toml`. |
| `agentshield certify [path]` | Generate a DSSE attestation envelope for scan results. |
| `agentshield wrap --policy <path> -- <command>` | Enforce an egress policy through a local HTTP proxy when built with the `runtime` feature. |
| `agentshield guard --stdin` | Evaluate one runtime event JSON document when built with the `runtime-guard` feature. |
| `agentshield guard --mcp-proxy [-- <server cmd...>]` | EXPERIMENTAL: evaluate line-delimited MCP JSON-RPC `tools/call` messages, block unsafe calls, and either emit forward markers or bridge stdio to a spawned downstream MCP server when built with the `runtime-guard` feature. |

Useful `scan` options include `--config`, `--format`, `--fail-on`, `--output`, `--ignore-tests`, `--explain`, `--baseline`, `--write-baseline`, and `--emit-egress-policy`.
Configured `[scan] include` and `[scan] exclude` filters scope source and
metadata-derived findings before detectors run.

For mature repositories with existing findings, write a baseline first and use
it in CI:

```bash
agentshield scan --write-baseline .agentshield-baseline.json
agentshield scan --baseline .agentshield-baseline.json --explain
agentshield ci install --baseline .agentshield-baseline.json
```

`--explain` is intentionally console-only. It will not append text to JSON,
SARIF, or HTML output. Explain output includes the scan root, metadata root
when different, and hotspot summaries for concentrated blocking findings.

---

## Detection Rules

AgentShield ships built-in rules for command execution, credential exfiltration, SSRF, arbitrary file access, runtime package installation, self-modification, prompt injection surfaces, excessive permissions, dependency hygiene, dynamic code execution, metadata service access, download-and-execute flows, overbroad filesystem capabilities, unsafe deserialization, archive traversal, and secret leakage.

Use the CLI for the authoritative rule list in your installed version:

```bash
agentshield list-rules
agentshield list-rules --format json
```

---

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Console | `--format console` | Local development default |
| JSON | `--format json` | Programmatic consumption and fingerprint extraction |
| SARIF | `--format sarif` | GitHub Code Scanning and compatible tools |
| HTML | `--format html` | Shareable standalone reports |

---

## Configuration

### Trust workflows

AgentShield includes trust workflow documentation for baselines, suppressions, certification attestations, and egress enforcement:

- `docs/BASELINES.md`: write and use `.agentshield-baseline.json` for known findings.
- `docs/SUPPRESSIONS.md`: suppress individual findings by fingerprint with required reasons and optional expiry.
- `docs/CERTIFICATION.md`: generate unsigned or Ed25519-signed DSSE attestations.
- `docs/EGRESS.md`: emit `agentshield.egress.toml` and enforce it with `agentshield wrap`.

Release binaries are built with the `full` feature set, including Python parsing, TypeScript parsing, runtime `wrap` support, and experimental runtime guard commands. If building from source, use `cargo build --features full --release` to include `agentshield wrap` and `agentshield guard`.

Create `.agentshield.toml` in your project root or run `agentshield init`:

```toml
[policy]
# Minimum severity to fail the scan: info, low, medium, high, critical
fail_on = "high"

# Rules to skip entirely
ignore_rules = ["SHIELD-008"]

# Downgrade specific rules
[policy.overrides]
"SHIELD-012" = "info"

[scan]
# Skip test files before parsing
ignore_tests = true

# Optional path filters are relative to the scan root.
# Empty include means all scan-supported files are eligible.
# Use ** for recursive directories; * and ? stay within one path segment.
include = ["src/**", "tools/**"]
exclude = ["legacy/**", "**/generated/**", "vendor/**"]

[runtime.proxy]
# Runtime MCP proxy guard blocking threshold: block, warn, or never.
fail_on = "block"

[[runtime.proxy.tool]]
name = "calculator.add"
fail_on = "never"
```

Suppressions can be added through `agentshield suppress <fingerprint> --reason "..."` after obtaining finding fingerprints from JSON output.

When both `include` and `exclude` match a file, `exclude` wins. Use
`agentshield scan . --explain` to confirm the active path filters and parsed
source-file count before relying on a focused scan in CI.
Path filter matching is case-sensitive, accepts `/` on all platforms, treats
leading `./` or `/` as relative to the scan root, and treats a trailing slash
such as `legacy/` as matching that directory's contents.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan passed with no findings above threshold |
| 1 | Scan failed with findings above threshold |
| 2 | Scan error, such as invalid config or no supported adapter found |
| 3 | Runtime guard blocked or failed closed on invalid runtime input |

---

## Language Support

| Language | Parser | Feature flag |
|----------|--------|--------------|
| Python | Regex parser with source/sink patterns | `python` compatibility flag (default) |
| TypeScript/TSX | tree-sitter AST with fallback patterns | `typescript` (default) |
| JavaScript/JSX | tree-sitter AST through TypeScript grammar support | `typescript` (default) |
| Shell | Regex parser | always on |
| JSON Schema / OpenAPI-style schemas | Schema parser | always on |

TypeScript tree-sitter support is feature-gated; the Python compatibility flag keeps existing build commands stable:

```bash
cargo build --no-default-features
cargo build --features python
cargo build --features full
```

The `full` feature enables language parsers plus the runtime proxy used by `agentshield wrap` and the experimental runtime guard commands.

---

## Architecture

```text
CLI / GitHub Action / Library API
       |
       v
Scan Engine -> ScanReport
       |
       v
Adapters -> Parsers -> Cross-file analysis -> Unified IR (ScanTarget)
       |
       v
Rule Engine -> Policy / Suppressions / Baseline filtering
       |
       v
Console / JSON / SARIF / HTML / DSSE attestation
```

Adapters translate framework-specific files into a unified intermediate representation. Detectors consume only that IR, so new frameworks can be added without rewriting every rule. Policy, suppressions, and baselines are separate from detection so scans remain explainable and repeatable.

---

## Security Policy

Please report vulnerabilities privately. See [`SECURITY.md`](SECURITY.md) for supported versions, reporting guidance, and disclosure scope.

---

## Development

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
cargo run -- list-rules
```

For release-specific notes, see `docs/releases/0.8.6.md`,
`docs/releases/0.8.7.md`, and `docs/RELEASE_CHECKLIST.md`.
