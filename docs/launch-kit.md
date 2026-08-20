# 🚀 AgentShield v1.0.1 — Launch & Go-To-Market Kit

This kit contains ready-to-publish launch copy, technical deep dives, and distribution material for announcing **AgentShield v1.0.1** across developer communities.

---

## 1. 🟠 Hacker News (Show HN)

### URL to submit:
`https://news.ycombinator.com/submit`

### Title:
> **Show HN: AgentShield – Offline Rust security scanner for AI agent tools & MCP (<50ms)**

### Post Body:
```text
Hey HN,

We built AgentShield (https://github.com/aiconnai/agentshield), an offline-first, sub-50ms security analyzer written in Rust specifically designed for AI agent extensions, Model Context Protocol (MCP) servers, and multi-agent tools.

### Why we built this:
As frontier LLMs (Claude 5 Sonnet/Opus, GPT-5.6 Sol, Gemini 3.7 Flash, DeepSeek-V4, Grok 4.6, Qwen3.8, GLM-5.3, Codex, Antigravity) gain autonomous tool execution, they are being connected to production databases, shells, cloud APIs, and local file systems. A single malicious or unvetted tool can read AWS secrets, execute arbitrary shell commands, drop reverse shells, or exfiltrate private files via webhooks.

Existing SAST tools (Semgrep, SonarQube) analyze traditional web apps, but miss agent-specific dataflow patterns like:
- Tainted LLM parameters flowing into subprocess executions across nested helper functions.
- Insecure dynamic deserializers (`yaml.load`, `pickle.loads`, `torch.load` checkpoints) in agent configuration loaders.
- Cross-Site SSE Hijacking on unauthenticated MCP Server-Sent Events transports without origin validation.
- SQL Injection in MCP database servers (`cursor.execute(f"...")`, `prisma.$queryRawUnsafe`).
- Cloud metadata SSRF (`169.254.169.254`) via unvalidated URL fetch tools.
- System prompt injection tampering where untrusted parameters override system instructions.
- Over-permissive filesystem access and unpinned upstream dependencies.

### What AgentShield does:
1. Interprocedural Call-Graph Taint Engine: Builds an AST + interprocedural call-graph in native Rust to track tainted parameters from tool declarations all the way into deep execution sinks across files.
2. 100% Offline & Private: Zero telemetry, zero cloud calls, executes in <50ms.
3. 11 Framework Adapters: Native support for Model Context Protocol (MCP), Hermes Agent (.hermes.md / SKILL.md), OpenAI Codex / GPT Actions (OpenAPI), Cursor Rules (.cursorrules), CrewAI, LangChain/LangGraph, OpenClaw, Vercel AI SDK, AutoGen, LlamaIndex, and Semantic Kernel.
4. 35 Built-in Security Rules: Comprehensive coverage for OWASP MCP Top 10 (2025) and CWEs (SHIELD-001..035).
5. 1-Click Auto-Remediation: Safely patches vulnerable code (e.g. `yaml.load` -> `yaml.safe_load`, pinning unpinned dependencies).
6. Continuous Fuzzing & Criterion Benchmarks: Fuzz-tested with cargo-fuzz (libfuzzer-sys) and proptest property-based generative testing.
7. Native IDE & CI Integration: Official VS Code Extension (Marketplace & Open VSX) with lightbulb code actions, and GitHub Action for automated SARIF Code Scanning.

### Quick Start:
# ⚡ 1-Line Universal Installer (macOS & Linux):
$ curl -fsSL https://aiconnai.github.io/agentshield/install.sh | sh

# 🍺 Or Homebrew:
$ brew tap aiconnai/tap && brew install agentshield

# 🦀 Or Cargo:
$ cargo install agent-shield

# Scan your project:
$ agentshield scan ./my-agent-project --explain

- Live Website & Interactive Playground: https://aiconnai.github.io/agentshield/
- GitHub Marketplace Action: https://github.com/marketplace/actions/agentshield-security-scanner
- VS Code Extension: https://marketplace.visualstudio.com/items?itemName=aiconnai-vs.agentshield
- Open VSX (Cursor / Windsurf): https://open-vsx.org/extension/aiconnai-vs/agentshield
- GitHub: https://github.com/aiconnai/agentshield
- Crates.io: https://crates.io/crates/agent-shield

We’d love your feedback on the taint engine, custom rule engine (declarative YAML), and the developer experience!
```

---

## 2. 🐦 X / Twitter Launch Thread

### Tweet 1 (Hook & Value Prop):
> 🛡️ Don't let AI agents execute rogue tools.
> 
> As agents gain autonomy, one unvetted MCP tool can read your AWS secrets, execute arbitrary shell scripts, or pivot through your VPC.
> 
> Introducing AgentShield v1.0.1: The open-source, 100% offline security firewall for AI tools in <50ms. 🧵👇

### Tweet 2 (The Architecture):
> ⚡ Powered by Rust + Interprocedural Call-Graph Taint Analysis.
> 
> AgentShield parses your tool schemas (MCP, Hermes, Cursor, CrewAI, LangChain) into a unified Intermediate Representation (IR) and traces tainted parameter flows into execution sinks across files.
> 
> Zero cloud calls. 100% local privacy.

### Tweet 3 (The Terminal Demo):
> 🔍 Real-time blocking in action:
> 
> ```bash
> $ agentshield scan ./agent-tools --fail-on high --explain
> 
> [BLOCKED] tools/executor.py:18 SHIELD-001 (Critical)
>   Flow: Tool 'exec_task' param 'query' -> helper_format() -> subprocess.run(shell=True)
> 
> [FIXABLE] config/settings.py:42 SHIELD-016 (High) — Insecure yaml.load()
> 
> $ agentshield fix .
> ✔ 1 patch applied cleanly. Zero vulnerabilities remaining.
> ```

### Tweet 4 (IDE & Ecosystem):
> 🧩 Available everywhere you build:
> 
> 🐙 GitHub Marketplace: https://github.com/marketplace/actions/agentshield-security-scanner
> 🔵 VS Code Marketplace: https://marketplace.visualstudio.com/items?itemName=aiconnai-vs.agentshield
> 🟣 Open VSX (Cursor / Windsurf): https://open-vsx.org/extension/aiconnai-vs/agentshield
> 🦀 Crates.io: https://crates.io/crates/agent-shield
> 🍺 Homebrew: `brew install aiconnai/tap/agentshield`

### Tweet 5 (Call to Action):
> Try it now in seconds:
> 
> ⚡ `curl -fsSL https://aiconnai.github.io/agentshield/install.sh | sh`
> 🌐 Interactive Playground: https://aiconnai.github.io/agentshield/
> ⭐ Star on GitHub: https://github.com/aiconnai/agentshield
> 
> What AI tools are you securing today? Let us know below! 👇

---

## 3. 🔴 Reddit Strategy

### Subreddit: `r/rust`
**Title**: `[Media] AgentShield v1.0.1: A 100% offline AI tool security scanner written in Rust (<50ms, AST + Interprocedural Taint Graph)`
**Key Talking Points**:
- AST parsing using tree-sitter & rust-native regex heuristics.
- Interprocedural call-graph construction with bounded recursion depth (`MAX_PROPAGATION_DEPTH = 16`).
- Zero-allocation sensitivity classifiers (`eq_ignore_ascii_case`).
- Continuous fuzzing with `cargo-fuzz` / `libfuzzer-sys` and `proptest` generative property suites.
- 587 unit and integration tests, 0 clippy warnings (`-D warnings`).
- Dual-licensed under MIT OR Apache-2.0.

### Subreddit: `r/LocalLLaMA`
**Title**: `Securing Local Agents & MCP Servers: AgentShield v1.0.1 (Offline SAST Scanner + Runtime Guard)`
**Key Talking Points**:
- Why running local models (Hermes Agent, DeepSeek-R1/V4, Qwen) with local tool access requires zero-trust security.
- How tool poisoning, unsigned checkpoint loading (`SHIELD-034`), and unauthenticated SSE transports (`SHIELD-035`) can turn a benign-looking MCP server into a shell execution backdoor.
- How AgentShield runs locally without leaking code to cloud scanners.
- How to install via `curl | sh`, `brew`, or `cargo`.

### Subreddit: `r/cybersecurity` & `r/netsec`
**Title**: `AgentShield: Static Application Security Testing (SAST) for Model Context Protocol (MCP) & AI Agent Extensions`
**Key Talking Points**:
- OWASP Top 10 for LLM Applications and MCP mapping (MCP01..MCP10).
- CWE mapping (CWE-78 Command Injection, CWE-89 SQL Injection, CWE-918 SSRF, CWE-502 Deserialization, CWE-346 Origin Validation, CWE-200 Exfiltration, CWE-74 Prompt Tampering).
- GitHub Code Scanning SARIF integration for automated PR gating.

---

## 4. 🚀 Product Hunt

### Tagline:
> **The 100% offline security firewall for AI agent tools & MCP servers (<50ms)**

### Short Description:
> Protect your autonomous AI agents and MCP servers from command injection, credential theft, and toxic data flows. Built in Rust with an interprocedural taint engine, 35 security rules, 1-click auto-fix, VS Code extension, GitHub Marketplace Action, and SARIF CI integration.

