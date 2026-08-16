# 🚀 AgentShield v1.0.0 — Launch & Go-To-Market Kit

This kit contains ready-to-publish launch copy, technical deep dives, and distribution material for announcing **AgentShield v1.0.0** across developer communities.

---

## 1. 🟠 Hacker News (Show HN)

### Title:
> **Show HN: AgentShield – Offline Rust security scanner for AI agent tools & MCP (<50ms)**

### Post Body:
```text
Hey HN,

We built AgentShield (https://github.com/aiconnai/agentshield), an offline-first, sub-50ms security analyzer written in Rust specifically designed for AI agent extensions, Model Context Protocol (MCP) servers, and multi-agent tools.

### Why we built this:
As LLMs (Claude, GPT-5, Gemini, DeepSeek, Antigravity, Hermes) gain autonomous tool execution, they are being connected to databases, shells, cloud APIs, and local file systems. A single malicious or unvetted tool can read AWS secrets, execute arbitrary shell commands, or pivot through your private network via SSRF.

Existing SAST tools (Semgrep, SonarQube) analyze traditional web apps, but miss agent-specific dataflow patterns like:
- Tainted LLM parameters flowing into subprocess executions across helper functions.
- Insecure dynamic deserializers (`yaml.load`) in agent configuration loaders.
- Cloud metadata SSRF (`169.254.169.254`) via unvalidated URL fetch tools.
- Over-permissive filesystem access and unpinned upstream dependencies.

### What AgentShield does:
1. Interprocedural Call-Graph Taint Engine: Builds an AST + interprocedural call-graph to track tainted parameters from tool declarations all the way into deep execution sinks across files.
2. 100% Offline & Private: Zero telemetry, zero cloud calls, executes in <50ms.
3. 7 Framework Adapters: Native support for Model Context Protocol (MCP), Hermes Agent (.hermes.md / SKILL.md), OpenAI Codex / GPT Actions (OpenAPI), Cursor Rules (.cursorrules), CrewAI, LangChain, and OpenClaw.
4. 1-Click Auto-Remediation: Safely patches vulnerable code (e.g. `yaml.load` -> `yaml.safe_load`, pinning unpinned dependencies).
5. Native CI & IDE Integration: Outputs standard SARIF for GitHub Code Scanning and has a dedicated VS Code extension with inline diagnostic squiggles.

### Quick Start:
$ cargo install agent-shield
$ agentshield scan ./my-agent-project --explain

Live Website & Interactive Playground: https://aiconnai.github.io/agentshield/
GitHub: https://github.com/aiconnai/agentshield
Crates.io: https://crates.io/crates/agent-shield

We’d love your feedback on the taint engine, custom rule engine (declarative YAML), and the developer experience!
```

---

## 2. 🐦 X / Twitter Launch Thread

### Tweet 1 (Hook & Value Prop):
> 🛡️ Don't let AI agents execute rogue tools.
> 
> As agents gain autonomy, one unvetted MCP tool can read your AWS secrets, execute arbitrary shell scripts, or pivot through your VPC.
> 
> Introducing AgentShield v1.0.0: The open-source, 100% offline security firewall for AI tools in <50ms. 🧵👇

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

### Tweet 4 (Ecosystem & Model Compatibility):
> 🧩 Model-agnostic & Universal.
> 
> Works out-of-the-box for agents powered by Claude 5 Sonnet/Opus, GPT-5.6 Sol, Gemini 3.7 Flash, DeepSeek-V4, Grok 4.6, Qwen3.8, GLM-5.3, OpenAI Codex, and Google Antigravity.
> 
> Comes with a VS Code extension + GitHub Action for SARIF Code Scanning.

### Tweet 5 (Call to Action):
> Try it now in seconds:
> 
> 📦 `cargo install agent-shield`
> 🌐 Interactive Playground: https://aiconnai.github.io/agentshield/
> ⭐ Star on GitHub: https://github.com/aiconnai/agentshield
> 
> What AI tools are you securing today? Let us know below! 👇

---

## 3. 🔴 Reddit Strategy

### Subreddit: `r/rust`
**Title**: `[Media] AgentShield: A 100% offline AI tool security scanner written in Rust (<50ms, AST + Interprocedural Taint Graph)`
**Key Talking Points**:
- AST parsing using tree-sitter & rust-native regex heuristics.
- Interprocedural call-graph construction with bounded recursion depth (`MAX_PROPAGATION_DEPTH = 16`).
- Zero-allocation sensitivity classifiers (`eq_ignore_ascii_case`).
- Atomic filesystem patcher (`tempfile` + `fs::rename`).
- 555 unit and integration tests, 0 clippy warnings (`-D warnings`).

### Subreddit: `r/LocalLLaMA`
**Title**: `Securing Local Agents & MCP Servers: AgentShield v1.0.0 (Offline SAST Scanner + Runtime Guard)`
**Key Talking Points**:
- Why running local models (Hermes Agent, DeepSeek-R1/V4, Qwen) with local tool access requires zero-trust security.
- How tool poisoning and prompt injection can turn a benign-looking Python MCP server into a shell execution backdoor.
- How AgentShield runs locally without leaking code to cloud scanners.

### Subreddit: `r/cybersecurity` & `r/netsec`
**Title**: `AgentShield: Static Application Security Testing (SAST) for Model Context Protocol (MCP) & AI Agent Extensions`
**Key Talking Points**:
- OWASP Top 10 for LLM Applications mapping (ASI-01 Prompt Injection, ASI-02 Insecure Output Handling, ASI-05 Supply Chain).
- CWE mapping (CWE-78 Command Injection, CWE-918 SSRF, CWE-502 Deserialization).
- GitHub Code Scanning SARIF integration for automated PR gating.

---

## 4. 🏷️ Product Hunt / Launch Directory Snippets

- **Name**: AgentShield
- **Tagline**: The security firewall for AI agent tools & MCP servers
- **Short Description**: 100% offline, model-agnostic Rust SAST scanner & runtime guard that detects command injection, credential theft, and SSRF in AI agent tools in <50ms.
- **Pricing**: 100% Free & Open Source (MIT / Apache-2.0).
