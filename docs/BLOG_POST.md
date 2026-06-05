# We Scanned 19 MCP Servers — Here's What We Found

*AI agents are gaining powerful tools through the Model Context Protocol. But who's checking the tools themselves?*

---

We built [AgentShield](https://github.com/limaronaldo/agentshield), an open-source security scanner for AI agent extensions, and pointed it at some of the most popular MCP servers on GitHub. The results were eye-opening: **126 security findings** across 19 scan targets, including a critical arbitrary code execution vulnerability in a server with 17,000 stars.

## The Problem

The [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) lets AI assistants like Cursor, Windsurf, and other MCP clients call external tools — read files, query databases, browse the web, control applications. It's powerful. It's also a new attack surface.

When you install an MCP server, you're giving an AI agent the ability to execute code on your machine. Most developers review the *agent's* behavior but not the *tools* it's calling. A malicious or poorly-written MCP server can:

- **Execute arbitrary code** on your machine
- **Read or write any file** the process has access to
- **Make network requests** to internal services (SSRF)
- **Exfiltrate credentials** through tool responses
- **Install packages at runtime** without your knowledge

We wanted to find out: how common are these issues in the real world?

## Methodology

We selected 12 of the most popular MCP server repositories on GitHub, representing approximately 250,000 combined stars:

| Repository | Stars | Language |
|-----------|-------|----------|
| modelcontextprotocol/servers (official) | ~79k | TS + Python |
| awslabs/mcp (15+ AWS servers) | ~8k | Python |
| ahujasid/blender-mcp | ~17k | Python |
| firecrawl/firecrawl-mcp-server | ~6k | TypeScript |
| executeautomation/mcp-playwright | ~5k | TypeScript |
| cloudflare/mcp-server-cloudflare | ~3k | TypeScript |
| supabase-community/supabase-mcp | ~3k | TypeScript |
| benborla/mcp-server-mysql | ~1k | TypeScript |

We ran AgentShield against each, scanning for 12 categories of vulnerabilities including command injection, SSRF, credential exfiltration, arbitrary file access, and supply chain issues.

## Results at a Glance

| Severity | Findings |
|----------|----------|
| Critical | 1 |
| High | 31 |
| Medium | 88 |
| Low | 6 |
| **Total** | **126** |

**8 of 19 targets were completely clean** (42%). The official Anthropic Python servers (`fetch`, `git`) had zero findings. But 11 targets had issues ranging from unpinned dependencies to arbitrary code execution.

## The Findings

### Finding #1: `exec()` on User Input (Critical)

**Server:** [blender-mcp](https://github.com/ahujasid/blender-mcp) (17k stars)
**Rule:** SHIELD-011 — Dynamic Code Execution
**Severity:** Critical

This was the most alarming finding. The server exposes an `execute_code` tool that passes user-supplied code directly to Python's `exec()`:

```python
# addon.py, line 421-436
def execute_code(self, code):
    """Execute arbitrary Blender Python code"""
    # This is powerful but potentially dangerous - use with caution
    try:
        namespace = {"bpy": bpy}
        capture_buffer = io.StringIO()
        with redirect_stdout(capture_buffer):
            exec(code, namespace)  # <-- SHIELD-011: Critical
        return {"executed": True, "result": captured_output}
    except Exception as e:
        raise Exception(f"Code execution error: {str(e)}")
```

The `code` parameter comes directly from the AI agent's tool call. While the server's docstring says "use with caution," there is no sandboxing, no allowlist, and no validation. An AI agent connected to this server can execute arbitrary Python on the user's machine — including file operations, network requests, or installing packages.

**Impact:** Any AI model connected to blender-mcp can run arbitrary code with the user's full permissions. A prompt injection attack in a Blender file could trigger this without the user ever approving the tool call.

### Finding #2: SSRF in AWS MCP Servers (High)

**Server:** [awslabs/mcp](https://github.com/awslabs/mcp) — bedrock-agentcore
**Rule:** SHIELD-003 — Server-Side Request Forgery
**Severity:** High

The AWS Bedrock AgentCore MCP server fetches URLs without an allowlist:

```python
# doc_fetcher.py, line 58-60
req = urllib.request.Request(url, headers={'User-Agent': doc_config.user_agent})
with urllib.request.urlopen(req, timeout=doc_config.timeout) as r:  # nosec
    return r.read().decode('utf-8', errors='ignore')
```

The `# nosec` comment suggests the developers were aware of the risk and chose to suppress the warning. But when this server runs inside a VPC or on a machine with access to internal services, an AI agent could request `http://169.254.169.254/latest/meta-data/` (AWS instance metadata) or any internal endpoint.

The same pattern appeared in the `amazon-mq` server, where `requests.request()` fetches URLs from tool parameters without validation.

### Finding #3: Unrestricted File Access (High)

**Server:** blender-mcp
**Rule:** SHIELD-004 — Arbitrary File Access
**Severity:** High — 10 instances

The blender-mcp server reads and writes files based on tool parameters without path validation. An AI agent can:

- Read any file the process has access to
- Write to arbitrary paths
- Potentially overwrite the server's own source code (SHIELD-006 — Self-Modification, 4 instances)

This is separate from the `exec()` issue — even without code execution, the file access tools alone create significant risk.

### Finding #4: Supply Chain Issues Are Everywhere (Medium)

**68 of 126 findings (54%)** were supply chain related:

- **SHIELD-009 — Unpinned Dependencies:** 68 findings across 8 servers. Most Node.js MCP servers use `^` semver ranges in `package.json`, allowing automatic minor/patch upgrades. A compromised dependency could be pulled in silently.
- **SHIELD-012 — No Lockfile:** 6 servers lacked a `package-lock.json` or equivalent, meaning builds are not reproducible.
- **SHIELD-010 — Typosquat Detection:** 6 findings for dependency names suspiciously similar to popular packages.

Even Anthropic's official TypeScript servers (filesystem, memory, sequentialthinking) had unpinned dependency findings. This isn't unusual in the Node.js ecosystem, but it matters more for security-sensitive tools that AI agents rely on.

### Finding #5: What We Did NOT Find

Equally interesting is what SHIELD-001 (Command Injection) and SHIELD-002 (Credential Exfiltration) did *not* trigger. Zero findings for both.

This suggests that while MCP server authors are generally careful about not running shell commands with user input, they're less cautious about:
- Fetching arbitrary URLs (SSRF)
- Reading/writing files from user-supplied paths
- Passing code strings to `exec()`/`eval()`

## The Scorecard

| Server | Findings | Worst Severity | Verdict |
|--------|----------|---------------|---------|
| mcp-servers/fetch | 0 | — | Clean |
| mcp-servers/git | 0 | — | Clean |
| aws/kendra-index | 0 | — | Clean |
| aws/keyspaces | 0 | — | Clean |
| aws/neptune | 0 | — | Clean |
| aws/qbusiness | 0 | — | Clean |
| aws/qindex | 0 | — | Clean |
| aws/sns-sqs | 0 | — | Clean |
| aws/mq | 1 | High | SSRF via `requests.request` |
| aws/bedrock-agentcore | 3 | High | SSRF + file access + prompt injection |
| supabase-mcp | 2 | Medium | Supply chain only |
| cloudflare-mcp | 5 | Medium | Supply chain only |
| firecrawl-mcp | 6 | Medium | Supply chain only |
| mcp-servers/memory | 8 | Medium | Supply chain only |
| mcp-servers/sequentialthinking | 11 | Medium | Supply chain only |
| mcp-servers/filesystem | 14 | Medium | Supply chain only |
| mcp-playwright | 14 | High | Runtime install + supply chain |
| mysql-mcp | 21 | Medium | Supply chain only |
| **blender-mcp** | **41** | **Critical** | **exec() + SSRF + file access + self-mod** |

## How to Protect Yourself

### 1. Scan before you install

```bash
# Install AgentShield
brew tap limaronaldo/engram && brew install agentshield
# or: cargo install agent-shield

# Scan any MCP server before using it
agentshield scan /path/to/mcp-server
```

### 2. Add to your CI pipeline

```yaml
# .github/workflows/security.yml
- uses: limaronaldo/agentshield@v0.2.3
  with:
    path: .
    fail-on: high
    format: sarif
    ignore-tests: true
```

This uploads results to GitHub Code Scanning, blocking PRs that introduce high-severity issues.

### 3. Review what tools your agent has access to

MCP servers declare their tools, but the tool *implementations* matter more than the descriptions. A tool called `read_file` might not validate paths. A tool called `execute` might `exec()` anything.

### 4. Use the principle of least privilege

Run MCP servers in containers or with restricted filesystem access. Don't give a Blender automation tool access to your SSH keys.

## About AgentShield

[AgentShield](https://github.com/limaronaldo/agentshield) is a free, open-source, offline-first security scanner for AI agent extensions. It ships as a single ~1 MiB binary with:

- **12 built-in detectors** covering OWASP-style vulnerabilities adapted for AI tools
- **4 framework adapters:** MCP, OpenClaw, CrewAI, LangChain
- **Python + TypeScript parsers** (tree-sitter AST) with cross-file validation tracking
- **4 output formats:** console, JSON, SARIF (GitHub Code Scanning), HTML
- **GitHub Action** with PR inline annotations
- **VS Code extension** with inline diagnostics

Install it:

```bash
# Via Homebrew
brew tap limaronaldo/engram && brew install agentshield

# Via cargo
cargo install agent-shield

# Via Docker
docker run ghcr.io/limaronaldo/agentshield:v0.2.3 scan /project
```

Or use the GitHub Action:

```yaml
- uses: limaronaldo/agentshield@v0.2.3
```

Star the repo if you find it useful: [github.com/limaronaldo/agentshield](https://github.com/limaronaldo/agentshield)

---

*AgentShield is MIT licensed. We have no affiliation with the MCP servers mentioned in this post. All findings were reported by automated static analysis and may include false positives. We encourage server maintainers to review the findings and decide what's appropriate for their threat model.*
