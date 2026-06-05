# AgentShield for VS Code

**Inline security findings for AI agent extensions — MCP, OpenClaw, CrewAI, LangChain/LangGraph, GPT Actions, and Cursor Rules.**

AgentShield scans your AI agent tools for command injection, SSRF, credential exfiltration, and 9 other vulnerability patterns. Findings appear as inline squiggles and in the Problems panel.

## Features

- **Inline diagnostics** — security findings shown directly in the editor with severity-colored underlines
- **Automatic scanning** — rescans on file save (debounced, configurable)
- **Status bar** — shows scan status and finding count
- **12 detectors** — SHIELD-001 through SHIELD-012 covering command injection, SSRF, credential leaks, arbitrary file access, and more
- **Current framework coverage** — MCP servers, OpenClaw skills, CrewAI agents, LangChain/LangGraph tools, GPT Actions, and Cursor Rules

## Requirements

AgentShield CLI must be installed:

```bash
# From crates.io
cargo install agent-shield

# Or download from releases
# https://github.com/limaronaldo/agentshield/releases/latest
```

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `agentshield.binaryPath` | `""` | Path to binary (empty = use PATH) |
| `agentshield.ignoreTests` | `true` | Skip test files during scanning |
| `agentshield.scanOnSave` | `true` | Auto-scan after saving files |
| `agentshield.scanOnOpen` | `true` | Scan workspace when opened |
| `agentshield.timeout` | `30` | Scan timeout in seconds |

## Usage

1. Open a project containing AI agent tools (MCP server, OpenClaw skill, CrewAI agent, LangChain/LangGraph tool, GPT Action, Cursor Rule, etc.)
2. The extension auto-scans on open and shows findings inline
3. Use `Cmd+Shift+P` > **AgentShield: Scan Workspace** to trigger a manual scan
4. Click the status bar item to rescan
5. Click a finding's rule ID to view documentation

## Supported Frameworks

The VS Code extension displays findings produced by the installed AgentShield CLI. Current AgentShield scans cover:

- MCP servers
- OpenClaw skills
- CrewAI agents and tools
- LangChain tools and LangGraph projects
- GPT Actions
- Cursor Rules

## CLI Compatibility

The extension shells out to the local AgentShield CLI instead of reimplementing scanning logic:

```bash
agentshield scan <workspace> --format json
```

When `agentshield.ignoreTests` is enabled, the extension also passes `--ignore-tests`.

The extension expects JSON output containing a top-level `findings` array. Each finding should include rule IDs, severity, location, message, remediation, and fingerprint fields so diagnostics can be displayed consistently and suppression state can remain stable across scans.

## Suppressions

Suppressions are managed by the AgentShield CLI using each finding's stable fingerprint. Once a finding is suppressed through the CLI workflow, later CLI scans honor that suppression, and the VS Code extension reflects the filtered JSON results it receives from `agentshield scan --format json`.

## Severity Mapping

| AgentShield | VS Code | Color |
|-------------|---------|-------|
| Critical / High | Error | Red underline |
| Medium | Warning | Yellow underline |
| Low / Info | Information | Blue underline |

## Detection Rules

| ID | Name | Severity |
|----|------|----------|
| SHIELD-001 | Command Injection | Critical |
| SHIELD-002 | Credential Exfiltration | Critical |
| SHIELD-003 | SSRF | High |
| SHIELD-004 | Arbitrary File Access | High |
| SHIELD-005 | Runtime Package Install | High |
| SHIELD-006 | Self-Modification | High |
| SHIELD-007 | Prompt Injection Surface | Medium |
| SHIELD-008 | Excessive Permissions | Medium |
| SHIELD-009 | Unpinned Dependencies | Medium |
| SHIELD-010 | Typosquat Detection | Medium |
| SHIELD-011 | Dynamic Code Execution | Critical |
| SHIELD-012 | No Lockfile | Low |

## Links

- [AgentShield on GitHub](https://github.com/limaronaldo/agentshield)
- [Detection Rules Documentation](https://github.com/limaronaldo/agentshield/blob/main/docs/RULES.md)
- [GitHub Action](https://github.com/marketplace/actions/agentshield-security-scanner)
