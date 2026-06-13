# Claude MCP Security

Claude Desktop and Claude Code can use MCP servers to give an assistant access
to files, shell commands, browser automation, APIs, databases, and other local or
remote tools. AgentShield reviews those MCP servers before they are added to a
Claude MCP configuration.

## When to Scan

Scan a Claude MCP server when:

- installing a server from GitHub or an awesome list;
- adding a local MCP server to Claude Desktop;
- wiring Claude Code to a repo-specific MCP server;
- reviewing a pull request that changes tool definitions, schemas, commands,
  file access, network access, or dependencies.

## Local Gate

From the MCP server repository:

```bash
agentshield scan . --ignore-tests --fail-on high --explain
```

For CI and GitHub Code Scanning:

```bash
agentshield scan . --ignore-tests --format sarif --output agentshield.sarif
```

## What to Review First

Prioritize findings involving:

- command execution with user-controlled arguments;
- environment variable or secret-file reads;
- HTTP requests built from tool input;
- filesystem access outside expected project paths;
- runtime package installs or download-and-execute chains;
- broad MCP permissions and unsafe tool schemas.

AgentShield is an offline static scanner. It does not replace sandboxing,
runtime allowlists, or human approval for sensitive tools, but it gives
maintainers and users a repeatable review gate before Claude can call the tools.

See [examples/claude-mcp](../examples/claude-mcp/README.md) for a runnable
fixture and Claude MCP config shape.
