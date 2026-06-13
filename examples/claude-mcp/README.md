# Claude MCP Security Scan

Use this workflow before adding a third-party MCP server to Claude Desktop or
Claude Code.

```bash
agentshield scan examples/claude-mcp/fixture --ignore-tests --fail-on high --explain
```

Expected result for this safe fixture:

```text
Gate: PASS
Coverage:
- Adapters: MCP
```

The fixture includes `claude_desktop_config.json` to show the Claude MCP config
shape. Before installing a real server, scan the server repository first, then
copy the command and args into Claude's local config.

AgentShield checks:

- shell and process calls reachable from MCP tools;
- local file reads and writes;
- network calls and SSRF-sensitive URL handling;
- credential reads from environment variables or local secret files;
- dependency and lockfile hygiene.

For a longer guide, see [Claude MCP security](../../docs/claude-mcp-security.md).
