# FastMCP Server Security Scan

FastMCP makes it quick to expose Python functions as MCP tools. Scan the server
before publishing it or adding it to Claude, Cursor, OpenAI Agents, or another
MCP client.

```bash
agentshield scan examples/fastmcp-server/fixture --ignore-tests --fail-on high --explain
```

Expected result for this safe fixture:

```text
Gate: PASS
Coverage:
- Adapters: MCP
```

Review findings for command injection, credential exfiltration, unsafe file
access, SSRF, runtime package installs, and dependency hygiene.

For teams publishing FastMCP servers, use the SARIF output in GitHub Code
Scanning so MCP server security findings show up on pull requests.

For MCP-specific guidance, see
[MCP security scanner](../../docs/mcp-security-scanner.md).
