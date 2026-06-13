# Playwright MCP Security Scan

Use this workflow for browser automation MCP servers and tool repositories that
expose browsing, screenshot, extraction, or page-control capabilities to agents.

```bash
agentshield scan examples/playwright-mcp/fixture --ignore-tests --fail-on high --explain
```

Expected result for this safe fixture:

```text
Gate: PASS
Coverage:
- Adapters: MCP
```

Pay close attention to findings that combine agent input with command execution,
file writes, arbitrary URLs, downloaded content, or credential access. Browser
automation should also have runtime allowlists for navigable hosts, download
paths, and credential isolation; static scanning is one gate, not the sandbox.

For browser automation teams, publish SARIF to GitHub Code Scanning so
Playwright MCP server security findings are visible during review.

For MCP-specific guidance, see
[MCP security scanner](../../docs/mcp-security-scanner.md).
