# AgentShield Examples

These examples show how to position AgentShield in common agent and MCP
workflows. Each fixture is intentionally small and safe so it can be scanned
from a fresh clone without credentials.

| Example | Search target | Scan command |
|---------|---------------|--------------|
| [Claude MCP](claude-mcp/README.md) | Claude Desktop, Claude Code, MCP servers | `agentshield scan examples/claude-mcp/fixture --ignore-tests --explain` |
| [OpenAI Agents SDK](openai-agents-sdk/README.md) | OpenAI Agents SDK tools, MCP, GPT Actions, SARIF | `agentshield scan examples/openai-agents-sdk/fixture --ignore-tests --explain` |
| [FastMCP server](fastmcp-server/README.md) | FastMCP Python MCP servers | `agentshield scan examples/fastmcp-server/fixture --ignore-tests --explain` |
| [Playwright MCP](playwright-mcp/README.md) | Browser automation MCP servers | `agentshield scan examples/playwright-mcp/fixture --ignore-tests --explain` |

For a deliberately vulnerable comparison target, scan one of the fixtures under
`tests/fixtures/mcp_servers/vuln_*`.
