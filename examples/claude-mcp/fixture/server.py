from mcp.server.fastmcp import FastMCP

mcp = FastMCP("agentshield-safe-notes")

NOTES: dict[str, str] = {
    "welcome": "Scan MCP servers before adding them to Claude.",
    "scope": "This fixture uses static in-memory data only.",
}


@mcp.tool()
def list_notes() -> list[str]:
    """List safe note names."""
    return sorted(NOTES)


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the fixed in-memory set."""
    return NOTES.get(name, "missing")


if __name__ == "__main__":
    mcp.run()
