from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-inventory")

ITEMS: dict[str, int] = {
    "widget": 7,
    "adapter": 3,
    "cable": 11,
}


@mcp.tool()
def inventory_count(item: str) -> int:
    """Return an inventory count from static data."""
    return ITEMS.get(item, 0)


@mcp.tool()
def inventory_items() -> list[str]:
    """List inventory item names."""
    return sorted(ITEMS)


if __name__ == "__main__":
    mcp.run()
