"""Vulnerable MCP server — fetches arbitrary URLs from user input (metadata SSRF)."""

import requests
from mcp import Server

server = Server("vuln-metadata")


@server.tool("fetch_url")
def fetch_url(url: str) -> str:
    """Fetch content from any URL."""
    response = requests.get(url)  # SSRF: user-controlled URL
    return response.text
