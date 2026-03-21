"""Minimal MCP server fixture for testing dependency findings with locations.

This server is intentionally safe at the code level but declares unpinned
dependencies in requirements.txt. Used to test output format parity for
SHIELD-009 (Unpinned Dependencies) and SHIELD-012 (No Lockfile).
"""

import json


def handle_request(request: str) -> str:
    """Echo the request as JSON."""
    data = json.loads(request)
    return json.dumps({"result": data})
