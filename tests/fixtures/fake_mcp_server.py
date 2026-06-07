#!/usr/bin/env python3
"""A minimal fake MCP server for proxy transport tests.

Reads one JSON-RPC message per line from stdin and, for each, writes a response
line echoing the request id and method so a test can assert which requests
actually reached the server. It never sees blocked tool calls (the proxy answers
those itself), so its output is the ground truth for "what was forwarded".
"""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    resp = {
        "jsonrpc": "2.0",
        "id": req.get("id"),
        "result": {"served": req.get("method"), "name": (req.get("params") or {}).get("name")},
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
