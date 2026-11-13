#!/usr/bin/env python3
"""A minimal fake MCP server for proxy transport tests.

Reads one JSON-RPC message per line from stdin and, for each, writes a response
line echoing the request id and method so a test can assert which requests
actually reached the server. It never sees blocked tool calls (the proxy answers
those itself), so its output is the ground truth for "what was forwarded".
"""
import json
import sys

while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue

    def serve(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "served": message.get("method"),
                "name": (message.get("params") or {}).get("name"),
            },
        }

    if isinstance(req, list):
        # JSON-RPC batch: one response per member that has an id.
        resp = [serve(m) for m in req if isinstance(m, dict) and "id" in m]
        if not resp:
            continue
    else:
        resp = serve(req)
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
