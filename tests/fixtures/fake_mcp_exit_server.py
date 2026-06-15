#!/usr/bin/env python3
import json
import os
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
        "result": {"served": req.get("method")},
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

sys.exit(int(os.environ.get("AGENTSHIELD_FAKE_MCP_EXIT", "7")))
