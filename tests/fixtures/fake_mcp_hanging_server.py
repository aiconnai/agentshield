#!/usr/bin/env python3
import json
import sys
import time

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

time.sleep(30)
