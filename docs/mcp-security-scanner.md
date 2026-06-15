# MCP Security Scanner

AgentShield scans Model Context Protocol servers and related agent extension
repositories before they are installed in Claude, Cursor, OpenAI Agents,
LangGraph, CrewAI, Browser Use, or other MCP-heavy workflows.

## What AgentShield Analyzes

- MCP manifests and tool schemas;
- Python, TypeScript, JavaScript, and shell source;
- command execution, file IO, and network IO surfaces;
- dependency metadata and lockfiles;
- provenance and repository metadata;
- cross-file sanitizer-aware data flow for common safe-input patterns.

## Local Scan

```bash
agentshield scan . --ignore-tests --fail-on high --explain
```

## CI Scan

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: aiconnai/agentshield@main
        with:
          path: '.'
          fail-on: 'high'
          ignore-tests: true
          upload-sarif: true
```

## Common Findings

AgentShield reports command injection, credential exfiltration, SSRF, unsafe
file access, runtime package installation, prompt-injection surfaces, excessive
permissions, dependency hygiene issues, metadata service access,
download-and-execute chains, unsafe deserialization, archive traversal, and
secret leakage.

Runnable MCP examples are in [examples/](../examples/README.md).
