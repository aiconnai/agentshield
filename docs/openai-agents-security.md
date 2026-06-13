# OpenAI Agents Security

AgentShield helps teams scan the local tool and extension code used by OpenAI
Agents SDK applications. It is especially useful when an OpenAI agent can call
MCP servers, GPT Actions, OpenAPI tools, browser automation, shell commands,
file operations, or HTTP APIs.

## What to Scan

Scan repositories that contain:

- OpenAI Agents SDK tool functions;
- MCP servers connected to an OpenAI agent;
- OpenAPI or GPT Actions schemas;
- LangGraph, LangChain, or CrewAI tools used alongside OpenAI models;
- browser automation tools such as Browser Use or Playwright MCP;
- CI workflows that publish agent tool packages.

## Local Commands

```bash
agentshield scan . --ignore-tests --fail-on high --explain
agentshield scan . --format json --output agentshield.json
agentshield scan . --format sarif --output agentshield.sarif
```

JSON is useful for automation and baselines. SARIF is useful for GitHub Code
Scanning and pull request annotations.

AgentShield is offline-first: it scans source code, schemas, dependencies, and
policy inputs without sending repository contents to a hosted service.

See [examples/openai-agents-sdk](../examples/openai-agents-sdk/README.md) for a
credential-free OpenAI Agents SDK layout with MCP and GPT Actions surfaces.
