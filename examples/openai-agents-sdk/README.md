# OpenAI Agents SDK Security Scan

Use this workflow for repos that implement tools, MCP connectors, or OpenAPI/GPT
Actions surfaces used by OpenAI Agents SDK applications.

```bash
agentshield scan examples/openai-agents-sdk/fixture --ignore-tests --fail-on high --explain
agentshield scan examples/openai-agents-sdk/fixture --format json --output agentshield.json
agentshield scan examples/openai-agents-sdk/fixture --format sarif --output agentshield.sarif
```

Expected result for this safe fixture:

```text
Gate: PASS
Coverage:
- Adapters: MCP, GPT Actions
```

AgentShield is an offline security scanner for local source, tool schemas,
OpenAPI/GPT Actions specs, dependencies, and lockfile presence. It does not
execute the OpenAI Agents SDK, prove hosted model behavior, or inspect live
traces.

This fixture uses `@openai/agents` and `zod`, matching the current TypeScript
Agents SDK package shape documented by OpenAI, and includes an MCP dependency so
AgentShield can scan the MCP-connected project surface without credentials.

For a longer guide, see
[OpenAI Agents security](../../docs/openai-agents-security.md).
