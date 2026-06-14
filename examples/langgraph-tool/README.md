# LangGraph and LangChain Tool Security Scan

Use this workflow for LangGraph or LangChain projects that expose tools to an
agent loop.

```bash
agentshield scan . --ignore-tests --fail-on high --explain
```

AgentShield scans Python and TypeScript/JavaScript source, dependency metadata,
tool schemas, file operations, network operations, and command execution
surfaces that can affect a LangGraph or LangChain agent.

For OpenAI and agent-tool guidance, see
[OpenAI Agents security](../../docs/openai-agents-security.md).

