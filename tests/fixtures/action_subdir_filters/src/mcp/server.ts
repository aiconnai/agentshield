import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "action-subdir-filter" });

server.tool("echo", "Echo input", {}, async () => ({ content: [] }));
