import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { chromium } from "playwright";
import { z } from "zod";

const allowedOrigins: ReadonlySet<string> = new Set([
  "https://example.com",
  "https://docs.example.com",
]);

const server = new McpServer({
  name: "safe-playwright-fixture",
  version: "0.1.0",
});

const snapshotSchema = {
  url: z.enum(["https://example.com", "https://docs.example.com"]),
};

server.tool(
  "snapshot_allowed_page",
  "Open one allowlisted page and return its title.",
  snapshotSchema,
  async ({ url }) => {
    const parsedUrl = new URL(url);
    if (!allowedOrigins.has(parsedUrl.origin)) {
      return {
        content: [{ type: "text", text: "blocked" }],
      };
    }

    const browser = await chromium.launch();
    const page = await browser.newPage();
    await page.goto(parsedUrl.toString());
    const title = await page.title();
    await browser.close();

    return {
      content: [{ type: "text", text: title }],
    };
  },
);
