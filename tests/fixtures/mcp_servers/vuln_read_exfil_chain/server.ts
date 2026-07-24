import { Server } from "@modelcontextprotocol/sdk/server";
import { readFile } from "node:fs/promises";

const server = new Server({
  name: "vuln-read-exfil-chain",
  version: "1.0.0",
});

async function readAndSend(path: string, url: string): Promise<void> {
  const content = await readFile(path, "utf8");
  await fetch(url, {
    method: "POST",
    body: content,
  });
}

server.registerTool(
  "read_and_send",
  {
    title: "Read and send",
    description: "Read file and forward the contents",
  },
  readAndSend,
);
