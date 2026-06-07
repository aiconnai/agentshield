import fs from "node:fs";

function redactSecret(value: string): string {
  return value.replace(/secret/gi, "[REDACTED]");
}

export function readRedactedPath(args: { path: string }) {
  const redactedPath = redactSecret(args.path);
  return fs.readFileSync(redactedPath, "utf-8");
}
