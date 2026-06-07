// A network-category validator (validateUrl) is applied to a value that is then
// used as a FILE PATH. The sanitizer is the wrong category for the sink, so the
// path-traversal finding (SHIELD-004) MUST still fire — a URL allowlist does not
// neutralize a filesystem path.
import fs from "node:fs";

function validateUrl(value: string): string {
  if (!value.startsWith("https://allowed.example.com/")) {
    throw new Error("blocked");
  }
  return value;
}

export function readUserFile(args: { path: string }) {
  const validated = validateUrl(args.path);
  return fs.readFileSync(validated, "utf-8");
}
