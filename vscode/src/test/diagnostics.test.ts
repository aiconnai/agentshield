import assert from "node:assert/strict";
import test from "node:test";

class Position {
  constructor(public line: number, public character: number) {}
}
class Range {
  constructor(
    public startLine: number,
    public startColumn: number,
    public endLine: number,
    public endColumn: number
  ) {}
}
class Diagnostic {
  source?: string;
  code?: unknown;
  relatedInformation?: unknown[];
  constructor(
    public range: Range,
    public message: string,
    public severity: number
  ) {}
}
class Location {
  constructor(public uri: unknown, public range: Position) {}
}
class DiagnosticRelatedInformation {
  constructor(public location: Location, public message: string) {}
}

const vscodeMock = {
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
  Position,
  Range,
  Diagnostic,
  Location,
  DiagnosticRelatedInformation,
  Uri: {
    file: (file: string) => ({ file }),
    parse: (value: string) => ({ value }),
  },
};
const Module = require("node:module");
const originalLoad = Module._load;
Module._load = function (request: string, parent: unknown, isMain: boolean) {
  if (request === "vscode") return vscodeMock;
  return originalLoad.call(this, request, parent, isMain);
};

const { findingToDiagnostic } = require("../diagnostics") as typeof import("../diagnostics");
const finding = {
  rule_id: "AS-001",
  rule_name: "Unsafe tool",
  severity: "high" as const,
  confidence: "high" as const,
  attack_category: "execution",
  message: "Unsafe command",
  location: { file: "/workspace/a.py", line: 2, column: 3, end_line: null, end_column: null },
  evidence: [{
    description: "command reaches shell",
    location: { file: "/workspace/a.py", line: 4, column: 1, end_line: null, end_column: null },
    snippet: null,
  }],
  taint_path: null,
  remediation: "Use an allowlist",
  cwe_id: null,
  fingerprint: null,
};

test("converts a finding into a complete VS Code diagnostic", () => {
  const diagnostic = findingToDiagnostic(finding);
  assert.equal(diagnostic.severity, vscodeMock.DiagnosticSeverity.Error);
  assert.deepEqual(diagnostic.range, new Range(1, 3, 1, 83));
  assert.equal(diagnostic.message, "[AS-001] Unsafe command");
  assert.equal(diagnostic.source, "AgentShield");
  assert.equal((diagnostic.code as { value: string }).value, "AS-001");
  assert.equal(diagnostic.relatedInformation?.length, 2);
});
