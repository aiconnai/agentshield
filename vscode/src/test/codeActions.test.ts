import assert from "node:assert/strict";
import test from "node:test";

const Module = require("node:module");
const originalLoad = Module._load;
const vscodeMock = {
  workspace: {
    getConfiguration: () => ({
      get: (key: string, fallback: unknown) =>
        key === "enableQuickFix" ? true : fallback,
    }),
  },
  window: {
    showInformationMessage: () => undefined,
    showErrorMessage: () => undefined,
    showInputBox: () => undefined,
  },
  CodeActionKind: {
    QuickFix: "quickfix",
  },
  CodeAction: class {
    title: string;
    kind: unknown;
    command?: unknown;
    diagnostics?: unknown[];
    isPreferred?: boolean;
    constructor(title: string, kind: unknown) {
      this.title = title;
      this.kind = kind;
    }
  },
  Range: class {
    start: unknown;
    end: unknown;
    constructor(sl: number, sc: number, el: number, ec: number) {
      this.start = { line: sl, character: sc };
      this.end = { line: el, character: ec };
    }
  },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
  Diagnostic: class {
    range: unknown;
    message: string;
    severity: number;
    source?: string;
    code?: unknown;
    constructor(range: unknown, message: string, severity: number) {
      this.range = range;
      this.message = message;
      this.severity = severity;
    }
  },
  Uri: {
    file: (f: string) => ({ fsPath: f }),
    parse: (u: string) => ({ uri: u }),
  },
};

Module._load = function (request: string, parent: unknown, isMain: boolean) {
  if (request === "vscode") {
    return vscodeMock;
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { AgentShieldCodeActionProvider, FIXABLE_RULES } = require("../codeActions") as typeof import("../codeActions");
const { buildScanArgs } = require("../scanner") as typeof import("../scanner");

test("FIXABLE_RULES contains SHIELD-016 and SHIELD-009", () => {
  assert.ok(FIXABLE_RULES.has("SHIELD-016"));
  assert.ok(FIXABLE_RULES.has("SHIELD-009"));
  assert.ok(!FIXABLE_RULES.has("SHIELD-001"));
});

test("buildScanArgs includes --rules-dir when provided", () => {
  const args = buildScanArgs(
    "/workspace",
    true,
    ".agentshield.toml",
    "baseline.json",
    "high",
    "/custom/rules"
  );
  assert.deepEqual(args, [
    "scan",
    "/workspace",
    "--format",
    "json",
    "--ignore-tests",
    "--config",
    ".agentshield.toml",
    "--baseline",
    "baseline.json",
    "--fail-on",
    "high",
    "--rules-dir",
    "/custom/rules",
  ]);
});

test("AgentShieldCodeActionProvider provides QuickFix for fixable rules", () => {
  const provider = new AgentShieldCodeActionProvider();

  const mockDoc = { uri: { fsPath: "/workspace/server.py" } };
  const mockDiagnostic = new vscodeMock.Diagnostic(
    new vscodeMock.Range(1, 0, 1, 30),
    "Unsafe deserialization detected",
    vscodeMock.DiagnosticSeverity.Error
  );
  mockDiagnostic.source = "AgentShield";
  mockDiagnostic.code = { value: "SHIELD-016" };

  const actions = provider.provideCodeActions(
    mockDoc as never,
    new vscodeMock.Range(1, 0, 1, 30) as never,
    { diagnostics: [mockDiagnostic] } as never,
    {} as never
  );

  assert.equal(actions.length, 1);
  assert.equal(actions[0].title, "Fix with AgentShield: SHIELD-016");
  assert.equal(actions[0].kind, "quickfix");
});
