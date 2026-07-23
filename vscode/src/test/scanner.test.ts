import assert from "node:assert/strict";
import test from "node:test";

const Module = require("node:module");
const originalLoad = Module._load;
const vscodeMock = {
  workspace: {
    getConfiguration: () => ({
      get: (key: string, fallback: unknown) =>
        key === "ignoreTests" ? true : fallback,
    }),
  },
  window: { showWarningMessage: () => undefined },
};
Module._load = function (request: string, parent: unknown, isMain: boolean) {
  if (request === "vscode") {
    return vscodeMock;
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { buildScanArgs, parseReport, resolveBinary, runScan } = require("../scanner") as typeof import("../scanner");

const outputLines: string[] = [];
const output = { appendLine: (line: string) => outputLines.push(line) };

test("builds scanner command inputs from configuration", () => {
  assert.equal(resolveBinary("/opt/agentshield"), "/opt/agentshield");
  assert.equal(resolveBinary(""), "agentshield");
  assert.deepEqual(buildScanArgs("/workspace", true), [
    "scan",
    "/workspace",
    "--format",
    "json",
    "--ignore-tests",
  ]);
  assert.deepEqual(buildScanArgs("/workspace", false), [
    "scan",
    "/workspace",
    "--format",
    "json",
  ]);
});

test("parses reports and honors scanner exit codes", async () => {
  const reportJson = JSON.stringify({ findings: [], summary: {} });
  assert.deepEqual(parseReport(reportJson, output as never), {
    findings: [],
    summary: {},
  });
  assert.equal(parseReport("not-json", output as never), null);

  const findingsExecutor = async () => {
    const error = Object.assign(new Error("findings"), {
      code: 1,
      stdout: reportJson,
      stderr: "",
    });
    throw error;
  };
  assert.deepEqual(
    await runScan("/workspace", output as never, findingsExecutor),
    { findings: [], summary: {} }
  );

  const failureExecutor = async () => {
    throw Object.assign(new Error("scan failed"), {
      code: 2,
      stdout: "",
      stderr: "bad configuration",
    });
  };
  assert.equal(
    await runScan("/workspace", output as never, failureExecutor),
    null
  );
  assert.ok(outputLines.some((line) => line.includes("bad configuration")));
});
