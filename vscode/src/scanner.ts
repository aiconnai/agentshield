import { execFile } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as vscode from "vscode";
import { AgentShieldReport } from "./types";

const execFileAsync = promisify(execFile);

type ScanExecutor = (
  binary: string,
  args: string[],
  options: { timeout: number; maxBuffer: number; cwd: string }
) => Promise<{ stdout: string; stderr: string }>;

/**
 * Locate the agentshield binary.
 *
 * Priority: user setting > PATH lookup.
 */
export function findBinary(): string {
  const config = vscode.workspace.getConfiguration("agentshield");
  const configured = config.get<string>("binaryPath", "");
  return resolveBinary(configured);
}

export function resolveBinary(configured: string): string {
  return configured || "agentshield";
}

export function buildScanArgs(workspacePath: string, ignoreTests: boolean): string[] {
  const args = ["scan", workspacePath, "--format", "json"];
  if (ignoreTests) {
    args.push("--ignore-tests");
  }
  return args;
}

/**
 * Run `agentshield scan <workspacePath> --format json` and parse the output.
 *
 * Exit code 1 means findings above threshold — JSON is still valid on stdout.
 * Exit code 2 means scan error — no JSON output.
 */
export async function runScan(
  workspacePath: string,
  output: vscode.OutputChannel,
  execute: ScanExecutor = execFileAsync
): Promise<AgentShieldReport | null> {
  const binary = findBinary();
  const config = vscode.workspace.getConfiguration("agentshield");
  const ignoreTests = config.get<boolean>("ignoreTests", true);
  const timeout = config.get<number>("timeout", 30) * 1000;

  const args = buildScanArgs(workspacePath, ignoreTests);

  output.appendLine(`> ${binary} ${args.join(" ")}`);

  try {
    const { stdout } = await execute(binary, args, {
      timeout,
      maxBuffer: 10 * 1024 * 1024,
      cwd: workspacePath,
    });
    return parseReport(stdout, output);
  } catch (err: unknown) {
    // Exit code 1 = findings found, stdout still has valid JSON
    if (isExecError(err) && err.code === 1 && err.stdout) {
      return parseReport(err.stdout, output);
    }
    // Exit code 2 = scan error
    if (isExecError(err) && err.code === 2) {
      output.appendLine(`Scan error: ${err.stderr || err.message}`);
      return null;
    }
    // Binary not found
    if (isExecError(err) && err.code === "ENOENT") {
      output.appendLine(
        `Binary not found: "${binary}". Install via: cargo install agent-shield`
      );
      vscode.window.showWarningMessage(
        `AgentShield binary not found. Install via "cargo install agent-shield" or set agentshield.binaryPath.`
      );
      return null;
    }
    // Timeout or other error
    output.appendLine(`Error: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}

export function parseReport(
  stdout: string,
  output: vscode.OutputChannel
): AgentShieldReport | null {
  try {
    return JSON.parse(stdout) as AgentShieldReport;
  } catch {
    output.appendLine(`Failed to parse JSON output: ${stdout.slice(0, 200)}`);
    return null;
  }
}

interface ExecError extends Error {
  code: number | string;
  stdout: string;
  stderr: string;
}

function isExecError(err: unknown): err is ExecError {
  return err instanceof Error && "code" in err;
}

/**
 * Resolve a finding's file path to an absolute path within the workspace.
 */
export function resolveFilePath(
  file: string,
  workspacePath: string
): string {
  if (path.isAbsolute(file)) {
    return file;
  }
  return path.join(workspacePath, file);
}
