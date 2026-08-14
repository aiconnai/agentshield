import * as vscode from "vscode";
import { runScan, runFix, runSuppress } from "./scanner";
import { updateDiagnostics } from "./diagnostics";
import { AgentShieldCodeActionProvider } from "./codeActions";

let scanTimer: ReturnType<typeof setTimeout> | undefined;
let isScanning = false;

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("agentshield");
  const output = vscode.window.createOutputChannel("AgentShield");
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.command = "agentshield.scan";
  statusBar.show();

  context.subscriptions.push(diagnostics, output, statusBar);

  // Register Code Action Provider for all common files
  const selector: vscode.DocumentSelector = [
    { scheme: "file", language: "python" },
    { scheme: "file", language: "typescript" },
    { scheme: "file", language: "javascript" },
    { scheme: "file", language: "json" },
    { scheme: "file", language: "yaml" },
    { scheme: "file", language: "toml" },
    { scheme: "file", language: "markdown" },
  ];

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      selector,
      new AgentShieldCodeActionProvider(),
      {
        providedCodeActionKinds: AgentShieldCodeActionProvider.providedCodeActionKinds,
      }
    )
  );

  // Command: manual scan
  context.subscriptions.push(
    vscode.commands.registerCommand("agentshield.scan", () =>
      scan(diagnostics, output, statusBar)
    )
  );

  // Command: fix workspace
  context.subscriptions.push(
    vscode.commands.registerCommand("agentshield.fix", async () => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders || workspaceFolders.length === 0) {
        return;
      }
      const workspacePath = workspaceFolders[0].uri.fsPath;
      vscode.window.showInformationMessage("AgentShield: Running automated remediation...");
      const success = await runFix(workspacePath, output);
      if (success) {
        vscode.window.showInformationMessage("AgentShield: Remediation completed.");
        await scan(diagnostics, output, statusBar);
      } else {
        vscode.window.showErrorMessage("AgentShield: Remediation failed — check Output panel.");
      }
    })
  );

  // Command: fix specific finding (invoked from Code Action)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "agentshield.fixFinding",
      async (filePath: string, ruleId: string) => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        const workspacePath = workspaceFolders && workspaceFolders.length > 0
          ? workspaceFolders[0].uri.fsPath
          : filePath;

        const success = await runFix(workspacePath, output, filePath, ruleId);
        if (success) {
          vscode.window.showInformationMessage(`AgentShield: Applied fix for ${ruleId}.`);
          await scan(diagnostics, output, statusBar);
        } else {
          vscode.window.showErrorMessage(`AgentShield: Failed to apply fix for ${ruleId}.`);
        }
      }
    )
  );

  // Command: suppress finding
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "agentshield.suppressFinding",
      async (arg: vscode.Diagnostic | string, ruleId?: string) => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
          return;
        }
        const workspacePath = workspaceFolders[0].uri.fsPath;

        let fingerprint = "";
        let rule = ruleId || "finding";

        if (typeof arg === "string") {
          fingerprint = arg;
        }

        if (!fingerprint) {
          vscode.window.showErrorMessage("AgentShield: Unable to determine finding fingerprint for suppression.");
          return;
        }

        const reason = await vscode.window.showInputBox({
          prompt: `Reason for suppressing ${rule} (${fingerprint.slice(0, 8)})`,
          placeHolder: "e.g., Reviewed and accepted business risk / test fixture",
          validateInput: (val) => (val && val.trim().length > 0 ? null : "Reason is required"),
        });

        if (!reason) {
          return;
        }

        const success = await runSuppress(workspacePath, output, fingerprint, reason.trim());
        if (success) {
          vscode.window.showInformationMessage(`AgentShield: Suppressed ${rule}.`);
          await scan(diagnostics, output, statusBar);
        } else {
          vscode.window.showErrorMessage(`AgentShield: Failed to suppress ${rule}.`);
        }
      }
    )
  );

  // Auto-scan on save (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      const config = vscode.workspace.getConfiguration("agentshield");
      if (!config.get<boolean>("scanOnSave", true)) {
        return;
      }
      if (scanTimer) {
        clearTimeout(scanTimer);
      }
      scanTimer = setTimeout(() => scan(diagnostics, output, statusBar), 1500);
    })
  );

  // Scan on workspace open
  const config = vscode.workspace.getConfiguration("agentshield");
  if (config.get<boolean>("scanOnOpen", true)) {
    scan(diagnostics, output, statusBar);
  }
}

async function scan(
  diagnostics: vscode.DiagnosticCollection,
  output: vscode.OutputChannel,
  statusBar: vscode.StatusBarItem
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    return;
  }

  if (isScanning) {
    return;
  }
  isScanning = true;

  const workspacePath = workspaceFolders[0].uri.fsPath;

  statusBar.text = "$(sync~spin) AgentShield...";
  statusBar.tooltip = "Scanning for security issues...";

  try {
    const report = await runScan(workspacePath, output);

    if (!report) {
      statusBar.text = "$(error) AgentShield";
      statusBar.tooltip = "Scan failed — check Output panel";
      diagnostics.clear();
      return;
    }

    updateDiagnostics(report, diagnostics, workspacePath);

    const count = report.verdict.effective_findings;
    if (count === 0) {
      statusBar.text = "$(check) AgentShield";
      statusBar.tooltip = "No security findings";
      statusBar.color = undefined;
    } else {
      statusBar.text = `$(warning) AgentShield: ${count} finding${count !== 1 ? "s" : ""}`;
      statusBar.tooltip = `${count} security finding${count !== 1 ? "s" : ""} — click to rescan`;
      statusBar.color = new vscode.ThemeColor(
        report.verdict.pass
          ? "statusBarItem.warningForeground"
          : "statusBarItem.errorForeground"
      );
    }

    output.appendLine(
      `Scan complete: ${count} finding(s), verdict: ${report.verdict.pass ? "PASS" : "FAIL"}`
    );
  } finally {
    isScanning = false;
  }
}

export function deactivate(): void {
  if (scanTimer) {
    clearTimeout(scanTimer);
  }
}
