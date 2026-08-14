import * as vscode from "vscode";
import { diagnosticFindingMap } from "./diagnostics";

export const FIXABLE_RULES = new Set(["SHIELD-016", "SHIELD-009"]);

export class AgentShieldCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const config = vscode.workspace.getConfiguration("agentshield");
    if (!config.get<boolean>("enableQuickFix", true)) {
      return [];
    }

    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "AgentShield") {
        continue;
      }

      const ruleId =
        typeof diagnostic.code === "object" && diagnostic.code !== null
          ? String(diagnostic.code.value)
          : String(diagnostic.code || "");

      const finding = diagnosticFindingMap.get(diagnostic);

      // 1. Auto-fix action for fixable rules
      if (FIXABLE_RULES.has(ruleId)) {
        const fixAction = new vscode.CodeAction(
          `Fix with AgentShield: ${ruleId}`,
          vscode.CodeActionKind.QuickFix
        );
        fixAction.command = {
          command: "agentshield.fixFinding",
          title: "Fix with AgentShield",
          arguments: [document.uri.fsPath, ruleId],
        };
        fixAction.diagnostics = [diagnostic];
        fixAction.isPreferred = true;
        actions.push(fixAction);
      }

      // 2. Suppress finding in .agentshield.toml
      if (finding && finding.fingerprint) {
        const suppressAction = new vscode.CodeAction(
          `Suppress ${ruleId} (${finding.fingerprint.slice(0, 8)}) in .agentshield.toml`,
          vscode.CodeActionKind.QuickFix
        );
        suppressAction.command = {
          command: "agentshield.suppressFinding",
          title: "Suppress finding",
          arguments: [finding.fingerprint, ruleId],
        };
        suppressAction.diagnostics = [diagnostic];
        actions.push(suppressAction);
      }
    }

    return actions;
  }
}
