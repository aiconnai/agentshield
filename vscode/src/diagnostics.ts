import * as vscode from "vscode";
import { Finding, Severity, AgentShieldReport } from "./types";
import { resolveFilePath } from "./scanner";

const RULES_URL =
  "https://github.com/aiconnai/agentshield/blob/main/docs/RULES.md";

/**
 * Map AgentShield severity to VS Code DiagnosticSeverity.
 */
function mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
      return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Create a VS Code Range from an AgentShield SourceLocation.
 *
 * AgentShield: line is 1-based, column is 0-based.
 * VS Code:     line is 0-based, column is 0-based.
 */
function makeRange(
  line: number,
  column: number,
  endLine: number | null,
  endColumn: number | null
): vscode.Range {
  const startLine = Math.max(0, line - 1);
  const startCol = Math.max(0, column);
  const eLine = endLine != null ? Math.max(0, endLine - 1) : startLine;
  const eCol = endColumn != null ? endColumn : startCol + 80;
  return new vscode.Range(startLine, startCol, eLine, eCol);
}

/**
 * Convert a single Finding into a VS Code Diagnostic.
 */
function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
  const loc = finding.location!;
  const range = makeRange(loc.line, loc.column, loc.end_line, loc.end_column);

  const diag = new vscode.Diagnostic(
    range,
    `[${finding.rule_id}] ${finding.message}`,
    mapSeverity(finding.severity)
  );

  diag.source = "AgentShield";
  diag.code = {
    value: finding.rule_id,
    target: vscode.Uri.parse(RULES_URL),
  };

  // Attach remediation as related information
  if (finding.remediation) {
    diag.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(
          vscode.Uri.file(loc.file),
          new vscode.Position(Math.max(0, loc.line - 1), loc.column)
        ),
        `Fix: ${finding.remediation}`
      ),
    ];
  }

  // Add evidence as additional related information
  for (const ev of finding.evidence) {
    if (ev.location) {
      diag.relatedInformation = diag.relatedInformation || [];
      diag.relatedInformation.push(
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(
            vscode.Uri.file(ev.location.file),
            new vscode.Position(
              Math.max(0, ev.location.line - 1),
              ev.location.column
            )
          ),
          ev.description
        )
      );
    }
  }

  return diag;
}

/**
 * Update the diagnostic collection with findings from a scan report.
 */
export function updateDiagnostics(
  report: AgentShieldReport,
  collection: vscode.DiagnosticCollection,
  workspacePath: string
): void {
  collection.clear();

  // Group findings by absolute file path
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of report.findings) {
    if (!finding.location) {
      continue;
    }

    const absPath = resolveFilePath(finding.location.file, workspacePath);
    // Update the file path in-place so related info uses absolute path
    finding.location.file = absPath;

    const diag = findingToDiagnostic(finding);
    const existing = byFile.get(absPath) || [];
    existing.push(diag);
    byFile.set(absPath, existing);
  }

  for (const [file, diags] of byFile) {
    collection.set(vscode.Uri.file(file), diags);
  }
}
