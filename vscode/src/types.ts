/**
 * TypeScript interfaces mirroring AgentShield's Rust JSON output.
 *
 * Source: src/rules/finding.rs, src/output/json.rs, src/rules/policy.rs
 *
 * Coordinate system:
 *   - line: 1-based (subtract 1 for VS Code Position)
 *   - column: 0-based (use directly for VS Code Position)
 */

export interface AgentShieldReport {
  findings: Finding[];
  verdict: PolicyVerdict;
}

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  attack_category: AttackCategory;
  message: string;
  location: SourceLocation | null;
  evidence: Evidence[];
  taint_path: unknown | null;
  remediation: string | null;
  cwe_id: string | null;
  /** Stable 64-char SHA-256 hex fingerprint; present in JSON output only. */
  fingerprint: string | null;
}

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
  end_line: number | null;
  end_column: number | null;
}

export interface Evidence {
  description: string;
  location: SourceLocation | null;
  snippet: string | null;
}

export interface PolicyVerdict {
  pass: boolean;
  total_findings: number;
  effective_findings: number;
  highest_severity: Severity | null;
  fail_threshold: string;
}

export type AttackCategory =
  | "command_injection"
  | "code_injection"
  | "credential_exfiltration"
  | "ssrf"
  | "arbitrary_file_access"
  | "supply_chain"
  | "self_modification"
  | "prompt_injection_surface"
  | "excessive_permissions"
  | "data_exfiltration"
  | "capability_mismatch";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
