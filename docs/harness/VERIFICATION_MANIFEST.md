# Verification Manifest Convention

This file defines how AgentShield harness work records verification evidence.

A verification record should include:

| Field | Meaning |
|---|---|
| `command` | Exact command run |
| `exit_code` | Process exit code |
| `output_summary` | Short factual summary of important output |
| `passed` | `true` or `false` |
| `evidence_path` | File path for saved output, if any |
| `skipped_reason` | Required if the check was not run |
| `issue_numbers` | Related issue, task, or PR identifiers |
| `workspace` | Repository/worktree path where the check ran |
| `importance` | Why this check matters |

Skipped checks are explicit negative evidence. Do not omit them from progress when a completion claim depends on them.

## Harness Verify Convention

Use this shape in progress notes when useful:

```text
harness_verify:
  command: <exact command>
  exit_code: <code or skipped>
  output_summary: <summary>
  passed: true|false
  evidence_path: <path or none>
  skipped_reason: <reason or none>
  issue_numbers: <ids or none>
  workspace: <absolute or repo-relative path>
  importance: <why this mattered>
```
