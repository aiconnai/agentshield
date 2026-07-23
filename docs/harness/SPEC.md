# AgentShield Harness Spec

| Field | Value |
|---|---|
| Project | `agentshield` / Cargo package `agent-shield` |
| Active program | Scanner hardening and release-surface parity |
| Started | 2026-06-05 |
| Owner | Ronaldo + agents |
| Current version in `Cargo.toml` | `0.8.0` |
| Current adapters | MCP, OpenClaw, Hermes Agent, CrewAI, LangChain, GPT Actions, Cursor Rules |
| Current detectors | 19 built-in rules, `SHIELD-001` through `SHIELD-019` |

## Goal

Keep AgentShield reliable as an offline-first scanner for AI agent extensions while preserving CLI behavior, detector explainability, SARIF compatibility, trust workflows, release packaging, the GitHub Action, and the VS Code extension.

The harness adds local operational discipline:

- `bootstrap.sh` orients a session;
- `doctor.sh` validates harness consistency;
- `sensors.sh` runs deterministic gates;
- `review-gate.sh` handles independent review artifacts;
- `baseline.sh` and `quarterly-audit.sh` collect evidence without mutating product behavior.

## Active Work Streams

### Scanner Correctness

- Keep adapters producing IR and detectors consuming only IR.
- Keep all matching adapters active for mixed-framework repositories.
- Preserve taint semantics around `ArgumentSource`, sanitizers, cross-file analysis, sources, sinks, and policy filtering.
- Use fixtures for concrete true-positive and safe-baseline behavior.

### Output And Trust Workflows

- Keep console, JSON, SARIF, and HTML outputs stable enough for downstream tooling.
- Preserve SARIF 2.1.0 compatibility for GitHub Code Scanning.
- Keep baselines, suppressions, DSSE certification, egress policy generation, and runtime wrapping documented and testable.

### Distribution Surface

- Keep the composite GitHub Action aligned with CLI inputs and exit-code behavior.
- Keep release workflows building with `--features full` and smoke-checking `wrap` on native targets.
- Keep the VS Code extension compatible with the current JSON scan output and CLI flags.

### Documentation Parity

- Documentation must not advertise commands, adapters, rules, outputs, features, or release behavior that the current code does not support.
- Old version-history notes may remain as history, but current quickstart and release docs must match the current CLI.

## Out Of Scope

- Cloud scanning, hosted uploads, or background telemetry.
- Automatic remediation of findings.
- Rewriting the scanner around full program dataflow without a measured false-positive/false-negative case.
- Making local harness scripts part of production CI.
- Changing `AGENTS.md` as part of harness operation.

## Review Discipline

Complex changes must carry review evidence before final review. A change is complex when any of these are true:

- more than roughly 200 lines changed, excluding generated review artifacts;
- multiple scanner surfaces touched, such as adapter plus detector plus output;
- CLI, SARIF, JSON, GitHub Action, release, VS Code extension, or harness behavior changed;
- new dependency, parser, runtime layer, cache, network behavior, or signing behavior introduced;
- new architectural pattern or reusable detector pipeline introduced.

Required evidence:

- approaches considered and why the chosen path won;
- hot-path time/space complexity for new or changed parsing, analysis, detector, or rendering logic;
- at least two meaningful edge cases covered by tests or manual trace;
- breakage-risk table covering CLI, policy, SARIF, release/action, VS Code, harness, and rollback.

## Entrypoints

Read in this order:

1. `docs/harness/SPEC.md`
2. `docs/harness/INVARIANTS.md`
3. `docs/harness/WHAT_WE_DONT_DO.md`
4. `docs/harness/GATES.md`
5. `docs/harness/CODE_REVIEW_POLICY.md`
6. `docs/harness/VERIFICATION_MANIFEST.md`
7. `docs/harness/progress.md`
8. Active issue or task context
