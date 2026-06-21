# AGENTS.md

This file provides repository-specific guidance to Codex and other AI coding
agents.

## Authoritative Project Guide

Use `CLAUDE.md` as the canonical AgentShield project guide for:

- project overview and repository structure;
- supported adapters, detectors, CLI commands, and version history;
- architecture principles, key types, and implementation conventions;
- build, test, lint, and CLI examples.

Do not duplicate those sections here. If project facts change, update
`CLAUDE.md`; this file should stay a thin agent-facing pointer plus the
agent-specific notes below.

## Huly Skill

When working with Huly issues, projects, labels, milestones, or documents, use
the repo skill at `skills/huly/SKILL.md`.

The skill prefers the official Huly Platform API with token auth. Required
environment variables are:

```bash
HULY_URL=https://huly.app/workbench/<workspace>/
HULY_WORKSPACE=<workspace-slug>
HULY_PROJECT=<project-identifier>
HULY_API_TOKEN=<token>
```

Compatibility token fallbacks are `HULY_TOKEN` and `HULY_APY_TOKEN`. Do not
print tokens or full environment values. Run a read-only project lookup before
creating or updating Huly data, and make write scripts idempotent.

## RTK Usage for Agent Check Loops

RTK is optional and should only filter command output seen by agents or humans.
RTK filters local command output only. It must not alter AgentShield JSON,
SARIF, HTML, or console output contracts consumed by users, clients, CI, or
GitHub Code Scanning.

Use filtered commands for noisy local checks:

```bash
rtk cargo test
rtk cargo clippy -- -D warnings
rtk cargo run -- scan tests/fixtures/mcp_servers/safe_calculator
```

Use raw commands for complete diagnostics:

```bash
rtk proxy cargo test
rtk proxy cargo run -- scan tests/fixtures/mcp_servers/safe_calculator --format sarif --output target/agentshield/scan.sarif
```

Rules:

- Do not filter final JSON, SARIF, HTML, or console artifacts consumed by users,
  clients, CI, or GitHub Code Scanning.
- Do not rely on filtered output to make security-critical decisions.
- If a test, parser, detector, or policy check fails, rerun the specific
  command raw before making code changes based on the failure.
