# Changelog

## [Unreleased]

### Added

- Documented current framework support for MCP, OpenClaw, CrewAI, LangChain/LangGraph, GPT Actions, and Cursor Rules.
- Added CLI compatibility notes for the extension's `agentshield scan --format json` integration and expected finding fields.
- Added suppression workflow notes explaining fingerprint-based CLI suppressions and how later scans honor them.

## [0.1.0] - 2026-02-20

### Added

- Initial release
- Inline diagnostics from AgentShield scan results
- Automatic scanning on file save (debounced 2s)
- Automatic scanning on workspace open
- Manual scan via command palette: "AgentShield: Scan Workspace"
- Status bar item showing scan status and finding count
- Configurable binary path, ignore-tests, timeout
- Severity mapping: Critical/High → Error, Medium → Warning, Low/Info → Information
- Clickable rule IDs linking to documentation
- Remediation text in related diagnostic information
