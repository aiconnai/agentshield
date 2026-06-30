# Security Policy

AgentShield is a security-focused project. If you discover a security vulnerability, please report it privately so it can be handled before public disclosure.

## Supported Versions

Security fixes are prioritized for the latest released version and the `main` branch. Older releases may receive fixes when the issue is severe and the patch can be applied safely.

## Reporting a Vulnerability

Please do not disclose security vulnerabilities in public issues, discussions, or pull requests before maintainers have had a chance to investigate.

Preferred reporting path:

1. Use GitHub private vulnerability reporting or a GitHub Security Advisory for this repository, if available.
2. If private reporting is not available, open a minimal public issue asking for a secure contact path, without including exploit details, secrets, or proof-of-concept payloads.

Include, when safe to share privately:

- affected component and version, or commit SHA;
- attack scenario and impact;
- reproduction steps and payload examples;
- scanner command or integration path used;
- files, logs, or commands that demonstrate the issue;
- whether credentials, source code, or runtime data could be exposed.

## Scope

In scope:

- vulnerabilities in AgentShield detection, output, CLI, GitHub Action, runtime guard, or VS Code extension behavior;
- unsafe handling of findings, SARIF, HTML, JSON, logs, or runtime events;
- secret leakage, command injection, path traversal, unsafe archive handling, or sandbox bypasses caused by AgentShield itself.

Out of scope:

- vulnerabilities in third-party projects scanned by AgentShield;
- intentionally vulnerable test fixtures under `tests/fixtures/`;
- placeholder tokens used by redaction tests;
- findings that require malicious local filesystem access outside AgentShield's threat model.

## What to Expect

- We aim to acknowledge reports quickly and will keep you informed of triage and fix status.
- We may request additional details or a proof-of-concept patch.
- Once fixed, we will publish disclosure details in release notes or an advisory when appropriate.
