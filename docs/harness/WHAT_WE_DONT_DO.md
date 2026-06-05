# What We Do Not Do - AgentShield

This file defines negative scope for AgentShield harness and scanner work. It prevents harness work from silently expanding into product, infrastructure, cleanup, or gate weakening without explicit approval.

## Hard No

- Do not change storage schema, MCP tool contracts, hooks, embeddings, sync, or SDK public APIs as part of harness-only work.
- Do not remove code, dependencies, feature flags, docs, or scripts based only on static audit evidence.
- Do not make `docs/harness/bin/*` changes authoritative without an independent post-review or human sign-off.
- Do not weaken `sensors.sh` default behavior. Optional modes may be narrower, but the no-argument default remains the canonical full gate.
- Do not treat generated review, progress, audit, or baseline artifacts as proof that implementation is correct.
- Do not add networked, paid, or credentialed checks to default harness gates.
- Do not bypass `doctor.sh` after changing harness docs, scripts, read order, or review policy.
- Do not use exclusions to make production code look green. Exclusions require a known issue, a reason, and progress registration.
- Do not turn AgentShield into a hosted scanning service by default.
- Do not upload source code, findings, prompts, or scan metadata during local scans.
- Do not add telemetry, background network calls, paid checks, or credentialed checks to default harness gates.
- Do not change detector semantics, adapter contracts, CLI output contracts, GitHub Action behavior, release packaging, or VS Code behavior as part of harness-only work.

## Allowed With Explicit Scope

- Add documentation-only plans under `docs/harness/plans/`.
- Add evidence-only audit reports under `docs/harness/audits/`.
- Add optional sensor modes if the default full gate stays unchanged.
- Add review-canvas artifacts for complex changes.
- Propose product, scanner, release, dependency, or cleanup follow-ups as separate tasks, issues, or ADRs.

## Review Rule

Reviewers must flag hidden scope creep against this file as `[HIGH]` or `[BLOCKER]` depending on impact.
