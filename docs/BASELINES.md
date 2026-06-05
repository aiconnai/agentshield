# Baselines

AgentShield baselines let you record the findings that are already known in a repository, then fail future scans only for findings that are new relative to that saved state.

A baseline is useful when onboarding AgentShield to an existing project that already has accepted or triaged findings. It should not replace fixing issues; it is a migration and drift-control mechanism.

## Write a baseline

From the repository root, run:

```bash
agentshield scan . --write-baseline .agentshield-baseline.json
```

This scans the project and writes every current finding to `.agentshield-baseline.json`. Each entry records the finding fingerprint, rule ID, first-seen timestamp, schema version, creation timestamp, and AgentShield version.

Review the scan output before treating the baseline as trusted. The baseline records what exists; it does not mark findings as safe.

## Scan against a baseline

Use `--baseline` to filter out findings already present in the baseline:

```bash
agentshield scan . --baseline .agentshield-baseline.json
```

Findings whose fingerprints match the baseline are removed from the report before the final policy verdict is evaluated. Findings not present in the baseline remain visible and can still fail the scan according to policy.

## Recommended CI pattern

For GitHub Code Scanning or similar SARIF consumers, keep the baseline committed and scan with test-file exclusion enabled:

```bash
agentshield scan . \
  --ignore-tests \
  --baseline .agentshield-baseline.json \
  --format sarif \
  --output agentshield.sarif
```

Recommended workflow:

1. Generate the baseline once during rollout.
2. Review and commit `.agentshield-baseline.json`.
3. Use `--baseline` in CI so only new findings are reported.
4. Periodically refresh or shrink the baseline as findings are fixed.

## When to update a baseline

Update the baseline only after intentional review. Common cases are initial adoption, accepted legacy risk, or after changing detection rules and re-triaging the resulting findings.

Avoid automatically rewriting the baseline in CI. That would hide newly introduced findings instead of surfacing them.
