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

## Fingerprints and schema versions

Baselines match findings by fingerprint. Since fingerprint scheme v2, a fingerprint is the SHA-256 of:

1. the rule ID;
2. the file path relative to the scan root, with `/` separators;
3. the normalized evidence text (every evidence description and snippet, with the file path rewritten relative to the scan root and whitespace collapsed; the message is used only when a finding has no evidence);
4. an occurrence index among the findings of the same scan that share items 1 to 3, ordered by line and column.

Line and column numbers are not hashed. Editing code above a finding keeps its fingerprint, while two findings of the same rule with the same evidence in one file still get different fingerprints, so a baseline never hides a new copy of a known finding. Fingerprints do not depend on how the scan path is spelled: `agentshield scan .`, a relative path, and the absolute path of the same tree produce the same values, and renaming or moving the repository root does not change them.

Baseline files carry a `schema_version`:

| `schema_version` | Fingerprints | Written by |
|---:|---|---|
| `1` | legacy scheme v1: rule ID, path stripped of the scan root, first evidence description, attack category | AgentShield 1.0.2 and earlier |
| `2` | scheme v2, described above | current releases |

Schema-v1 baselines are still read and matched with the legacy algorithm, so they keep hiding exactly what they hid before. That includes every finding that collided with a recorded one, and v1 fingerprints still depend on the scan path spelling used when the baseline was written. AgentShield prints a note on stderr when it reads a v1 baseline. To upgrade, review the current findings and rewrite the baseline with `--write-baseline`. A baseline with a `schema_version` newer than the running AgentShield supports is rejected.
