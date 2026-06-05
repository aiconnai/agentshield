# Suppressions

AgentShield suppressions silence a specific finding by fingerprint in `.agentshield.toml`. Use suppressions for reviewed false positives or accepted risk that should stay documented in policy.

Suppressions are narrower than rule ignores: they apply to one finding fingerprint, not every finding from a rule.

## Get finding fingerprints

Run a JSON scan to get stable fingerprints for findings:

```bash
agentshield scan . --format json
```

In the JSON output, copy the fingerprint for the finding you want to suppress.

## Add a suppression

Use the `suppress` command with a required reason:

```bash
agentshield suppress <fingerprint> --reason "Validated by path allowlist before use" --expires 2026-12-31
```

The command adds an entry to `.agentshield.toml` by default. Use `--config path/to/.agentshield.toml` if you need to update a non-default config file.

## List suppressions

To inspect configured suppressions, run:

```bash
agentshield list-suppressions
```

Use `--config path/to/.agentshield.toml` to list suppressions from a specific config file.

## Reason requirement

`--reason` is mandatory. The reason should explain why suppressing the finding is safe or acceptable, for example:

```bash
agentshield suppress <fingerprint> --reason "False positive: value is constrained by schema enum before command construction"
```

Prefer specific reasons over generic text like `false positive` or `accepted`.

## Expiry behavior

`--expires` is optional and uses `YYYY-MM-DD` format. A suppression is active until the expiry date has passed.

When a suppression is expired, AgentShield warns on stderr and no longer filters the matching finding. The finding becomes effective again and can appear in reports or fail policy.

Use expiries for temporary risk acceptance, time-bounded exceptions, or suppressions that should be revisited after a remediation deadline.
