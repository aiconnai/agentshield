# AgentShield risk model v1

Status: experimental opt-in output

Model identifier: `agentshield-risk-v1`

This document freezes the E.1 model selected under
[`explainable-risk-score.md`](explainable-risk-score.md). The model is
emitted only when `scan --experimental-risk` is explicitly selected with
console or JSON output. Default output remains unchanged. Findings remain the
security facts; policy verdict and process exit status remain the only
enforcement contract.

## Inputs

The model receives the final effective findings for the invocation and the scan
root used by the existing finding fingerprint. CLI baseline filtering occurs
before assessment. Exact duplicate fingerprints contribute once; conflicting
duplicates retain the highest contribution.

## Contributions

| Severity | Weight |
|---|---:|
| info | 0 |
| low | 1 |
| medium | 4 |
| high | 10 |
| critical | 20 |

| Confidence | Multiplier |
|---|---:|
| low | 1 |
| medium | 2 |
| high | 3 |

For each unique fingerprint:

```text
points = severity_weight × confidence_multiplier
```

Contributions are ordered by fingerprint and contain only the fingerprint,
rule identifier, effective severity, confidence and points. They never copy
source, evidence, snippets or environment data.

## Aggregation

Let `S` be the checked sum of contribution points and `D = S + 30`.
All division is flooring integer division:

```text
score = (100 × S + floor(D / 2)) / D
score = min(score, 99)
```

This rounds the saturating rational value to the nearest integer, with ties
rounded upward. The model never emits `100`.

## Identity and comparison

Every assessment includes:

- `model_version`, fixed to `agentshield-risk-v1`;
- `coverage_id`, a SHA-256 identity over the coverage schema, scanner version,
  enabled Cargo features, and sorted participating rule IDs plus default
  severities.

Assessment comparison is rejected when model or coverage identifiers differ.
Callers must additionally ensure compatible policy, baseline and path-filter
contexts; E.1 does not expose a comparison UI.

## Known limitation and release gate

Fingerprint deduplication removes exact duplicates but does not prove semantic
independence across different rules. Golden tests validate deterministic
mechanics, not breach probability or real-world calibration. E.2 output remains
experimental and must be removed or revised if representative correlated
findings make the ranking misleading.

## Experimental output boundary

`--experimental-risk` supports console and JSON only. It is incompatible with
`--explain`; it does not modify SARIF, HTML or DSSE. At most 50 ordered
contributions are emitted, with an explicit omitted count. The flag never
changes findings, policy, verdict, baseline behavior or process exit status.
