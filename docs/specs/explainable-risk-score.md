# ADR: Explainable and versioned risk assessment

- **Status:** Proposed
- **Date:** 2026-07-24
- **Decision owners:** AgentShield maintainers
- **Implementation gate:** no risk-score code or output before this ADR is
  reviewed and accepted

## 1. Context

AgentShield currently reports discrete findings with severity, confidence,
evidence and stable fingerprints. Policy applies ignored rules, severity
overrides, suppressions and baseline filtering before producing a severity-based
`PolicyVerdict`.

The roadmap calls for an explainable, versioned risk score. A headline number
can help prioritize remediation, but it also creates false precision and a
second apparent decision surface. A deterministic formula is reproducible; it
is not automatically calibrated, comparable or meaningful.

The decision must preserve these established contracts:

- offline and deterministic analysis, with no mandatory LLM;
- findings and their evidence remain the security facts;
- `fail_on`, `PolicyVerdict` and the process exit status remain the enforcement
  contract;
- fingerprints, baselines and suppressions keep their existing identity and
  matching semantics;
- public Rust APIs and legacy console, JSON, SARIF, HTML and DSSE shapes do not
  change implicitly;
- feature-dependent detector coverage is represented honestly rather than
  hidden behind one number.

## 2. Decision

Adopt an additive, deterministic integer risk assessment in the range `0..100`
as an informational prioritization index.

Delivery is split into independent gates:

1. **E.0 — architecture:** this ADR fixes inputs, invariants, versioning,
   compatibility and release gates. It does not make numerical weights
   normative.
2. **E.1 — internal golden model:** implement a standalone assessment type and
   pure calculation, then validate the exact formula against golden vectors,
   correlation cases and compatibility fixtures. Default outputs remain
   byte-for-byte unchanged.
3. **E.2 — opt-in experimental exposure:** expose the validated assessment only
   through explicit opt-in surfaces. This requires a separate review and is
   blocked if E.1 does not justify aggregation, comparison and calibration
   behavior.

The assessment never changes:

- finding severity or confidence;
- detector execution or rule registration;
- `fail_on`, verdict or exit status;
- fingerprints or baseline membership;
- suppression matching;
- default output unless the E.2 opt-in is selected;
- the DSSE v1 predicate.

## 3. Meaning and non-meaning

The score summarizes the effective findings in one scan under one model and one
coverage context. It is not:

- a probability of exploitation or breach;
- a percentage secure;
- CVSS;
- an attestation verdict;
- a replacement for severity, confidence, evidence or coverage;
- a policy threshold in E.1 or E.2;
- comparable across different model or coverage identifiers.

Zero means only that no effective finding contributed points under the selected
scan, policy and baseline context. It does not prove safety or complete
coverage.

The initial model reserves `100` for a future explicitly defined semantic
condition. E.1 must not emit it.

## 4. Input boundary

The model consumes the same final finding set shown to the user. In the library
pipeline this is the result of policy application; in CLI invocations that
select a baseline it is the remaining set after the CLI baseline filter and
verdict re-evaluation:

1. detectors emit raw findings;
2. ignored rules are removed;
3. active suppressions are applied;
4. severity overrides are applied;
5. baseline filtering requested by the invocation is applied.

This makes the score policy-relative and baseline-relative. Reports must not
compare scores unless their policy, baseline mode, model and coverage context
are compatible.

Suppressed, ignored and baseline-filtered findings contribute zero to the
effective assessment. E.1 does not add a second raw score. Future demand for raw
and effective scores requires a separate decision because two headline numbers
would increase ambiguity and signed-output surface.

## 5. Standalone model

E.1 introduces a dedicated risk module with a standalone assessment type. It
does not add a required field to `Finding`, `ScanReport`, `ScanOptions` or
`PolicyVerdict`.

This boundary avoids breaking downstream Rust code that uses struct literals or
exhaustive destructuring. Existing `scan()` and `render_report()` calls retain
their behavior.

The calculation accepts:

- effective findings;
- the scan root needed to derive existing stable fingerprints;
- an explicit coverage descriptor derived from scanner/rule/feature coverage.

It returns:

```text
RiskAssessment
  model_version
  coverage_id
  score
  raw_points
  contributions[]
  summary
```

Every contribution contains only allowlisted, non-secret fields required to
reconstruct the calculation:

```text
fingerprint
rule_id
effective_severity
confidence
points
```

Contributions never include raw source, snippets, command arguments, environment
values or secret-bearing evidence.

## 6. Identity, deduplication and correlation

E.1 deduplicates exact findings by existing stable fingerprint. When duplicate
fingerprints occur, one deterministic contribution remains. Conflicting
duplicates retain the highest contribution so input order cannot lower the
score.

Fingerprint deduplication does not prove that different rules or fingerprints
represent independent risks. E.1 must include correlated-finding fixtures and
document known inflation. It must not infer semantic clusters from unstable
message text, line numbers or arbitrary proximity.

If the golden evaluation shows that fingerprint deduplication materially
overcounts common correlated findings, E.2 is blocked. A stable correlation
taxonomy or contribution-group contract then requires an ADR amendment or a new
model version before output exposure.

## 7. Versioning and coverage

Every assessment declares two separate identities:

- `model_version`: immutable identity for weights, confidence mapping,
  arithmetic, aggregation, deduplication and interpretation;
- `coverage_id`: immutable digest or identifier for scanner version, enabled
  analysis features and participating rule catalog.

Changing any of these requires a new `model_version`:

- severity weights;
- confidence multipliers;
- aggregation or saturation formula;
- rounding;
- caps or bounds;
- deduplication or correlation rules;
- the meaning of the output.

Adding, removing or changing participating detector coverage changes
`coverage_id`. It does not by itself require a new model version if the formula
and interpretation are unchanged.

Scores are directly comparable only when all of these match:

- `model_version`;
- `coverage_id`;
- relevant policy and override configuration;
- baseline mode and baseline identity when used;
- scan path/filter configuration.

E.2 output must not label mismatched assessments as an increase or decrease.

## 8. Mathematical invariants

The model uses integer arithmetic only and is:

- deterministic across supported platforms;
- independent of finding input order;
- bounded;
- overflow-safe;
- monotone: adding an independent positive contribution cannot reduce the
  score;
- saturating: additional points have diminishing effect near the upper bound;
- exactly reconcilable from its ordered contributions and declared formula.

E.1 must use checked or proven-bounded arithmetic. Silent wrapping is forbidden.

### 8.1 Candidate model for E.1 evaluation

The initial candidate, not yet normative, is:

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

For each deduplicated finding:

```text
contribution = severity_weight × confidence_multiplier
```

Let `S` be the checked sum of contributions and `D = S + 30`. Using
flooring integer division, round the rational value `100 × S / D` to the
nearest integer:

```text
score = (100 × S + floor(D / 2)) / D
```

The result is clamped to `0..99`; `100` remains reserved. Ties round upward.

E.1 may change this candidate before merge only when golden evidence and review
justify the change. The merged E.1 implementation and model documentation then
freeze the exact formula under a named version.

## 9. Golden evaluation

E.1 includes a versioned, source-safe golden corpus with:

- every severity-confidence pair;
- no findings and informational-only findings;
- repeated identical fingerprints;
- same fingerprint with conflicting effective contribution;
- mixed independent findings;
- ignored, suppressed and baseline-filtered findings;
- severity overrides;
- input permutations;
- saturation and arithmetic boundary cases;
- representative safe and vulnerable existing fixtures;
- correlated findings from one underlying behavior;
- default and no-default feature configurations.

The evaluation proves:

- exact golden score and contribution vectors;
- byte-stable assessment serialization;
- permutation invariance;
- duplicate invariance;
- monotonicity;
- bounds and overflow safety;
- contribution reconciliation;
- cross-platform equality;
- stable comparison rejection for mismatched model or coverage identities;
- zero changes to legacy outputs and enforcement.

The golden corpus is not claimed to calibrate breach probability. Its purpose is
to validate deterministic prioritization behavior and expose pathological
aggregation before E.2.

## 10. Compatibility boundaries

### 10.1 Public Rust API

E.1 keeps existing public structs and functions unchanged. The scorer and its
types remain crate-private during the internal validation gate.

An additive public accessor or public assessment type requires explicit
compatibility review in E.2 or a later API-specific ADR. Visibility is not
widened merely to let the CLI compile.

### 10.2 Console, JSON and HTML

E.1 makes no changes.

E.2 may add an explicit scan flag for experimental risk output. Default output
without that flag remains byte-for-byte compatible. Wherever rendered:

- PASS/FAIL remains primary;
- the label says `informational`;
- `model_version` and `coverage_id` are visible;
- the score is never rendered as a percentage;
- contributions are inspectable;
- no green state implies safety.

### 10.3 SARIF

E.1 makes no changes.

If approved in E.2, SARIF risk metadata is limited to namespaced run-level
properties. It does not alter result level, rule identity, fingerprints,
locations, suppressions or GitHub Code Scanning behavior.

### 10.4 Certification and DSSE

The DSSE predicate v1 remains unchanged in E.1 and E.2.

Risk data in an attestation changes signed semantics and requires a new
predicate version plus a separate compatibility and trust review. An
informational CLI score is not automatically an attested claim.

## 11. Policy separation

No E.1 or E.2 configuration key, CLI flag or code path maps a score to:

- pass, warn or fail;
- severity;
- `fail_on`;
- exit status;
- suppression;
- baseline filtering.

A future score threshold is a new policy dialect and requires a separate ADR
with migration, precedence and contradiction semantics. It must not be smuggled
into the experimental output increment.

## 12. Alternatives considered

### 12.1 CVSS-like environmental model now

Rejected for this increment. AgentShield does not yet have uniform, proven
cross-framework inputs for exposure, reachability, privileges, asset
criticality, compensating controls or exploit preconditions. Inferring them
would create stronger false precision and false attribution.

Reconsider only after explicit environmental inputs and an adjudicated corpus
show that the richer model improves prioritization reproducibly.

### 12.2 Defer all numeric scoring

Preserved as the release fallback. If E.1 cannot define defensible aggregation,
correlation, comparison and golden behavior, structured internal contributions
may remain while E.2 is deferred.

This is not failure: withholding a misleading number is preferable to shipping
a deterministic but arbitrary security grade.

### 12.3 Put the score directly in `PolicyVerdict`

Rejected. It would conflate prioritization and enforcement, create pressure for
score thresholds, and change a public serialized contract.

### 12.4 Add the score directly to `ScanReport`

Rejected for E.1. A required public field is source-breaking for downstream
struct literals and exhaustive destructuring even if serialization is not
derived.

### 12.5 Maximum severity mapped to a number

Rejected. It adds numerical appearance without adding information beyond the
existing severity and does not represent breadth.

## 13. Consequences

Positive:

- deterministic prioritization from existing facts;
- complete point-level explanation;
- no mandatory service, network or LLM;
- explicit model and coverage comparison boundaries;
- reversible internal-first delivery;
- existing enforcement and compatibility remain stable.

Negative:

- any headline number invites false precision;
- detector and coverage changes can move the score;
- fingerprint deduplication may not remove correlated findings;
- policy-relative inputs complicate comparisons;
- golden fixtures validate behavior but do not establish real-world
  exploitability.

## 14. Reversal and blocking triggers

Defer E.2 or reverse to no numeric output if:

- users treat the score as probability, percentage secure or a policy verdict
  despite explicit labeling;
- common correlated findings materially inflate ranking;
- harmless detector duplication or input ordering changes the score;
- a representative golden corpus produces unstable or misleading ordering;
- comparison boundaries cannot be represented honestly;
- legacy output, API, fingerprint, baseline, suppression, policy or DSSE
  compatibility cannot be preserved;
- output would require hidden weights, secret-bearing contributions or runtime
  inference.

Replace the simple model with a richer version only when:

- deterministic exposure and capability inputs exist across supported
  frameworks;
- an adjudicated corpus shows improved ordering;
- inter-rater agreement and sensitivity testing justify the additional factors;
- migration and historical comparison rules are explicit.

## 15. Implementation sequence

### E.1 — internal golden model

1. add crate-private risk assessment types and pure calculation;
2. freeze the exact model formula and identifier in code and model docs;
3. derive deterministic coverage identity from scanner/rule/feature coverage;
4. deduplicate exact fingerprints and sort contributions deterministically;
5. add golden, property and compatibility tests;
6. keep every current renderer, public API, policy result and signed predicate
   unchanged;
7. review aggregation and correlation evidence before merge.

### E.2 — opt-in experimental output

1. add an explicit experimental CLI opt-in;
2. compute once and project the same assessment into approved surfaces;
3. keep default output byte-for-byte unchanged;
4. label the score informational and display model/coverage identities;
5. expose bounded, secret-safe contributions;
6. add namespaced SARIF run properties only if separately justified;
7. keep DSSE v1 and policy behavior unchanged;
8. remove or defer the output if the E.1 release gate is not met.

## 16. Acceptance criteria

### E.0

- [ ] the score is explicitly informational and non-enforcing;
- [ ] E.1 and E.2 are separate review gates;
- [ ] exact weights remain an E.1 evidence decision;
- [ ] model and coverage identities are separate and immutable;
- [ ] comparison requirements include policy, baseline and scan configuration;
- [ ] public Rust and legacy output compatibility are explicit;
- [ ] DSSE v1 remains unchanged;
- [ ] deferral remains the required fallback if evaluation fails.

### E.1

- [ ] standalone crate-private assessment; no required public struct fields;
- [ ] exact named model and integer formula documented;
- [ ] effective post-policy/post-baseline inputs only;
- [ ] stable fingerprint deduplication and deterministic ordering;
- [ ] complete contribution reconciliation;
- [ ] deterministic, bounded, monotone and overflow-safe arithmetic;
- [ ] score `100` is never emitted;
- [ ] explicit `model_version` and `coverage_id`;
- [ ] golden vectors cover every factor and boundary;
- [ ] correlation cases are evaluated and documented;
- [ ] mismatched comparison contexts are rejected;
- [ ] default and no-default feature behavior is covered;
- [ ] legacy APIs, outputs, enforcement, identities and DSSE remain unchanged.

### E.2

- [ ] separate review approves E.1 evaluation evidence;
- [ ] output is explicit opt-in and experimental;
- [ ] default renderers and serialization remain byte-for-byte unchanged;
- [ ] PASS/FAIL remains visually and semantically primary;
- [ ] score is not a percentage, probability, grade or threshold;
- [ ] model and coverage identifiers accompany every score;
- [ ] contributions are inspectable, bounded and secret-safe;
- [ ] SARIF changes, if any, are namespaced run properties only;
- [ ] DSSE v1 is unchanged;
- [ ] no score-to-policy or score-to-exit path exists;
- [ ] unsupported cross-context comparisons are not presented.

## 17. Council review

The full Level 1 council included independent First-Principles, Skeptic,
Strategist, Security/Reliability, Executor, Migration, UX and Data/Eval roles,
cross-review, Chair synthesis and a Codex cross-model opinion.

The majority selected the additive internal-first architecture. The strongest
dissent recommended deferring the numeric score until calibration,
correlation, aggregation and comparison semantics are proven. This dissent is
preserved as the E.2 release gate rather than dismissed.

Council confidence is high for the architecture and medium for any initial
numeric calibration.
