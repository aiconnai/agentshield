# Gates - PASS/FAIL Thresholds

## Canonical Gate

`bash docs/harness/bin/sensors.sh` is the canonical full local gate. It is equivalent to `bash docs/harness/bin/sensors.sh full`.

Optional sensor lanes are developer aids. They do not replace the no-argument `sensors.sh` full gate for merge, release, or completion claims.

## Sensor Modes

| Mode | Command | Threshold | Use |
|---|---|---|---|
| `full` | `bash docs/harness/bin/sensors.sh` or `bash docs/harness/bin/sensors.sh full` | doctor + fmt + clippy + tests + fixture smoke + SARIF + action/release static checks pass | Completion / PR / broad scanner change |
| `quick` | `bash docs/harness/bin/sensors.sh quick` | doctor + harness shell syntax + fmt + all-features check pass | Local iteration |
| `docs` | `bash docs/harness/bin/sensors.sh docs` | harness policy references and current CLI/action/release doc references are present | Documentation parity work |
| `mcp` | `bash docs/harness/bin/sensors.sh mcp` | MCP validation report references the Anthropic reference servers and records current validation evidence | MCP reference parity work |
| `fixtures` | `bash docs/harness/bin/sensors.sh fixtures` | supported fixture scans return success or findings, not scan errors | Adapter/detector work |
| `sarif` | `bash docs/harness/bin/sensors.sh sarif` | SARIF file is emitted and has expected top-level shape | Output/GitHub Code Scanning work |
| `action` | `bash docs/harness/bin/sensors.sh action` | composite action keeps expected inputs, SARIF upload, and exit-code behavior | GitHub Action changes |
| `release` | `bash docs/harness/bin/sensors.sh release` | release workflow keeps 5 targets, `--features full`, and `wrap` smoke checks | Release workflow changes |
| `vscode` | `bash docs/harness/bin/sensors.sh vscode` | `npm ci` and `npm run compile` pass in `vscode/` | VS Code extension changes |
| `baseline` | `bash docs/harness/bin/sensors.sh baseline` | baseline snapshot writes `.baseline-last` and doctor passes | Planning and complexity snapshots |
| `audit` | `bash docs/harness/bin/sensors.sh audit` | evidence-only quarterly audit report is generated and doctor passes | Periodic cleanup review |

## Rust Gates

| Gate | Command |
|---|---|
| Format | `cargo fmt --check` |
| Quick check | `cargo check --all-features` |
| Clippy | `cargo clippy --all-features -- -D warnings` |
| Tests | `cargo test --all-features` |
| Fixture smoke | `bash docs/harness/bin/sensors.sh fixtures` |
| SARIF smoke | `bash docs/harness/bin/sensors.sh sarif` |

## Fixture Smoke Gate

The fixture smoke gate checks that representative supported targets can be scanned without scanner errors:

- MCP safe fixture;
- MCP vulnerable command-injection fixture, expected to fail policy with exit code `1`;
- Hermes Agent fixture;
- CrewAI fixture;
- LangChain fixture;
- GPT Actions fixture;
- Cursor Rules fixture.

A fixture scan may exit `0` or `1` depending on findings. Exit code `2` or any other scanner error fails the gate.

## SARIF Gate

The SARIF gate must prove:

- the CLI writes a SARIF file;
- `version` is `2.1.0`;
- `runs[0].tool.driver` exists;
- `runs[0].results` is an array;
- findings do not prevent SARIF emission before the CLI exits with policy failure.

## Negative Scope Gate

All implementation and review must compare scope against `docs/harness/WHAT_WE_DONT_DO.md`. Hidden scope creep, gate weakening, networked default checks, or product behavior changes bundled into harness-only work must be flagged as `[HIGH]` or `[BLOCKER]`.

## Review Canvas Requirement

Complex changes require a canvas under `docs/harness/canvas/YYYY-MM-DD-<task-id>.md` before post-review. The review gate should flag missing canvas evidence as `[HIGH]` or `[BLOCKER]` when a trigger is present.

A change is complex when any of these are true:

- more than roughly 200 lines changed, excluding generated review artifacts;
- multiple scanner surfaces touched, such as adapter plus detector plus output;
- CLI, SARIF, JSON, GitHub Action, release, VS Code extension, or harness behavior changed;
- a new dependency, parser, runtime layer, cache, network behavior, or signing behavior is introduced;
- a new algorithm, scan pipeline phase, or reusable architectural pattern is introduced.

Required evidence for complex changes:

- approaches considered and rejection reasons;
- time/space complexity for hot paths;
- at least two edge cases tested or manually traced;
- breakage risks with likelihood, mitigation, and rollback;
- dependency and scope-creep justification when applicable.

## Baseline Snapshot

`baseline.sh` records cheap static repository facts in `docs/harness/.baseline-last`. It is evidence for drift review, not a substitute for `sensors.sh` or CI.

## Quarterly Audit Evidence

`quarterly-audit.sh` is evidence-only. It writes reports under `docs/harness/audits/` and updates `docs/harness/.quarterly-audit-last`.

It is not a pass/fail gate and must not delete, archive, or rewrite files. Humans decide whether each item is kept, archived, deleted, or promoted into a future gate.

## Harness Isolation Gate

`doctor.sh` and `sensors.sh quick` verify that:

- all harness scripts parse under `bash -n`;
- GitHub workflows do not execute `docs/harness/bin/*`;
- mandatory policy files and read-order references are present;
- review gate prompts include negative-scope and Review Canvas checks.

Changes to `docs/harness/bin/*` require independent post-review evidence. A self-generated or missing review artifact is not authoritative for harness script changes.

## Known-Issue Sensor Exclusions

A sensor exclusion requires:

- `--exclude-sensor <name>`;
- `--known-issue <path>` pointing to an existing known-issue file;
- `--reason <text>`;
- progress registration before relying on the exclusion.

Exclusions must not be used to hide production issues or claim unverified completion.

## Codex / Review Gate Skip Allowlist

Skip `review-gate.sh` only when the diff is exclusively one of:

1. Markdown-only docs that do not change scanner contracts, gates, or harness rules.
2. Comment-only changes.
3. Review artifact additions under `docs/harness/reviews/`.

Do not skip when touching:

- `Cargo.toml`, `Cargo.lock`, or `vscode/package.json`;
- `src/adapter/**`, `src/parser/**`, `src/analysis/**`, `src/rules/**`, or `src/output/**`;
- `src/bin/cli.rs`, `src/lib.rs`, `src/baseline.rs`, `src/certify/**`, or `src/egress/**`;
- `action.yml`, `.github/**`, `vscode/**`, release docs, README CLI/action sections, or `.gitignore`;
- `docs/harness/**` except review artifacts.

When in doubt, do not skip.

## Retry Policy

| Action | Retries | After max |
|---|---:|---|
| `sensors.sh` after a fix | unlimited while making progress | stop when stuck |
| `review-gate.sh post` | 2 | escalate to owner |
