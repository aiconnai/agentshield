# AgentShield Release Checklist

Use this checklist for public AgentShield releases.

## Pre-release

- [ ] Confirm `Cargo.toml` has the intended version.
- [ ] Confirm `README.md` describes only commands and adapters that exist in the release branch.
- [ ] Confirm `CHANGELOG.md` has a dated top entry for the release.
- [ ] Confirm `docs/releases/<version>.md` exists and summarizes scope, notable changes, and readiness state.
- [ ] Confirm `action.yml` metadata reflects the supported scanner scope.
- [ ] Confirm no `.env` files, private keys, tokens, or local secrets are staged.

## Validation

- [ ] Run `cargo test`.
- [ ] Run `cargo clippy -- -D warnings`.
- [ ] Run `cargo fmt --check`.
- [ ] Run a CLI smoke scan against a known vulnerable fixture.
- [ ] Run `agentshield list-rules` and check the rule list for release drift.
- [ ] If `runtime` is part of the release, build with `--features full` and smoke test `agentshield wrap`.
- [ ] If the GitHub Action changed, test SARIF upload in a disposable repository or workflow run.

## Packaging

- [ ] Build release artifacts for all supported targets.
- [ ] Generate SHA256 checksums.
- [ ] Confirm archive names match `action.yml` download expectations.
- [ ] Confirm the binary starts and reports the intended version on each target.
- [ ] Confirm crate/package metadata points to the correct repository, license, README, and homepage.

## Publication

- [ ] Tag the release with `v<version>`.
- [ ] Publish the GitHub release with release notes and artifacts.
- [ ] Publish the crate if this is a crates.io release.
- [ ] Confirm the GitHub Action can resolve `latest` after publication.
- [ ] Confirm GitHub Code Scanning accepts generated SARIF from the release binary.

## Post-release

- [ ] Announce the release in the appropriate project channels.
- [ ] Open follow-up issues for any known gaps deferred from the release.
- [ ] Verify documentation links and badges after publication.
