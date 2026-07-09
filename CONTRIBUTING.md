# Contributing

Thanks for helping improve AgentShield.

## Before you start

- Open an issue for discussion if the change is large.
- Fork the repository and create a feature branch.
- Keep commits focused and include context in commit messages.

## Development setup

- Install Rust and run:

```bash
git clone https://github.com/aiconnai/agentshield.git
cd agentshield
cargo build --release
```

## Code quality checks

Before opening a PR, run:

```bash
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

Run the CLI smoke checks you changed before/after your edits when relevant:

```bash
cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
cargo run -- --help
```

## PR expectations

- Add tests for behavioral changes when possible.
- Keep PRs small and scoped.
- Reference test results in the PR description.

## Questions

If you are unsure about scanner behavior, include a small reproduction sample so reviewers
can validate the finding or false-positive/false-negative change.
