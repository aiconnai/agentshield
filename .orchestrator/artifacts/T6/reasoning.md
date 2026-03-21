## Task: Add CLI suppression workflow to AgentShield

### Approach

Added two new subcommands (`suppress` and `list-suppressions`) to the existing Clap CLI. The `suppress` command reads the existing `.agentshield.toml` (or creates a default config), appends a `Suppression` entry, and writes back using `toml::to_string_pretty`. The `list-suppressions` command reads the config and prints a table with status (active/expired). Also added `toml::ser::Error` to the `ShieldError` enum to handle TOML serialization errors.

### Files Changed

- `src/error.rs` — Added `TomlSer(#[from] toml::ser::Error)` variant to `ShieldError` for serialization errors from `toml::to_string_pretty`
- `src/bin/cli.rs` — Added `Suppress` and `ListSuppressions` subcommands to the `Commands` enum, match arms in `main`, and two new command functions `cmd_suppress` and `cmd_list_suppressions`
- `src/lib.rs` — Added `suppress_command_roundtrip` integration test that scans a fixture, suppresses the first finding, and verifies it no longer appears in a re-scan

### Decisions Made

- Chose Option A (separate `suppress` subcommand) over flag on scan — keeps scan command clean and each command has single responsibility
- Used `toml::to_string_pretty` for round-trip serialization; the `Config` struct is already `Serialize` via serde, so this requires no new types
- Validated `--expires` date format at the CLI layer before touching the config file, so the file is never left in a corrupt state
- Showed only 12-char fingerprint prefix in confirmation message (matching the task spec example), 16-char in the table for better distinguishability
- Used `tempfile::TempDir` in the integration test to avoid polluting fixture directories

### Verification

- Tests pass: yes — 119 tests (118 original + 1 new `suppress_command_roundtrip`)
- Lint clean: yes — `cargo clippy -- -D warnings` produces zero warnings
- Type check: yes — `cargo build` succeeds
