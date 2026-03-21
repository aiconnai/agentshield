## Task: T12 — Create egress policy schema

### Approach
Created a new `src/egress/` module with `policy.rs` containing the `EgressPolicy` schema for the future `wrap` command. The schema defines domain allow/deny rules, network IP blocking, rate limiting, and audit logging — all serializable to/from TOML.

### Files Changed
- `src/egress/mod.rs` — New module declaration
- `src/egress/policy.rs` — EgressPolicy schema with domain matching, IP blocking, rate limiting, load/save, starter TOML generation, and 9 unit tests
- `src/lib.rs` — Added `pub mod egress;`

### Decisions Made
- Used existing `ShieldError` variants (`Io`, `Config`, `Toml`, `TomlSer`) instead of adding new error types — keeps the change minimal
- Domain matching uses simple glob (`*.example.com`) rather than pulling in a regex dependency — sufficient for domain patterns
- IP classification uses string prefix matching rather than parsing into `std::net::IpAddr` — keeps it simple and handles edge cases like `localhost` and DNS names like `metadata.google.internal`
- `Default` impls on `NetworkPolicy`, `RateLimitPolicy`, `AuditPolicy` enable `#[serde(default)]` for optional TOML sections
- Schema version check is forward-only (rejects newer versions) — standard pattern for config evolution

### Verification
- Tests pass: yes (163 total — 154 existing + 9 new)
- Lint clean: yes (cargo clippy -- -D warnings)
- Type check: yes (included in build)
- Format: yes (cargo fmt applied)
