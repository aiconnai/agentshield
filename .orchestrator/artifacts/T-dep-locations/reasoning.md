## Task: Add manifest locations to dependency findings

### Approach
Populated `SourceLocation` on dependency findings so they appear in SARIF output and GitHub Code Scanning annotations. Three changes: (1) package.json deps get line numbers via raw text search, (2) SHIELD-012 no-lockfile findings point to the manifest file, (3) added helper function for JSON key line lookup.

### Files Changed
- `src/adapter/mcp.rs` — Added `find_json_key_line()` helper; populate `location` on package.json dependencies with file path and line number found by searching raw JSON for the key string
- `src/rules/builtin/no_lockfile.rs` — Derive manifest location from the first dependency's location (line 1 of the manifest file); import `SourceLocation`

### Decisions Made
- Used raw text search (`find_json_key_line`) for package.json line numbers rather than a JSON parser with position tracking, because serde_json does not expose source positions and adding a new dependency (e.g., `serde_json::de::StreamDeserializer`) would be overkill for this use case
- For SHIELD-012, used the first dependency's file path at line 1 as the manifest location, since the lockfile itself does not exist (that is the whole point of the finding)
- requirements.txt already had locations populated — no changes needed there
- SHIELD-009 and SHIELD-010 already used `dep.location.clone()` — no changes needed in those detectors

### Verification
- Tests pass: yes (119 passed)
- Lint clean: yes (clippy -D warnings: 0 warnings)
- Type check: yes (cargo build succeeds)
- SARIF output verified: SHIELD-009 and SHIELD-012 now included (previously filtered)
