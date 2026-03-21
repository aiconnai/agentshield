## Task: Output format parity for dependency findings in AgentShield

### Approach

T7 already added manifest file locations to dependency findings at two levels:
1. `src/adapter/mcp.rs` — `parse_dependencies()` now populates `Dependency.location` with file path and line number for both `requirements.txt` (1-based line index) and `package.json` entries (via `find_json_key_line()`).
2. `src/rules/builtin/no_lockfile.rs` — SHIELD-012 computes `manifest_location` from the first dependency's location.
3. `src/rules/builtin/unpinned_deps.rs` — SHIELD-009 uses `dep.location.clone()`.

The key gap was:
- The SARIF comment incorrectly named SHIELD-009 and SHIELD-012 as "location-less" even though they now carry locations.
- No test verified that all 4 formats show the same location for a dependency finding.

SHIELD-008 (Excessive Permissions) still has `location: None` because it is a tool-level finding (declared vs. used permissions) with no specific code line — it remains correctly filtered from SARIF.

### Files Changed

- `src/output/sarif.rs` — Updated comment to accurately describe that only SHIELD-008 is location-less now; SHIELD-009 and SHIELD-012 pass through the SARIF filter since they have manifest locations.
- `src/lib.rs` — Added `dep_findings_location_parity_across_output_formats` integration test that scans the new fixture and verifies location consistency across console, JSON, SARIF, and HTML.
- `tests/fixtures/mcp_servers/vuln_unpinned_deps/requirements.txt` — New minimal fixture with `mcp>=1.0.0`, `requests>=2.31.0`, and `flask>=3.0.0` (all unpinned, no lockfile).
- `tests/fixtures/mcp_servers/vuln_unpinned_deps/server.py` — Minimal Python stub so the fixture directory is valid.

### Decisions Made

- Kept the SARIF `filter_map` with `let loc = f.location.as_ref()?` — this is the correct approach. It now correctly handles SHIELD-008 (no location → excluded from SARIF) while SHIELD-009 and SHIELD-012 (with locations → included in SARIF).
- The `diagnostics.ts` `if (!finding.location) { continue; }` guard is already correct: SHIELD-008 is skipped, dep findings with locations flow through.
- HTML already renders `"-"` for `location: None` which is still correct for SHIELD-008.
- Created a dedicated fixture (`vuln_unpinned_deps`) rather than reusing `crewai_project` so the test has a stable, minimal, self-describing baseline.
- The fixture has `mcp>=1.0.0` in requirements.txt so the MCP adapter's `detect()` recognizes it as an MCP server.

### Verification

- Tests pass: yes — 120 passed (up from 119)
- Lint clean: yes — `cargo clippy -- -D warnings` clean
- Type check: yes — no compilation errors
