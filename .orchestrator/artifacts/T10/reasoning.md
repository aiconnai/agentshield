## Task: Upgrade credential_exfil and prompt_injection detectors with taint paths

### Approach
Added two-phase detection to both SHIELD-002 (credential_exfil) and SHIELD-007 (prompt_injection) detectors. Phase 1 checks DataSurface.taint_paths for matching source/sink type pairs and produces findings with taint_path populated. Phase 2 runs the original ArgumentSource-based fallback logic. Deduplication by location ensures taint-path findings (richer info) take priority over fallback findings at the same location.

### Files Changed
- `src/rules/builtin/credential_exfil.rs` -- Added Phase 1 taint-path detection for (SecretStore|EnvVariable) -> (HttpRequest|ResponseToLlm) paths. Extracted original logic into `run_fallback()` method. Added deduplication. Added 4 new tests: taint_path detection, secret_store to response, fallback without taint_paths, deduplication, and irrelevant path filtering.
- `src/rules/builtin/prompt_injection.rs` -- Added Phase 1 taint-path detection for (ToolArgument|PromptContent) -> (DynamicEval|ResponseToLlm) paths. Extracted original logic into `run_fallback()` method. Added deduplication. Added 5 new tests: taint_path detection, dynamic_eval sink, fallback without taint_paths, deduplication, and irrelevant path filtering.

### Decisions Made
- Used `PromptContent` as an additional source type for prompt injection alongside `ToolArgument` since prompt content is also a prompt injection vector
- Mapped taint path confidence >= 0.8 to High confidence, below to Medium for prompt injection detector
- Credential exfil taint-path findings always get High confidence since the taint-path already confirms the data flow
- Deduplication compares by SourceLocation equality (file + line + column) using the existing PartialEq derive
- The task spec mentions SHIELD-010 for prompt injection but the actual code uses SHIELD-007; implemented against the actual code

### Verification
- Tests pass: yes (154 tests, up from ~145)
- Lint clean: yes (cargo clippy -- -D warnings)
- Type check: yes (compiles cleanly)
