use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-037: Agent Memory Poisoning / Unsanitized Vector Store Write
///
/// Detects MCP tool handler functions (Python) or tool-registered blocks (TS/JS) that write
/// untrusted input directly into a persistent vector store or agent memory system without
/// sanitization, enabling an attacker to embed malicious prompt-injection payloads that will
/// be retrieved and re-injected into future LLM contexts (CWE-20, OWASP MCP PromptInjection).
///
/// Covered patterns:
///   Python  — `@mcp.tool` / `@tool` / tool-named `def` whose body calls any of:
///             `.add(documents=`, `.add_texts(`, `.add_documents(`, `.upsert(`,
///             `.insert(Document(`, `.save_context(`, `memory.add_message(`,
///             `vectorstore.from_documents(` — **only when the call contains a
///             parameter-like variable** (i.e., the argument is not a plain string literal).
///   TS/JS   — `.addDocuments(`, `.addTexts(`, `.upsert(`, `.saveContext(`,
///             `.add({ documents:`, `collection.add(` appearing within 50 lines of a
///             tool-registration line — again only when the call is not purely hardcoded.
///
/// Suppression guard: if any of the 3 lines preceding the flagged call contain a call to
/// `sanitize`, `escape`, `validate`, `strip_tags`, `bleach.clean`, or `clean_input`, the
/// finding is suppressed (the developer has applied explicit sanitization).
pub struct AgentMemoryPoisoningDetector;

// ── Python statics (applied per-line; no (?m) flag) ───────────────────────────

// Matches @mcp.tool, @tool, @server.tool, @app.tool decorator lines.
static PY_TOOL_DECORATOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*@(?:\w+\.)*tool\b"#).expect("valid regex")
});

// Matches `def <name>(` where <name> contains a tool-related keyword.
static PY_TOOL_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^\s*(?:async\s+)?def\s+\w*(?:tool|handler|execute|process|handle|invoke)\w*\s*\("#,
    )
    .expect("valid regex")
});

// Matches any `def <name>(` — used to detect function boundaries after a decorator.
static PY_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*(?:async\s+)?def\s+\w+\s*\("#).expect("valid regex")
});

// Matches vector store write calls that receive a variable argument (not a plain string literal).
//
// The negative look-ahead for a bare string literal `["'<only chars>["']` is approximated by
// a positive assertion: the call must either have no argument at all on this line (multi-line
// call opened here) **or** contain at least one identifier character that is not immediately
// adjacent to only quote characters.  The simplest and most robust approach mirrors the
// reference detector: match the API name and then require that a non-string-literal variable
// name appears in the argument portion.  We achieve this by capturing the entire API fragment
// and then, in `scan_python`, running a second pass to rule out purely literal arguments.
//
// Pattern groups:
//   1.  .add(documents=  / collection.add(documents=
//   2.  .add_texts(
//   3.  .add_documents(
//   4.  .upsert(
//   5.  .insert(Document(
//   6.  .save_context(
//   7.  memory.add_message(
//   8.  vectorstore.from_documents(
static PY_VECTOR_WRITE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:\.add\s*\(\s*documents\s*=|\.add_texts\s*\(|\.add_documents\s*\(|\.upsert\s*\(|\.insert\s*\(\s*Document\s*\(|\.save_context\s*\(|memory\.add_message\s*\(|vectorstore\.from_documents\s*\()"#,
    )
    .expect("valid regex")
});

// Positively detects a bare variable identifier in the argument portion of a Python
// vector store write call. Fires when a lowercase-starting word appears after
// `[`, `(`, `=`, or `,` (with optional whitespace). If no such identifier is found,
// the call is treated as literal-only and suppressed.
//
// Examples that match (variable present → fire):
//   collection.add(documents=[user_input])   ← `user_input` after `[`
//   collection.add_texts([query])            ← `query` after `[`
//
// Examples that do NOT match (literals only → suppress):
//   collection.add(documents=["safe text"])  ← only quoted string after `[`
static PY_VAR_IN_ARG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:[=\[,(]\s*)[a-z_]\w*(?:\s*[,\]\)\}\(]|$)"#).expect("valid regex")
});

// ── Sanitization guard (shared, applied per-line; no (?m) flag) ───────────────

// Matches calls to common sanitization / validation helpers.
static SANITIZER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\b(?:sanitize|escape|validate|strip_tags|bleach\.clean|clean_input)\s*\("#,
    )
    .expect("valid regex")
});

// ── TypeScript / JavaScript statics (applied per-line; no (?m) flag) ──────────

// Matches tool registration: `.tool(`, `.addTool(`, `server.tool(`, `mcp.tool(`
static TS_TOOL_REGISTRATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:addTool|server\.tool|mcp\.tool|\.tool)\s*\("#).expect("valid regex")
});

// Matches TS/JS vector store write calls (all common LangChain / LlamaIndex / SDK variants).
static TS_VECTOR_WRITE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:\.addDocuments\s*\(|\.addTexts\s*\(|\.upsert\s*\(|\.saveContext\s*\(|\.add\s*\(\s*\{\s*documents\s*:|collection\.add\s*\()"#,
    )
    .expect("valid regex")
});

// Positively detects a bare variable identifier in the argument portion of a TS/JS
// vector-store write call.  Fires when a camelCase/snake_case word appears after
// `[`, `(`, `,`, or `{` — and is NOT followed by `:` (which would mark it as an object
// key, not a value).  Does not fire on pure string literals or object-key identifiers.
//
// Examples that match (variable present → should fire):
//   .addDocuments([{ pageContent: userInput }])   ← `userInput` after space, before `}`
//   .add_texts([query])                           ← `query` after `[`
//
// Examples that do NOT match (literal-only → should suppress):
//   .saveContext({ input: "hardcoded" }, ...)     ← only quoted strings as values
//   collection.add(documents=["safe text"])        ← only quoted string
static TS_BARE_IDENTIFIER_IN_ARG_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches a bare lowercase-starting identifier NOT followed by `:` (object key) that
    // appears after `[`, `(`, `,`, space, or `{` as an argument value.
    Regex::new(r#"[\(\[,\s\{]\s*[a-z_]\w*\s*(?:[,\]\)\}\(]|$)"#).expect("valid regex")
});

// ── Detector impl ─────────────────────────────────────────────────────────────

impl Detector for AgentMemoryPoisoningDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-037".into(),
            name: "Agent Memory Poisoning / Unsanitized Vector Store Write".into(),
            description:
                "MCP tool handler writes untrusted input directly into a persistent vector store \
                 or agent memory system without sanitization, allowing an attacker to embed \
                 malicious prompt-injection payloads that are retrieved and injected into future \
                 LLM contexts"
                    .into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::PromptInjectionSurface,
            cwe_id: Some("CWE-20".into()),
            owasp_mcp: Some(OwaspMcp::PromptInjection),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &target.source_files {
            let lines: Vec<&str> = file.content.lines().collect();

            match file.language {
                Language::Python => {
                    scan_python(&lines, file, &mut findings);
                }
                Language::TypeScript | Language::JavaScript => {
                    scan_ts_js(&lines, file, &mut findings);
                }
                _ => {}
            }
        }

        findings
    }
}

// ── Python scanner ─────────────────────────────────────────────────────────────

fn scan_python(
    lines: &[&str],
    file: &crate::ir::SourceFile,
    findings: &mut Vec<Finding>,
) {
    let mut in_tool_fn = false;
    let mut expecting_tool_def = false;
    let mut tool_fn_indent: usize = 0;

    for (line_idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let current_indent = line.len() - line.trim_start().len();

        // If we were waiting for the def after a decorator, consume it now.
        if expecting_tool_def {
            if PY_DEF_RE.is_match(line) {
                in_tool_fn = true;
                expecting_tool_def = false;
                tool_fn_indent = current_indent;
                continue;
            } else if trimmed.starts_with('@') {
                // Stacked decorator (e.g. @staticmethod, @validate, @lru_cache)
                continue;
            } else {
                // If we see something other than a blank/comment/decorator before the def,
                // reset — this shouldn't normally happen but be defensive.
                expecting_tool_def = false;
            }
        }

        // Detect function exit: dedent back to or above the def-level.
        if in_tool_fn && current_indent <= tool_fn_indent {
            in_tool_fn = false;
        }

        // Detect tool entry.
        if !in_tool_fn {
            if PY_TOOL_DECORATOR_RE.is_match(line) {
                expecting_tool_def = true;
                continue;
            } else if PY_TOOL_DEF_RE.is_match(line) {
                in_tool_fn = true;
                tool_fn_indent = current_indent;
                continue;
            }
        }

        if in_tool_fn && PY_VECTOR_WRITE_RE.is_match(line) {
            // Suppress if the argument on this line is a plain string literal.
            if is_py_literal_arg(line) {
                continue;
            }

            // Suppress if any of the preceding 3 lines contain a sanitizer call.
            if preceding_lines_have_sanitizer(lines, line_idx, 3) {
                continue;
            }

            let col = find_write_col(line);
            let loc = SourceLocation {
                file: file.path.clone(),
                line: line_idx + 1,
                column: col,
                end_line: None,
                end_column: None,
            };
            findings.push(make_finding(trimmed, loc));
        }
    }
}

// ── TypeScript / JavaScript scanner ───────────────────────────────────────────

fn scan_ts_js(
    lines: &[&str],
    file: &crate::ir::SourceFile,
    findings: &mut Vec<Finding>,
) {
    for (line_idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if TS_TOOL_REGISTRATION_RE.is_match(line) {
            // Scan the next 50 lines for vector store writes.
            let end_idx = (line_idx + 50).min(lines.len());
            for (body_offset, &body_line) in lines[line_idx..end_idx].iter().enumerate() {
                let body_trimmed = body_line.trim();
                if body_trimmed.starts_with("//") || body_trimmed.starts_with('*') {
                    continue;
                }

                if !TS_VECTOR_WRITE_RE.is_match(body_line) {
                    continue;
                }

                // Suppress if the argument appears to be a hardcoded string literal.
                if is_ts_literal_arg(body_line) {
                    continue;
                }

                let finding_line_idx = line_idx + body_offset;

                // Suppress if any of the preceding 3 lines contain a sanitizer call.
                if preceding_lines_have_sanitizer(lines, finding_line_idx, 3) {
                    continue;
                }

                let col = find_write_col(body_line);
                let loc = SourceLocation {
                    file: file.path.clone(),
                    line: finding_line_idx + 1,
                    column: col,
                    end_line: None,
                    end_column: None,
                };
                findings.push(make_finding(body_trimmed, loc));
                // One finding per tool registration block.
                break;
            }
        }
    }
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

/// Returns `true` if the 3 lines immediately before `line_idx` contain a sanitizer call.
fn preceding_lines_have_sanitizer(lines: &[&str], line_idx: usize, window: usize) -> bool {
    let start = line_idx.saturating_sub(window);
    lines[start..line_idx]
        .iter()
        .any(|l| SANITIZER_RE.is_match(l))
}

/// Returns `true` when the Python vector store write call on this line appears to have
/// only hardcoded string literal arguments (no bare variable identifiers).
///
/// Uses `PY_VAR_IN_ARG_RE` which positively matches a bare lowercase identifier used
/// as an argument value. If no such identifier is found, the call is treated as safe
/// (literal-only) and the finding is suppressed.
fn is_py_literal_arg(line: &str) -> bool {
    // If a bare variable identifier is found in the argument → NOT a literal-only call → do NOT suppress.
    // If no bare variable is found → literal-only call → suppress (return true).
    !PY_VAR_IN_ARG_RE.is_match(line)
}

/// Returns `true` when the TS/JS vector-store write call on this line has NO bare variable
/// in its argument position (i.e., only string literals appear → suppress the finding).
///
/// We use `TS_BARE_IDENTIFIER_IN_ARG_RE` which positively matches a camelCase/snake_case
/// identifier used as a value (not as an object key, which is followed by `:`).  If no
/// such identifier is found the call is treated as hardcoded → suppress.
fn is_ts_literal_arg(line: &str) -> bool {
    !TS_BARE_IDENTIFIER_IN_ARG_RE.is_match(line)
}

/// Finds the column of the first vector-store write method name on the line.
fn find_write_col(line: &str) -> usize {
    // Look for `.add`, `.upsert`, `.insert`, `.save`, `.from_documents`, `memory.`, `collection.`
    for marker in &[
        ".add(",
        ".upsert(",
        ".insert(",
        ".save",
        ".from_documents(",
        "memory.add_message(",
        "collection.add(",
        ".addDocuments(",
        ".addTexts(",
        ".saveContext(",
    ] {
        if let Some(pos) = line.find(marker) {
            return pos;
        }
    }
    0
}

/// Constructs a SHIELD-037 `Finding` from a code snippet and location.
fn make_finding(snippet: &str, loc: SourceLocation) -> Finding {
    Finding {
        rule_id: "SHIELD-037".into(),
        rule_name: "Agent Memory Poisoning / Unsanitized Vector Store Write".into(),
        severity: Severity::High,
        confidence: Confidence::Medium,
        attack_category: AttackCategory::PromptInjectionSurface,
        message: "Tool handler writes unsanitized input into a vector store or agent memory \
                  system — an attacker who controls tool parameters can embed malicious \
                  prompt-injection payloads that will be retrieved and injected into future \
                  LLM contexts"
            .into(),
        location: Some(loc.clone()),
        evidence: vec![Evidence {
            description: "Unsanitized vector store / memory write inside a tool handler".into(),
            location: Some(loc),
            snippet: Some(snippet.to_string()),
        }],
        taint_path: None,
        remediation: Some(
            "Sanitize or validate all untrusted input before writing it to a vector store or \
             agent memory. Consider: (1) stripping HTML / control characters with a library such \
             as `bleach` or DOMPurify before embedding; (2) applying an allowlist schema \
             (Pydantic, Zod) to reject unexpected structure; (3) storing only normalized, \
             application-generated text and keeping raw user input in a separate, non-retrievable \
             field; (4) adding retrieval-time content policies that refuse to relay untrusted \
             stored chunks directly into the system prompt."
                .into(),
        ),
        cwe_id: Some("CWE-20".into()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Framework, Language, ScanTarget, SourceFile};
    use std::path::PathBuf;

    fn target_with_source(code: &str, language: Language) -> ScanTarget {
        ScanTarget {
            name: "test-memory-agent".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: Default::default(),
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![SourceFile {
                path: PathBuf::from(match language {
                    Language::Python => "memory_tool.py",
                    Language::TypeScript => "memory_tool.ts",
                    _ => "memory_tool.js",
                }),
                language,
                size_bytes: code.len() as u64,
                content_hash: "hash".into(),
                content: code.to_string(),
            }],
        }
    }

    // ── Test 1: Python .add(documents=[param]) inside @mcp.tool fires ─────────

    #[test]
    fn detects_python_vector_add_with_param_in_mcp_tool() {
        let code = r#"
@mcp.tool
def store_memory(user_input: str) -> str:
    collection.add(documents=[user_input], ids=["id1"])
    return "stored"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for .add(documents=[param]) in @mcp.tool; got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-037");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    // ── Test 2: Python hardcoded .add(documents=["safe text"]) does NOT fire ──

    #[test]
    fn ignores_python_vector_add_with_hardcoded_literal() {
        let code = r#"
@mcp.tool
def seed_memory() -> str:
    collection.add(documents=["safe text"], ids=["id1"])
    return "seeded"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "hardcoded literal arg must not trigger SHIELD-037; got: {findings:#?}"
        );
    }

    // ── Test 3: Python .add_texts([query]) inside tool-named function fires ───

    #[test]
    fn detects_python_add_texts_in_tool_named_function() {
        let code = r#"
async def handle_query(query: str) -> str:
    vectorstore.add_texts([query])
    return "indexed"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for .add_texts([query]) in tool-named function; got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-037");
    }

    // ── Test 4: Python write preceded by sanitize() does NOT fire ─────────────

    #[test]
    fn ignores_python_vector_write_after_sanitize() {
        let code = r#"
@mcp.tool
def store_memory(user_input: str) -> str:
    clean = sanitize(user_input)
    collection.add(documents=[clean], ids=["id1"])
    return "stored"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "write after sanitize() must not trigger SHIELD-037; got: {findings:#?}"
        );
    }

    // ── Test 5: TypeScript .addDocuments([{ pageContent: userInput }]) fires ──

    #[test]
    fn detects_ts_add_documents_with_variable() {
        let code = r#"
server.tool("store", async ({ userInput }) => {
    await vectorStore.addDocuments([{ pageContent: userInput }]);
    return { ok: true };
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for .addDocuments([{{ pageContent: userInput }}]); got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-037");
        assert_eq!(findings[0].severity, Severity::High);
    }

    // ── Test 6: TypeScript .saveContext({ input: "hardcoded" }) does NOT fire ─

    #[test]
    fn ignores_ts_save_context_with_hardcoded_string() {
        let code = r#"
server.tool("seed", async () => {
    await memory.saveContext({ input: "hardcoded" }, { output: "result" });
    return { ok: true };
});
"#;
        let target = target_with_source(code, Language::TypeScript);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert!(
            findings.is_empty(),
            "hardcoded .saveContext must not trigger SHIELD-037; got: {findings:#?}"
        );
    }

    // ── Test 7: Metadata well-formed (rule_id, severity, cwe, owasp) ──────────

    #[test]
    fn metadata_is_well_formed() {
        let detector = AgentMemoryPoisoningDetector;
        let meta = detector.metadata();
        assert_eq!(meta.id, "SHIELD-037");
        assert_eq!(meta.default_severity, Severity::High);
        assert_eq!(meta.cwe_id.as_deref(), Some("CWE-20"));
        assert_eq!(meta.owasp_mcp, Some(OwaspMcp::PromptInjection));
        assert_eq!(meta.attack_category, AttackCategory::PromptInjectionSurface);
    }

    // ── Test 8: Python .add(documents=get_untrusted()) with function call fires ─

    #[test]
    fn detects_python_vector_add_with_function_call_arg() {
        let code = r#"
@mcp.tool
def store_memory() -> str:
    collection.add(documents=get_untrusted_docs(), ids=["id1"])
    return "stored"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for .add(documents=get_untrusted_docs()); got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-037");
    }

    // ── Test 9: Python stacked decorators detected ────────────────────────────

    #[test]
    fn detects_stacked_decorator_tool() {
        let code = r#"
@mcp.tool
@validate_args
def store_memory(param: str) -> str:
    collection.add(documents=[param], ids=["id1"])
    return "stored"
"#;
        let target = target_with_source(code, Language::Python);
        let detector = AgentMemoryPoisoningDetector;
        let findings = detector.run(&target);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for stacked decorator tool; got {}: {findings:#?}",
            findings.len()
        );
        assert_eq!(findings[0].rule_id, "SHIELD-037");
    }
}

