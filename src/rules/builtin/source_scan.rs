use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::{Match, Regex};

use crate::ir::{Language, ScanTarget, SourceFile, SourceLocation};
use crate::rules::Finding;

// ── Shared tool-scope regexes (SHIELD-036, SHIELD-037) ────────────────────────

// Matches @mcp.tool, @tool, @server.tool, @app.tool decorator lines.
static PY_TOOL_DECORATOR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^\s*@(?:\w+\.)*tool\b"#).expect("valid regex"));

// Matches `def <name>(` where <name> contains a tool-related keyword.
static PY_TOOL_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^\s*(?:async\s+)?def\s+\w*(?:tool|handler|execute|process|handle|invoke)\w*\s*\("#,
    )
    .expect("valid regex")
});

// Matches any `def <name>(` — used to detect function boundaries after a decorator.
static PY_DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^\s*(?:async\s+)?def\s+\w+\s*\("#).expect("valid regex"));

// Matches tool registration: `.tool(`, `.addTool(`, `server.tool(`, `mcp.tool(`.
static TS_TOOL_REGISTRATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:addTool|server\.tool|mcp\.tool|\.tool)\s*\("#).expect("valid regex")
});

/// Language classification for source-file line scanners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceLang {
    Python,
    TypeScriptOrJs,
}

impl SourceLang {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::TypeScriptOrJs => "TypeScript",
        }
    }
}

/// Classifies a `SourceFile` as Python or TypeScript/JavaScript using both its
/// parsed `Language` enum and file extension fallback.
pub(super) fn classify_source_lang(source: &SourceFile) -> Option<SourceLang> {
    if source.language == Language::Python
        || source
            .path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "py")
    {
        Some(SourceLang::Python)
    } else if matches!(source.language, Language::TypeScript | Language::JavaScript)
        || source
            .path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "ts" | "js" | "tsx" | "jsx" | "mjs"))
    {
        Some(SourceLang::TypeScriptOrJs)
    } else {
        None
    }
}

/// Returns `true` if a trimmed line is a full-line comment in Python or TS/JS.
pub(super) fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

/// Builds a 1-indexed full-line `SourceLocation`.
pub(super) fn full_line_location(
    source: &SourceFile,
    line_idx: usize,
    line: &str,
) -> SourceLocation {
    SourceLocation {
        file: source.path.clone(),
        line: line_idx + 1,
        column: 1,
        end_line: Some(line_idx + 1),
        end_column: Some(line.len() + 1),
    }
}

/// Builds a 1-indexed regex-match `SourceLocation`.
pub(super) fn regex_match_location(
    source: &SourceFile,
    line_idx: usize,
    mat: &Match<'_>,
) -> SourceLocation {
    SourceLocation {
        file: source.path.clone(),
        line: line_idx + 1,
        column: mat.start() + 1,
        end_line: Some(line_idx + 1),
        end_column: Some(mat.end() + 1),
    }
}

/// Scans all Python and TypeScript/JavaScript source files in `target`, matching
/// each non-comment line against `py_re` or `ts_re` respectively.
pub(super) fn scan_py_ts_regex_matches<F>(
    target: &ScanTarget,
    py_re: &Regex,
    ts_re: &Regex,
    mut on_match: F,
) where
    F: FnMut(&SourceFile, SourceLang, usize, &str, Match<'_>),
{
    for source in &target.source_files {
        let Some(lang) = classify_source_lang(source) else {
            continue;
        };
        let regex = match lang {
            SourceLang::Python => py_re,
            SourceLang::TypeScriptOrJs => ts_re,
        };

        for (line_idx, line) in source.content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || is_comment_line(trimmed) {
                continue;
            }
            if let Some(mat) = regex.find(line) {
                on_match(source, lang, line_idx, line, mat);
            }
        }
    }
}

/// Dispatches Python and TypeScript/JavaScript source files to tool-scoped
/// scanners, splitting lines once per matching file.
pub(super) fn scan_tool_scoped_sources<P, T>(
    target: &ScanTarget,
    findings: &mut Vec<Finding>,
    mut on_py: P,
    mut on_ts: T,
) where
    P: FnMut(&[&str], &SourceFile, &mut Vec<Finding>),
    T: FnMut(&[&str], &SourceFile, &mut Vec<Finding>),
{
    for file in &target.source_files {
        match file.language {
            Language::Python => {
                let lines: Vec<&str> = file.content.lines().collect();
                on_py(&lines, file, findings);
            }
            Language::TypeScript | Language::JavaScript => {
                let lines: Vec<&str> = file.content.lines().collect();
                on_ts(&lines, file, findings);
            }
            _ => {}
        }
    }
}

/// Scans lines inside Python `@mcp.tool` / `@tool` decorated functions or
/// functions whose names match tool-handler conventions.
pub(super) fn scan_python_tool_lines<F>(lines: &[&str], mut on_body_line: F)
where
    F: FnMut(usize, &str, &str),
{
    let mut in_tool_fn = false;
    let mut expecting_tool_def = false;
    let mut tool_fn_indent: usize = 0;

    for (line_idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let current_indent = line.len() - line.trim_start().len();

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
                // A non-decorator, non-def line appeared between @tool and def.
                expecting_tool_def = false;
            }
        }

        if in_tool_fn && current_indent <= tool_fn_indent {
            in_tool_fn = false;
        }

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

        if in_tool_fn {
            on_body_line(line_idx, line, trimmed);
        }
    }
}

/// Scans a 50-line window after each TypeScript/JavaScript `.tool(` / `.addTool(`
/// registration. When `on_window_line(finding_line_idx, body_line, body_trimmed)`
/// returns `true`, that line is recorded to avoid duplicate findings across
/// overlapping windows and the scanner advances to the next registration block.
pub(super) fn scan_ts_tool_window_lines<F>(lines: &[&str], mut on_window_line: F)
where
    F: FnMut(usize, &str, &str) -> bool,
{
    let mut reported_lines: HashSet<usize> = HashSet::new();

    for (line_idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if TS_TOOL_REGISTRATION_RE.is_match(line) {
            let end_idx = (line_idx + 50).min(lines.len());
            for (body_offset, &body_line) in lines[line_idx..end_idx].iter().enumerate() {
                let finding_line_idx = line_idx + body_offset;
                if reported_lines.contains(&finding_line_idx) {
                    continue;
                }
                let body_trimmed = body_line.trim();
                if body_trimmed.starts_with("//") || body_trimmed.starts_with('*') {
                    continue;
                }

                if on_window_line(finding_line_idx, body_line, body_trimmed) {
                    reported_lines.insert(finding_line_idx);
                    break;
                }
            }
        }
    }
}

/// Joins a slice of lines `[line_idx.saturating_sub(lookbehind)..(line_idx + lookahead).min(lines.len())]`
/// with newlines for multi-line regex context inspection.
pub(super) fn line_window(
    lines: &[&str],
    line_idx: usize,
    lookbehind: usize,
    lookahead: usize,
) -> String {
    let start_idx = line_idx.saturating_sub(lookbehind);
    let end_idx = (line_idx + lookahead).min(lines.len());
    lines[start_idx..end_idx].join("\n")
}

/// Extends `findings` with `fallback_findings` whose locations do not already
/// appear in `findings` (keeping higher-confidence taint-path findings).
pub(super) fn extend_non_dominated_findings(
    findings: &mut Vec<Finding>,
    fallback_findings: Vec<Finding>,
) {
    let primary_locations: Vec<_> = findings.iter().filter_map(|f| f.location.clone()).collect();

    findings.extend(fallback_findings.into_iter().filter(|finding| {
        !finding
            .location
            .as_ref()
            .is_some_and(|loc| primary_locations.iter().any(|p_loc| p_loc == loc))
    }));
}
