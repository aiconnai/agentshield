//! Cross-file sanitizer-aware validation tracking.
//!
//! Runs after parsing, before detection. When a function is only ever called
//! with sanitized arguments, downgrades its parameters' `ArgumentSource` from
//! tainted to `Sanitized`. This eliminates false positives from internal
//! helper functions that receive already-validated input from their callers.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::ir::ArgumentSource;
use crate::parser::ParsedFile;

/// Sanitizer category. A sanitizer is only safe for matching sink types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerCategory {
    Path,
    Network,
    Redaction,
    TypeCoercion,
}

impl SanitizerCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Network => "network",
            Self::Redaction => "redaction",
            Self::TypeCoercion => "type",
        }
    }
}

use crate::ir::SinkClass;

/// Path/file sanitizers. These are safe for file/path sinks only.
static PATH_SANITIZER_NAMES: &[&str] = &[
    "validatePath",
    "sanitizePath",
    "normalizePath",
    "resolvePath",
    "canonicalizePath",
    "realpath",
    "path.resolve",
    "path.normalize",
    "resolve",
    "normalize",
    "os.path.realpath",
    "os.path.abspath",
    "os.path.normpath",
    "abspath",
    "normpath",
];

/// Network/url validators. Parse-only helpers such as URL.parse/urlparse are
/// intentionally excluded: parsing is not allowlist validation.
static NETWORK_SANITIZER_NAMES: &[&str] = &[
    "validateUrl",
    "validateURL",
    "validateUri",
    "validateURI",
    "validateAllowedUrl",
    "validateAllowedURL",
    "validateAllowedUri",
    "validateAllowedURI",
    "allowlistUrl",
    "allowlistURL",
    "allowlistUri",
    "allowlistURI",
    "ensureAllowedUrl",
    "ensureAllowedURL",
    "ensureAllowedUri",
    "ensureAllowedURI",
    "assertAllowedUrl",
    "assertAllowedURL",
    "assertAllowedUri",
    "assertAllowedURI",
];

/// Type coercion helpers. These are not path or network validators.
static TYPE_COERCION_SANITIZER_NAMES: &[&str] =
    &["parseInt", "parseFloat", "Number", "int", "float", "str"];

/// Credential/log redaction helpers. These are safe only for credential/log
/// leakage analysis and must not sanitize file, network, command, or eval sinks.
static REDACTION_SANITIZER_NAMES: &[&str] = &[
    "redactSecret",
    "redactSecrets",
    "redactToken",
    "redactCredentials",
    "maskSecret",
    "maskToken",
    "maskCredentials",
    "scrubSecret",
    "scrubToken",
    "scrubCredentials",
];

fn exact_or_method_match(name: &str, names: &[&str]) -> bool {
    if names.contains(&name) {
        return true;
    }

    name.rsplit('.')
        .next()
        .is_some_and(|method| names.contains(&method))
}

fn compact_lower(name: &str) -> String {
    name.chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Categorize a sanitizer helper by the sink family it protects.
pub fn sanitizer_category(name: &str) -> Option<SanitizerCategory> {
    if let Some((prefix, _)) = name.split_once(':') {
        return match prefix {
            "path" => Some(SanitizerCategory::Path),
            "network" => Some(SanitizerCategory::Network),
            "redaction" => Some(SanitizerCategory::Redaction),
            "type" => Some(SanitizerCategory::TypeCoercion),
            _ => None,
        };
    }

    if exact_or_method_match(name, REDACTION_SANITIZER_NAMES) {
        return Some(SanitizerCategory::Redaction);
    }

    if exact_or_method_match(name, PATH_SANITIZER_NAMES) {
        return Some(SanitizerCategory::Path);
    }

    if exact_or_method_match(name, NETWORK_SANITIZER_NAMES) {
        return Some(SanitizerCategory::Network);
    }

    if exact_or_method_match(name, TYPE_COERCION_SANITIZER_NAMES) {
        return Some(SanitizerCategory::TypeCoercion);
    }

    let lower = compact_lower(name);

    if (lower.starts_with("validate") || lower.starts_with("sanitize")) && lower.contains("path") {
        return Some(SanitizerCategory::Path);
    }

    if (lower.starts_with("validate")
        || lower.starts_with("allowlist")
        || lower.starts_with("ensureallowed")
        || lower.starts_with("assertallowed"))
        && (lower.contains("url")
            || lower.contains("uri")
            || lower.contains("host")
            || lower.contains("domain"))
    {
        return Some(SanitizerCategory::Network);
    }

    None
}

/// Check if a function name is a non-redaction input sanitizer. Kept for parser
/// compatibility; redaction helpers are intentionally excluded from this global
/// taint downgrade path.
pub fn is_sanitizer(name: &str) -> bool {
    matches!(
        sanitizer_category(name),
        Some(
            SanitizerCategory::Path | SanitizerCategory::Network | SanitizerCategory::TypeCoercion
        )
    )
}

pub fn is_redaction_sanitizer(name: &str) -> bool {
    matches!(sanitizer_category(name), Some(SanitizerCategory::Redaction))
}

pub fn sanitizer_label(name: &str) -> Option<String> {
    sanitizer_category(name).map(|category| format!("{}:{name}", category.as_str()))
}

/// Whether `sanitizer` neutralizes taint for `sink`.
///
/// Each sanitizer category protects only its own sink family. Type coercion
/// (`str()`/`Number()`) is identity on a string and is NOT accepted for any
/// injection sink — it neither escapes shell metacharacters nor constrains a
/// path or URL. Redaction sanitizers protect no input sink (only credential/log
/// leakage analysis), so they are absent here.
pub(crate) fn sanitizer_allows_sink(sanitizer: &str, sink: SinkClass) -> bool {
    // A cross-file downgrade is proven safe for exactly one sink.
    if let Some(downgraded_sink) = cross_file_sink(sanitizer) {
        return downgraded_sink == sink;
    }

    matches!(
        (sanitizer_category(sanitizer), sink),
        (Some(SanitizerCategory::Path), SinkClass::FilePath)
            | (Some(SanitizerCategory::Network), SinkClass::NetworkUrl)
    )
}

fn arg_safe_for_sink(arg: &ArgumentSource, sink: SinkClass) -> bool {
    !arg.is_tainted_for_sink(sink)
}

/// Prefix marking a cross-file downgrade label, followed by the exact sink it
/// was proven safe for. Unlike a named sanitizer (which protects a whole
/// category), a cross-file downgrade is proven safe for precisely one sink, so
/// the sink is encoded directly and matched back in [`sanitizer_allows_sink`].
const CROSS_FILE_SANITIZER_PREFIX: &str = "crossfile";

fn cross_file_sanitizer_label(sink: SinkClass, func_name: &str) -> String {
    let sink_tag = match sink {
        SinkClass::Command => "command",
        SinkClass::FilePath => "filepath",
        SinkClass::NetworkUrl => "networkurl",
        SinkClass::DynamicExec => "dynamicexec",
    };
    format!("{CROSS_FILE_SANITIZER_PREFIX}:{sink_tag}:caller passes sanitized value to {func_name}")
}

fn cross_file_sink(sanitizer: &str) -> Option<SinkClass> {
    let rest = sanitizer
        .strip_prefix(CROSS_FILE_SANITIZER_PREFIX)?
        .strip_prefix(':')?;
    let tag = rest.split(':').next()?;
    match tag {
        "command" => Some(SinkClass::Command),
        "filepath" => Some(SinkClass::FilePath),
        "networkurl" => Some(SinkClass::NetworkUrl),
        "dynamicexec" => Some(SinkClass::DynamicExec),
        _ => None,
    }
}

fn all_call_sites_safe_for_sink(
    sites: &[Vec<ArgumentSource>],
    param_idx: usize,
    sink: SinkClass,
) -> bool {
    sites.iter().all(|args| {
        args.get(param_idx)
            .is_some_and(|arg| arg_safe_for_sink(arg, sink))
    })
}

/// Result of cross-file sanitization analysis.
#[derive(Debug)]
pub struct CrossFileResult {
    /// Number of operations whose ArgumentSource was downgraded.
    pub downgraded_count: usize,
    /// Functions determined to receive only sanitized input.
    pub sanitized_functions: Vec<String>,
}

/// Perform cross-file sanitizer-aware analysis on parsed files.
///
/// For each function definition, checks if ALL discovered call sites pass
/// sanitized (or literal) arguments for each parameter. If so, downgrades
/// the function's operations from tainted to `Sanitized`.
///
/// Conservative: exported functions with zero discovered call sites keep
/// their parameters tainted.
pub fn apply_cross_file_sanitization(
    parsed_files: &mut [(PathBuf, ParsedFile)],
) -> CrossFileResult {
    let mut downgraded_count = 0;
    let mut sanitized_functions = Vec::new();

    // Phase 1: Build function definition map.
    // Key: function name → (file index, param names)
    let mut func_defs: HashMap<String, Vec<(usize, Vec<String>, bool)>> = HashMap::new();
    // Per-file set of (param name, sink) that are UNAMBIGUOUSLY safe:
    // every function in the file declaring `param_name` is itself proven
    // safe for `sink`. Used to scope the downgrade to the proven-safe
    // function and avoid clearing an UNSAFE sibling that shares the param
    // name (issue #33). When two functions in a file share a param
    // name but only one is proven safe, that (param, sink) is excluded.
    let mut file_safe_param_sinks: HashMap<usize, HashSet<(String, SinkClass)>> = HashMap::new();
    for (idx, (_, parsed)) in parsed_files.iter().enumerate() {
        for def in &parsed.function_defs {
            for param in &def.params {
                file_safe_param_sinks
                    .entry(idx)
                    .or_default()
                    .insert((param.clone(), SinkClass::Command));
                file_safe_param_sinks
                    .entry(idx)
                    .or_default()
                    .insert((param.clone(), SinkClass::FilePath));
                file_safe_param_sinks
                    .entry(idx)
                    .or_default()
                    .insert((param.clone(), SinkClass::NetworkUrl));
                file_safe_param_sinks
                    .entry(idx)
                    .or_default()
                    .insert((param.clone(), SinkClass::DynamicExec));
            }
            func_defs.entry(def.name.clone()).or_default().push((
                idx,
                def.params.clone(),
                def.is_exported,
            ));
        }
    }

    // Phase 2: Build call-site map.
    // Key: callee name → Vec of (argument sources)
    let mut call_sites: HashMap<String, Vec<Vec<ArgumentSource>>> = HashMap::new();
    for (_, parsed) in parsed_files.iter() {
        for cs in &parsed.call_sites {
            call_sites
                .entry(cs.callee.clone())
                .or_default()
                .push(cs.arguments.clone());
        }
    }

    // Phase 3: Determine which functions have all-sanitized parameters per sink.
    // For each function with a definition AND call sites, check if every
    // call site passes values safe for each sink category. When a function is
    // proven safe for a (param, sink), record it; if ANY function in the
    // same file declaring that param is NOT proven safe, drop the
    // (param, sink) from the unambiguous-safe set (issue #33).
    let mut params_to_downgrade: Vec<(usize, String, String, SinkClass)> = Vec::new();

    for (func_name, defs) in &func_defs {
        let sites = match call_sites.get(func_name) {
            Some(s) if !s.is_empty() => s,
            _ => {
                // No discovered call sites. If exported, stay conservative.
                continue;
            }
        };

        for (file_idx, params, _is_exported) in defs {
            // Check each parameter position
            for (param_idx, param_name) in params.iter().enumerate() {
                for sink in [
                    SinkClass::Command,
                    SinkClass::FilePath,
                    SinkClass::NetworkUrl,
                    SinkClass::DynamicExec,
                ] {
                    if all_call_sites_safe_for_sink(sites, param_idx, sink) {
                        params_to_downgrade.push((
                            *file_idx,
                            param_name.clone(),
                            func_name.clone(),
                            sink,
                        ));
                    } else {
                        // This function is NOT safe for this (param, sink), so the
                        // param name is ambiguous within the file — remove it from
                        // the unambiguous-safe set so no sibling gets downgraded.
                        if let Some(set) = file_safe_param_sinks.get_mut(file_idx) {
                            set.remove(&(param_name.clone(), sink));
                        }
                    }
                }
            }
        }
    }

    // Phase 4: Downgrade operations in the target functions.
    // Scope guard (issue #33): only downgrade a (param, sink) that is in
    // the file's unambiguous-safe set — i.e. EVERY function in that file
    // declaring the param name was proven safe for that sink. If an unsafe
    // sibling shares the param name, the entry was removed in Phase 3 and
    // we leave the argument tainted.
    for (file_idx, param_name, func_name, sink) in &params_to_downgrade {
        let safe = file_safe_param_sinks
            .get(file_idx)
            .is_some_and(|set| set.contains(&(param_name.clone(), *sink)));
        if !safe {
            continue;
        }
        let (_, parsed) = &mut parsed_files[*file_idx];
        // Encode the exact sink this downgrade was proven safe for, so the
        // label round-trips through `sanitizer_allows_sink` and clears taint
        // for THIS sink only. A bare description would parse to no category and
        // resurface as a false positive now that detectors are sink-aware.
        let sanitizer_label = cross_file_sanitizer_label(*sink, func_name);

        let sanitized = ArgumentSource::Sanitized {
            sanitizer: sanitizer_label.clone(),
        };
        let mut local_downgraded = 0;

        match sink {
            SinkClass::Command => {
                for cmd in &mut parsed.commands {
                    if matches!(&cmd.command_arg, ArgumentSource::Parameter { name } if name == param_name)
                    {
                        cmd.command_arg = sanitized.clone();
                        downgraded_count += 1;
                        local_downgraded += 1;
                    }
                }
            }
            SinkClass::FilePath => {
                for op in &mut parsed.file_operations {
                    if matches!(&op.path_arg, ArgumentSource::Parameter { name } if name == param_name)
                    {
                        op.path_arg = sanitized.clone();
                        downgraded_count += 1;
                        local_downgraded += 1;
                    }
                }
            }
            SinkClass::NetworkUrl => {
                for op in &mut parsed.network_operations {
                    if matches!(&op.url_arg, ArgumentSource::Parameter { name } if name == param_name)
                    {
                        op.url_arg = sanitized.clone();
                        downgraded_count += 1;
                        local_downgraded += 1;
                    }
                }
            }
            SinkClass::DynamicExec => {
                for op in &mut parsed.dynamic_exec {
                    if matches!(&op.code_arg, ArgumentSource::Parameter { name } if name == param_name)
                    {
                        op.code_arg = sanitized.clone();
                        downgraded_count += 1;
                        local_downgraded += 1;
                    }
                }
            }
        }

        if local_downgraded > 0 && !sanitized_functions.contains(func_name) {
            sanitized_functions.push(func_name.clone());
        }
    }

    CrossFileResult {
        downgraded_count,
        sanitized_functions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::auto_detect_and_load;
    use crate::ir::execution_surface::{FileOpType, FileOperation};
    use crate::ir::SourceLocation;
    use crate::parser::{CallSite, FunctionDef};
    use crate::rules::{Finding, RuleEngine};

    fn loc(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from(file),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn fixture_findings(name: &str) -> Vec<Finding> {
        let fixture_path = PathBuf::from("tests/fixtures/mcp_servers").join(name);
        let engine = RuleEngine::new();

        auto_detect_and_load(&fixture_path, false)
            .unwrap_or_else(|err| panic!("failed to load fixture {name}: {err}"))
            .iter()
            .flat_map(|target| engine.run(target))
            .collect()
    }

    #[test]
    fn sanitizer_names_recognized() {
        assert!(is_sanitizer("validatePath"));
        assert!(is_sanitizer("path.resolve"));
        assert!(is_sanitizer("os.path.realpath"));
        assert!(!is_sanitizer("URL.parse"));
        assert!(is_sanitizer("parseInt"));
        assert!(!is_sanitizer("urlparse"));
        assert!(!is_sanitizer("sanitizeSecret"));
        assert!(is_sanitizer("validateUrl"));
        assert!(!is_sanitizer("processData"));
        assert!(!is_sanitizer("readFile"));
    }

    #[test]
    fn custom_validate_path_recognized() {
        assert!(is_sanitizer("validate_path"));
        assert!(is_sanitizer("validateUrl"));
        assert!(is_sanitizer("sanitizeCustomPath"));
    }

    #[test]
    fn redaction_helpers_recognized() {
        assert!(is_redaction_sanitizer("redactSecret"));
        assert!(is_redaction_sanitizer("redactSecrets"));
        assert!(is_redaction_sanitizer("redactToken"));
        assert!(is_redaction_sanitizer("redactCredentials"));
        assert!(is_redaction_sanitizer("maskSecret"));
        assert!(is_redaction_sanitizer("maskToken"));
        assert!(is_redaction_sanitizer("maskCredentials"));
        assert!(is_redaction_sanitizer("scrubSecret"));
        assert!(is_redaction_sanitizer("scrubToken"));
        assert!(is_redaction_sanitizer("scrubCredentials"));
        assert!(!is_sanitizer("redactSecret"));
    }

    #[test]
    fn cross_file_downgrade() {
        // File A (index.ts): calls readFileContent with sanitized arg
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "readFileContent".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            }],
            caller: Some("handleRead".into()),
            location: loc("index.ts", 5),
        });

        // File B (lib.ts): defines readFileContent, uses filePath param
        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "readFileContent".into(),
            params: vec!["filePath".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "filePath".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 1);
        assert_eq!(result.sanitized_functions, vec!["readFileContent"]);

        // Verify the operation was downgraded
        let lib_ops = &files[1].1.file_operations;
        assert!(!lib_ops[0].path_arg.is_tainted());
        assert!(matches!(
            &lib_ops[0].path_arg,
            ArgumentSource::Sanitized { .. }
        ));
    }

    #[test]
    fn redaction_sanitizers_do_not_downgrade_file_paths() {
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "logRedactedValues".into(),
            arguments: vec![
                ArgumentSource::Sanitized {
                    sanitizer: "redactSecret".into(),
                },
                ArgumentSource::Sanitized {
                    sanitizer: "maskToken".into(),
                },
                ArgumentSource::Sanitized {
                    sanitizer: "scrubCredentials".into(),
                },
            ],
            caller: Some("handleLog".into()),
            location: loc("index.ts", 8),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "logRedactedValues".into(),
            params: vec!["secret".into(), "token".into(), "credentials".into()],
            is_exported: true,
            location: loc("logger.ts", 1),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "secret".into(),
            },
            operation: FileOpType::Write,
            location: loc("logger.ts", 3),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "token".into(),
            },
            operation: FileOpType::Write,
            location: loc("logger.ts", 4),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "credentials".into(),
            },
            operation: FileOpType::Write,
            location: loc("logger.ts", 5),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("logger.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 0);
        assert!(result.sanitized_functions.is_empty());
        for op in &files[1].1.file_operations {
            assert!(
                op.path_arg.is_tainted(),
                "redaction-sanitized argument must not downgrade file paths"
            );
        }
    }

    #[test]
    fn url_parse_does_not_downgrade_network_sink() {
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "fetchRemote".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "URL.parse".into(),
            }],
            caller: Some("handler".into()),
            location: loc("index.ts", 5),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "fetchRemote".into(),
            params: vec!["url".into()],
            is_exported: true,
            location: loc("net.ts", 1),
        });
        file_b
            .network_operations
            .push(crate::ir::execution_surface::NetworkOperation {
                function: "fetch".into(),
                url_arg: ArgumentSource::Parameter { name: "url".into() },
                method: Some("GET".into()),
                sends_data: false,
                location: loc("net.ts", 3),
            });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("net.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 0);
        assert!(files[1].1.network_operations[0].url_arg.is_tainted());
    }

    #[test]
    fn url_parse_ssrf_fixture_still_flags_ssrf() {
        let findings = fixture_findings("vuln_url_parse_ssrf");

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-003"),
            "URL.parse fixture should still trigger SSRF: {findings:?}"
        );
    }

    #[test]
    fn redacted_file_access_fixture_still_flags_arbitrary_file_access() {
        let findings = fixture_findings("vuln_redacted_file_access");

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-004"),
            "redacted file path fixture should still trigger arbitrary file access: {findings:?}"
        );
    }

    #[test]
    fn wrong_category_sanitizer_does_not_suppress_file_sink() {
        // A network-category validator (validateUrl) applied to a value used as
        // a FILE PATH within the same function must NOT suppress SHIELD-004.
        let findings = fixture_findings("vuln_wrong_category_sanitizer");

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-004"),
            "a network validator on a file-path sink must still trigger arbitrary file access: {findings:?}"
        );
    }

    #[test]
    fn type_coercion_does_not_suppress_eval_sink() {
        // String()/str() coercion on an attacker value passed to eval must
        // still fire SHIELD-011 — coercion is the wrong sanitizer category for
        // a dynamic-exec sink and escapes nothing.
        let findings = fixture_findings("vuln_coercion_eval");

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "SHIELD-011"),
            "type coercion on an eval sink must still trigger dynamic exec: {findings:?}"
        );
    }

    #[test]
    fn type_coercion_is_not_a_command_sanitizer() {
        // str()/String() coercion is identity on a string and does not
        // neutralize shell metacharacters, so it must not be accepted as a
        // sanitizer for command or dynamic-exec sinks.
        let coerced = ArgumentSource::Sanitized {
            sanitizer: "type:str".into(),
        };
        assert!(
            !arg_safe_for_sink(&coerced, SinkClass::Command),
            "type coercion must not sanitize a command sink"
        );
        assert!(
            !arg_safe_for_sink(&coerced, SinkClass::DynamicExec),
            "type coercion must not sanitize a dynamic-exec sink"
        );
    }

    #[test]
    fn argument_source_is_tainted_for_sink_respects_category() {
        // A network-category sanitizer is safe for a network sink but tainted
        // for a file-path sink.
        let net = ArgumentSource::Sanitized {
            sanitizer: "network:validateUrl".into(),
        };
        assert!(!net.is_tainted_for_sink(SinkClass::NetworkUrl));
        assert!(net.is_tainted_for_sink(SinkClass::FilePath));

        let path = ArgumentSource::Sanitized {
            sanitizer: "path:validatePath".into(),
        };
        assert!(!path.is_tainted_for_sink(SinkClass::FilePath));
        assert!(path.is_tainted_for_sink(SinkClass::NetworkUrl));
    }

    #[test]
    fn no_downgrade_when_unsanitized_caller_exists() {
        // Two call sites: one safe, one tainted
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "readFile".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            }],
            caller: Some("safeHandler".into()),
            location: loc("safe.ts", 5),
        });
        file_a.call_sites.push(CallSite {
            callee: "readFile".into(),
            arguments: vec![ArgumentSource::Parameter {
                name: "userInput".into(),
            }],
            caller: Some("unsafeHandler".into()),
            location: loc("safe.ts", 10),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "readFile".into(),
            params: vec!["path".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "path".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![
            (PathBuf::from("safe.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 0);
        // Operation stays tainted
        assert!(files[1].1.file_operations[0].path_arg.is_tainted());
    }

    #[test]
    fn no_downgrade_for_exported_with_no_callers() {
        let mut file_a = ParsedFile::default();
        file_a.function_defs.push(FunctionDef {
            name: "dangerousFunc".into(),
            params: vec!["input".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_a.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "input".into(),
            },
            operation: FileOpType::Write,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![(PathBuf::from("lib.ts"), file_a)];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 0);
        assert!(files[0].1.file_operations[0].path_arg.is_tainted());
    }

    #[test]
    fn downgrade_only_matching_params() {
        // Function with 2 params, only first is always sanitized
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "copyFile".into(),
            arguments: vec![
                ArgumentSource::Sanitized {
                    sanitizer: "validatePath".into(),
                },
                ArgumentSource::Parameter {
                    name: "rawDest".into(),
                },
            ],
            caller: Some("handler".into()),
            location: loc("index.ts", 5),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "copyFile".into(),
            params: vec!["src".into(), "dest".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        // Two file operations, one per param
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter { name: "src".into() },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "dest".into(),
            },
            operation: FileOpType::Write,
            location: loc("lib.ts", 4),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(result.downgraded_count, 1); // Only src
        assert!(!files[1].1.file_operations[0].path_arg.is_tainted()); // src: safe
        assert!(files[1].1.file_operations[1].path_arg.is_tainted()); // dest: still tainted
    }

    #[test]
    fn unsafe_sibling_with_shared_param_stays_tainted() {
        // Issue #33: two functions in the same file share a param name
        // (`path`). `safeRead` is only ever called with a sanitized
        // value, but `rawRead` is called with a tainted parameter. The
        // unsafe sibling must NOT be downgraded even though the safe one
        // is.
        let mut file_a = ParsedFile::default();
        // safeRead is called with a sanitized path
        file_a.call_sites.push(CallSite {
            callee: "safeRead".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            }],
            caller: Some("handler".into()),
            location: loc("index.ts", 5),
        });
        // rawRead is called with a TAINTED parameter
        file_a.call_sites.push(CallSite {
            callee: "rawRead".into(),
            arguments: vec![ArgumentSource::Parameter {
                name: "path".into(),
            }],
            caller: Some("handler".into()),
            location: loc("index.ts", 9),
        });

        let mut file_b = ParsedFile::default();
        file_b.function_defs.push(FunctionDef {
            name: "safeRead".into(),
            params: vec!["path".into()],
            is_exported: true,
            location: loc("lib.ts", 1),
        });
        file_b.function_defs.push(FunctionDef {
            name: "rawRead".into(),
            params: vec!["path".into()],
            is_exported: true,
            location: loc("lib.ts", 10),
        });
        // safeRead's op (should downgrade)
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "path".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });
        // rawRead's op (must stay tainted)
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "path".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 12),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        // `path` is shared between a safe and an unsafe function in the
        // same file, so ownership is ambiguous. The conservative fix (issue
        // #33) refuses to downgrade either, which correctly keeps the
        // unsafe sibling's operation tainted (no false negative).
        assert_eq!(result.downgraded_count, 0);
        assert!(files[1].1.file_operations[0].path_arg.is_tainted()); // safeRead: stays tainted (ambiguous)
        assert!(files[1].1.file_operations[1].path_arg.is_tainted()); // rawRead: stays tainted (unsafe sibling protected)
    }
}
