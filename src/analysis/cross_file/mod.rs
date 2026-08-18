//! Cross-file sanitizer-aware validation tracking.
//!
//! Runs after parsing, before detection. When a function is only ever called
//! with sanitized arguments, downgrades its parameters'  from
//! tainted to . This eliminates false positives from internal
//! helper functions that receive already-validated input from their callers.

pub(crate) mod engine;
mod sanitizer;
mod sink_policy;

pub use engine::{apply_cross_file_sanitization, CrossFileResult};
#[allow(unused_imports)]
pub(crate) use sanitizer::{
    SanitizerCategory, is_redaction_sanitizer, is_sanitizer, sanitizer_category, sanitizer_label,
};
pub use sink_policy::sanitizer_allows_sink;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::ir::{ArgumentSource, SinkClass};
    use crate::parser::ParsedFile;
    use crate::adapter::auto_detect_and_load;
    use crate::analysis::cross_file::sanitizer::{is_redaction_sanitizer, is_sanitizer};
    use crate::ir::SourceLocation;
    use crate::ir::execution_surface::{FileOpType, FileOperation};
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
            !sink_policy::arg_safe_for_sink(&coerced, SinkClass::Command),
            "type coercion must not sanitize a command sink"
        );
        assert!(
            !sink_policy::arg_safe_for_sink(&coerced, SinkClass::DynamicExec),
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

    #[test]
    fn uncalled_sibling_with_shared_param_stays_tainted() {
        // Uncalled/exported function sharing a parameter name with a called safe function
        // in the same file must NOT have its operations downgraded.
        let mut file_a = ParsedFile::default();
        file_a.call_sites.push(CallSite {
            callee: "internalRead".into(),
            arguments: vec![ArgumentSource::Sanitized {
                sanitizer: "validatePath".into(),
            }],
            caller: Some("handler".into()),
            location: loc("index.ts", 5),
        });

        let mut file_b = ParsedFile::default();
        // internalRead is called safely
        file_b.function_defs.push(FunctionDef {
            name: "internalRead".into(),
            params: vec!["path".into()],
            is_exported: false,
            location: loc("lib.ts", 1),
        });
        // exportRead has ZERO discovered call sites (uncalled)
        file_b.function_defs.push(FunctionDef {
            name: "exportRead".into(),
            params: vec!["path".into()],
            is_exported: true,
            location: loc("lib.ts", 10),
        });
        file_b.file_operations.push(FileOperation {
            path_arg: ArgumentSource::Parameter {
                name: "path".into(),
            },
            operation: FileOpType::Read,
            location: loc("lib.ts", 3),
        });

        let mut files = vec![
            (PathBuf::from("index.ts"), file_a),
            (PathBuf::from("lib.ts"), file_b),
        ];

        let result = apply_cross_file_sanitization(&mut files);

        assert_eq!(
            result.downgraded_count, 0,
            "uncalled sibling with shared param must invalidate unambiguous safety"
        );
        assert!(files[1].1.file_operations[0].path_arg.is_tainted());
    }
}
