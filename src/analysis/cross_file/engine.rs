use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::ir::{ArgumentSource, SinkClass};
use crate::parser::ParsedFile;

use super::sink_policy::{all_call_sites_safe_for_sink, cross_file_sanitizer_label};

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
        let has_cmd = !parsed.commands.is_empty();
        let has_file = !parsed.file_operations.is_empty();
        let has_net = !parsed.network_operations.is_empty();
        let has_exec = !parsed.dynamic_exec.is_empty();

        for def in &parsed.function_defs {
            for param in &def.params {
                if has_cmd {
                    file_safe_param_sinks
                        .entry(idx)
                        .or_default()
                        .insert((param.clone(), SinkClass::Command));
                }
                if has_file {
                    file_safe_param_sinks
                        .entry(idx)
                        .or_default()
                        .insert((param.clone(), SinkClass::FilePath));
                }
                if has_net {
                    file_safe_param_sinks
                        .entry(idx)
                        .or_default()
                        .insert((param.clone(), SinkClass::NetworkUrl));
                }
                if has_exec {
                    file_safe_param_sinks
                        .entry(idx)
                        .or_default()
                        .insert((param.clone(), SinkClass::DynamicExec));
                }
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
                // No discovered call sites. Uncalled functions must invalidate
                // unambiguous safety for their params within their declaring files
                // so no unsafe sibling sharing the param name gets downgraded.
                for (file_idx, params, _) in defs {
                    if let Some(set) = file_safe_param_sinks.get_mut(file_idx) {
                        for param in params {
                            set.remove(&(param.clone(), SinkClass::Command));
                            set.remove(&(param.clone(), SinkClass::FilePath));
                            set.remove(&(param.clone(), SinkClass::NetworkUrl));
                            set.remove(&(param.clone(), SinkClass::DynamicExec));
                        }
                    }
                }
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

    // Sort params_to_downgrade deterministically
    params_to_downgrade.sort();

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

    sanitized_functions.sort();

    CrossFileResult {
        downgraded_count,
        sanitized_functions,
    }
}
