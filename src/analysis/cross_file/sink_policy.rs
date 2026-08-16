use super::sanitizer::{SanitizerCategory, sanitizer_category};
use crate::ir::{ArgumentSource, SinkClass};

/// Prefix marking a cross-file downgrade label, followed by the exact sink it
/// was proven safe for. Unlike a named sanitizer (which protects a whole
/// category), a cross-file downgrade is proven safe for precisely one sink, so
/// the sink is encoded directly and matched back in [`sanitizer_allows_sink`].
const CROSS_FILE_SANITIZER_PREFIX: &str = "crossfile";

pub(super) fn cross_file_sanitizer_label(sink: SinkClass, func_name: &str) -> String {
    let sink_tag = match sink {
        SinkClass::Command => "command",
        SinkClass::FilePath => "filepath",
        SinkClass::NetworkUrl => "networkurl",
        SinkClass::DynamicExec => "dynamicexec",
    };
    format!("{CROSS_FILE_SANITIZER_PREFIX}:{sink_tag}:caller passes sanitized value to {func_name}")
}

pub(super) fn cross_file_sink(sanitizer: &str) -> Option<SinkClass> {
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

pub(super) fn arg_safe_for_sink(arg: &ArgumentSource, sink: SinkClass) -> bool {
    !arg.is_tainted_for_sink(sink)
}

pub(super) fn all_call_sites_safe_for_sink(
    sites: &[Vec<ArgumentSource>],
    param_idx: usize,
    sink: SinkClass,
) -> bool {
    sites.iter().all(|args| {
        args.get(param_idx)
            .is_some_and(|arg| arg_safe_for_sink(arg, sink))
    })
}

/// Whether `sanitizer` neutralizes taint for `sink`.
///
/// Each sanitizer category protects only its own sink family. Type coercion
/// (`str()`/`Number()`) is identity on a string and is NOT accepted for any
/// injection sink — it neither escapes shell metacharacters nor constrains a
/// path or URL. Redaction sanitizers protect no input sink (only credential/log
/// leakage analysis), so they are absent here.
pub fn sanitizer_allows_sink(sanitizer: &str, sink: SinkClass) -> bool {
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
