use crate::ir::data_surface::{TaintSink, TaintSinkType};
use crate::ir::execution_surface::{ExecutionSurface, FileOpType};

/// Collect taint sinks from execution surface operations.
pub(crate) fn collect_sinks(execution: &ExecutionSurface) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    for cmd in &execution.commands {
        sinks.push(TaintSink {
            sink_type: TaintSinkType::ProcessExec,
            description: format!("Process execution via {}", cmd.function),
            location: cmd.location.clone(),
        });
    }

    for net in &execution.network_operations {
        sinks.push(TaintSink {
            sink_type: TaintSinkType::HttpRequest,
            description: format!("HTTP request via {}", net.function),
            location: net.location.clone(),
        });
    }

    for file_op in &execution.file_operations {
        if matches!(file_op.operation, FileOpType::Write) {
            sinks.push(TaintSink {
                sink_type: TaintSinkType::FileWrite,
                description: "File write operation".to_string(),
                location: file_op.location.clone(),
            });
        }
    }

    for dyn_exec in &execution.dynamic_exec {
        sinks.push(TaintSink {
            sink_type: TaintSinkType::DynamicEval,
            description: format!("Dynamic code execution via {}", dyn_exec.function),
            location: dyn_exec.location.clone(),
        });
    }

    sinks
}
