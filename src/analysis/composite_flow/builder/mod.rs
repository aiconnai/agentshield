use std::collections::BTreeMap;

use super::ast::function_name;
use super::types::{CompositeFlowCandidate, SourceUnit, ToolFlowInput};

pub(crate) mod anchors;
pub(crate) mod parse;
pub(crate) mod trace;
pub(crate) mod types;

pub(crate) use parse::{find_node_for_location, parse_units};
pub(crate) use types::{Analyzer, ParsedUnit};

pub(crate) fn build(
    tools: &[ToolFlowInput],
    sources: &[SourceUnit<'_>],
) -> Vec<CompositeFlowCandidate> {
    let units = parse_units(sources);
    let mut candidates = Vec::new();

    for tool in tools {
        let Some((unit_index, handler)) = find_node_for_location(&units, &tool.handler) else {
            continue;
        };
        let owner = function_name(handler, units[unit_index].content)
            .unwrap_or_else(|| format!("<inline:{}>", handler.start_byte()));
        let mut analyzer = Analyzer {
            units: &units,
            tool_name: &tool.tool_name,
            anchor_ordinals: BTreeMap::new(),
            anchor_instances: BTreeMap::new(),
        };
        candidates.extend(analyzer.analyze_function(unit_index, handler, owner, None, 0));
    }

    candidates.sort_by(|left, right| {
        (
            &left.tool_name,
            &left.source_location.file,
            left.source_location.line,
            left.source_location.column,
            &left.sink_location.file,
            left.sink_location.line,
            left.sink_location.column,
        )
            .cmp(&(
                &right.tool_name,
                &right.source_location.file,
                right.source_location.line,
                right.source_location.column,
                &right.sink_location.file,
                right.sink_location.line,
                right.sink_location.column,
            ))
    });
    candidates
}
