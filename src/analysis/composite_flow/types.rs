use std::path::{Path, PathBuf};

use crate::ir::SourceLocation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId {
    pub relative_file: PathBuf,
    pub lexical_owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefinitionId {
    pub scope: ScopeId,
    pub definition_span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueId {
    pub definition: DefinitionId,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FlowEdgeKind {
    ControlsFilePath,
    ProducesFileContent,
    Propagates,
    EntersNetworkPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    pub kind: FlowEdgeKind,
    pub input: ValueId,
    pub output: ValueId,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticAnchor {
    pub relative_file: PathBuf,
    pub lexical_owner: String,
    pub operation_kind: &'static str,
    pub resolved_api: &'static str,
    pub normalized_subtree_hash: String,
    pub identical_ordinal: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeFlowCandidate {
    pub tool_name: String,
    pub source_location: SourceLocation,
    pub sink_location: SourceLocation,
    pub source_anchor: SemanticAnchor,
    pub sink_anchor: SemanticAnchor,
    pub edges: Vec<FlowEdge>,
    pub observation_complete: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SourceUnit<'a> {
    pub path: &'a Path,
    pub content: &'a str,
}

#[derive(Debug, Clone)]
pub struct ToolFlowInput {
    pub tool_name: String,
    pub handler: SourceLocation,
}
