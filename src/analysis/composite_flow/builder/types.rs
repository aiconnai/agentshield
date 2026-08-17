use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Tree};

use crate::ir::SourceLocation;

use super::super::types::{ByteSpan, FlowEdge, ValueId};

pub(crate) struct ParsedUnit<'a> {
    pub(crate) path: &'a Path,
    pub(crate) content: &'a str,
    pub(crate) tree: Tree,
    pub(crate) imports: Imports,
}

#[derive(Default)]
pub(crate) struct Imports {
    pub(crate) fs_read_functions: BTreeSet<String>,
    pub(crate) fs_namespaces: BTreeSet<String>,
    pub(crate) axios_names: BTreeSet<String>,
    pub(crate) local_functions: BTreeMap<String, RelativeImport>,
}

#[derive(Clone)]
pub(crate) struct RelativeImport {
    pub(crate) module: String,
    pub(crate) exported: String,
}

#[derive(Clone)]
pub(crate) struct Lineage {
    pub(crate) value: ValueId,
    pub(crate) tool_argument: ValueId,
    pub(crate) source_location: SourceLocation,
    pub(crate) edges: Vec<FlowEdge>,
    pub(crate) is_file_content: bool,
    pub(crate) source_anchor: Option<AnchorSeed>,
}

pub(crate) struct Analyzer<'a> {
    pub(crate) units: &'a [ParsedUnit<'a>],
    pub(crate) tool_name: &'a str,
    pub(crate) anchor_ordinals: BTreeMap<AnchorKey, usize>,
    pub(crate) anchor_instances: BTreeMap<AnchorSeed, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AnchorKey {
    pub(crate) file: PathBuf,
    pub(crate) owner: String,
    pub(crate) operation: &'static str,
    pub(crate) api: &'static str,
    pub(crate) hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AnchorSeed {
    pub(crate) key: AnchorKey,
    pub(crate) occurrence: ByteSpan,
}

pub(crate) struct FunctionMatch<'tree> {
    pub(crate) unit_index: usize,
    pub(crate) node: Node<'tree>,
    pub(crate) owner: String,
}
