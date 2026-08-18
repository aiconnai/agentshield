pub(crate) mod binding;
pub(crate) mod dependencies;
pub(crate) mod filter;
pub(crate) mod loader;
pub(crate) mod provenance;
pub(crate) mod tools;

#[cfg(test)]
mod tests;

use std::path::Path;

use crate::analysis::AnalysisBundle;
use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::*;
#[cfg(test)]
use crate::parser;

pub use dependencies::parse_dependencies;
pub use filter::is_test_file;
pub use provenance::parse_provenance;

pub(crate) use loader::{
    collect_source_files_with_filter, has_recursive_python_import, load_mcp_analysis,
    load_mcp_target,
};

#[cfg(test)]
use binding::bind_mcp_tool_operations;
#[cfg(test)]
use tools::{
    McpToolHandler, extract_mcp_tool_declarations_from_source, extract_mcp_tools_from_source,
    parse_mcp_tool_handler,
};

/// MCP Server adapter.
///
/// Detects MCP servers by looking for:
/// - package.json with dependencies
/// - Python files importing FastMCP or mcp.server
/// - mcp.json / mcp-config.json manifest
pub struct McpAdapter;

impl super::Adapter for McpAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        load_mcp_target(root, filter).map(|(target, _)| vec![target])
    }
}

impl super::AnalysisAdapter for McpAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>> {
        load_mcp_analysis(root, filter)
    }
}

pub(crate) struct McpAnalysisAdapter;

impl super::AnalysisAdapter for McpAnalysisAdapter {
    fn framework(&self) -> Framework {
        Framework::Mcp
    }

    fn detect(&self, root: &Path) -> bool {
        super::mcp_metadata::metadata_root_for_scan(root).is_some()
    }

    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>> {
        load_mcp_analysis(root, filter)
    }
}
