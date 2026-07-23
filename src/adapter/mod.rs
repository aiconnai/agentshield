pub mod crewai;
pub mod cursor_rules;
pub mod gpt_actions;
pub mod hermes;
pub mod langchain;
pub mod mcp;
pub(super) mod mcp_metadata;
pub mod openclaw;
mod pipeline;

use std::path::Path;

use crate::analysis::AnalysisBundle;
use crate::config::ScanPathFilter;
use crate::error::{Result, ShieldError};
use crate::ir::{Framework, ScanTarget};

/// Contextual analysis adapters load both public IR and non-serialized sidecar
/// data needed by future context-dependent detectors.
pub(crate) trait AnalysisAdapter: Send + Sync {
    /// The framework this adapter handles.
    fn framework(&self) -> Framework;

    /// Check if this adapter can handle the given directory.
    fn detect(&self, root: &Path) -> bool;

    /// Load analysis bundles from the directory.
    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>>;
}

/// An adapter detects a specific agent framework and loads its artifacts
/// into the unified IR.
pub trait Adapter: Send + Sync {
    /// The framework this adapter handles.
    fn framework(&self) -> Framework;

    /// Check if this adapter can handle the given directory.
    fn detect(&self, root: &Path) -> bool;

    /// Load artifacts from the directory into scan targets.
    /// When `ignore_tests` is true, test files are excluded before parsing.
    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>>;

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        self.load(root, filter.ignore_tests())
    }
}

/// All registered adapters.
#[derive(Copy, Clone)]
enum AdapterSpec {
    Mcp,
    OpenClaw,
    Hermes,
    CrewAi,
    LangChain,
    GptActions,
    CursorRules,
}

impl AdapterSpec {
    fn public(self) -> Box<dyn Adapter> {
        match self {
            Self::Mcp => Box::new(mcp::McpAdapter),
            Self::OpenClaw => Box::new(openclaw::OpenClawAdapter),
            Self::Hermes => Box::new(hermes::HermesAgentAdapter),
            Self::CrewAi => Box::new(crewai::CrewAiAdapter),
            Self::LangChain => Box::new(langchain::LangChainAdapter),
            Self::GptActions => Box::new(gpt_actions::GptActionsAdapter),
            Self::CursorRules => Box::new(cursor_rules::CursorRulesAdapter),
        }
    }

    fn analysis(self) -> Box<dyn AnalysisAdapter> {
        match self {
            Self::Mcp => Box::new(mcp::McpAnalysisAdapter),
            Self::OpenClaw => Box::new(legacy_analysis_adapter(openclaw::OpenClawAdapter)),
            Self::Hermes => Box::new(legacy_analysis_adapter(hermes::HermesAgentAdapter)),
            Self::CrewAi => Box::new(legacy_analysis_adapter(crewai::CrewAiAdapter)),
            Self::LangChain => Box::new(legacy_analysis_adapter(langchain::LangChainAdapter)),
            Self::GptActions => Box::new(legacy_analysis_adapter(gpt_actions::GptActionsAdapter)),
            Self::CursorRules => {
                Box::new(legacy_analysis_adapter(cursor_rules::CursorRulesAdapter))
            }
        }
    }
}

fn analysis_adapters() -> &'static [AdapterSpec] {
    use std::sync::OnceLock;

    static ADAPTERS: OnceLock<[AdapterSpec; 7]> = OnceLock::new();
    ADAPTERS.get_or_init(|| {
        [
            AdapterSpec::Mcp,
            AdapterSpec::OpenClaw,
            AdapterSpec::Hermes,
            AdapterSpec::CrewAi,
            AdapterSpec::LangChain,
            AdapterSpec::GptActions,
            AdapterSpec::CursorRules,
        ]
    })
}

#[derive(Debug)]
struct LegacyAnalysisAdapter<A: Adapter>(A);

impl<A: Adapter> AnalysisAdapter for LegacyAnalysisAdapter<A> {
    fn framework(&self) -> Framework {
        self.0.framework()
    }

    fn detect(&self, root: &Path) -> bool {
        self.0.detect(root)
    }

    fn load_analysis_with_filter(
        &self,
        root: &Path,
        filter: &ScanPathFilter,
    ) -> Result<Vec<AnalysisBundle>> {
        let targets = self.0.load_with_filter(root, filter)?;
        Ok(targets
            .into_iter()
            .map(|target| AnalysisBundle {
                target,
                composite_flows: Vec::new(),
            })
            .collect())
    }
}

fn legacy_analysis_adapter<A>(adapter: A) -> impl AnalysisAdapter
where
    A: Adapter + 'static + Send + Sync,
{
    LegacyAnalysisAdapter(adapter)
}

pub(crate) fn all_analysis_adapters() -> Vec<Box<dyn AnalysisAdapter>> {
    analysis_adapters()
        .iter()
        .map(|spec| spec.analysis())
        .collect()
}

pub(crate) fn all_adapters() -> Vec<Box<dyn Adapter>> {
    analysis_adapters()
        .iter()
        .map(|spec| spec.public())
        .collect()
}

/// Auto-detect all matching frameworks and load scan targets from each.
///
/// Repos may contain both MCP and OpenClaw artifacts — all matching
/// adapters contribute targets rather than stopping at the first match.
pub fn auto_detect_and_load(root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
    let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
    auto_detect_and_load_with_filter(root, &filter)
}

pub fn auto_detect_and_load_with_filter(
    root: &Path,
    filter: &ScanPathFilter,
) -> Result<Vec<ScanTarget>> {
    let adapters = all_adapters();
    let mut all_targets = Vec::new();

    for adapter in &adapters {
        if adapter.detect(root) {
            match adapter.load_with_filter(root, filter) {
                Ok(targets) => all_targets.extend(targets),
                Err(e) => {
                    tracing::warn!(
                        framework = %adapter.framework(),
                        error = %e,
                        "adapter failed to load, skipping"
                    );
                }
            }
        }
    }

    if all_targets.is_empty() {
        return Err(ShieldError::NoAdapter(root.display().to_string()));
    }

    Ok(all_targets)
}

pub(crate) fn auto_detect_analysis_with_filter(
    root: &Path,
    filter: &ScanPathFilter,
) -> Result<Vec<AnalysisBundle>> {
    let adapters = all_analysis_adapters();
    let mut all_bundles = Vec::new();

    for adapter in &adapters {
        if adapter.detect(root) {
            match adapter.load_analysis_with_filter(root, filter) {
                Ok(bundles) => all_bundles.extend(bundles),
                Err(e) => {
                    tracing::warn!(
                        framework = %adapter.framework(),
                        error = %e,
                        "analysis adapter failed to load, skipping"
                    );
                }
            }
        }
    }

    if all_bundles.is_empty() {
        return Err(ShieldError::NoAdapter(root.display().to_string()));
    }

    Ok(all_bundles)
}

#[cfg(test)]
mod tests {
    use super::all_adapters;
    use super::all_analysis_adapters;

    #[test]
    fn adapter_registries_stay_in_sync() {
        let public = all_adapters();
        let analysis = all_analysis_adapters();
        assert_eq!(public.len(), analysis.len());
        assert!(public
            .iter()
            .zip(analysis.iter())
            .all(|(a, b)| a.framework() == b.framework()));
    }
}
