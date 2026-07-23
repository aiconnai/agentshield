pub(crate) mod composite_flow;
pub mod cross_file;
pub(crate) mod runtime_install;
pub(crate) mod sensitivity;

use crate::ir::ScanTarget;

use self::composite_flow::CompositeFlowCandidate;

/// Internal analysis bundle emitted by adapter pipeline and consumed by
/// contextual detectors.
///
/// This remains crate-private and is never serialized.
#[derive(Debug)]
pub(crate) struct AnalysisBundle {
    pub target: ScanTarget,
    pub composite_flows: Vec<CompositeFlowCandidate>,
}

/// Input passed to contextual detectors.
#[derive(Debug)]
pub(crate) struct DetectionInput<'a> {
    pub target: &'a ScanTarget,
    pub composite_flows: &'a [CompositeFlowCandidate],
}
