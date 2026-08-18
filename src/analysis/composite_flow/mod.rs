//! Crate-private value-flow graph construction for composite findings.
//!
//! This module deliberately does not register a detector or add fields to the
//! serialized IR. It proves the C.0 contracts needed by SHIELD-020 while the
//! detector transport decision remains a separate API review.
// C.0 module intentionally remains test-only until C.1 chooses detector transport.
#![cfg_attr(
    not(feature = "typescript"),
    expect(
        dead_code,
        reason = "composite-flow types are exercised by the TypeScript analyzer only"
    )
)]

pub(crate) mod ast;
pub(crate) mod builder;
pub(crate) mod guard;
pub(crate) mod types;

#[cfg(test)]
mod tests;

pub use types::*;

#[cfg(feature = "typescript")]
pub(crate) fn build_composite_flow_candidates(
    tools: &[ToolFlowInput],
    sources: &[SourceUnit<'_>],
) -> Vec<CompositeFlowCandidate> {
    builder::build(tools, sources)
}

#[cfg(not(feature = "typescript"))]
pub(crate) fn build_composite_flow_candidates(
    _tools: &[ToolFlowInput],
    _sources: &[SourceUnit<'_>],
) -> Vec<CompositeFlowCandidate> {
    Vec::new()
}
