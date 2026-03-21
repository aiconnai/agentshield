//! Egress policy module for runtime network enforcement.
//!
//! Defines the schema for `agentshield.egress.toml` policy files,
//! which control outbound network access from wrapped agent processes.

pub mod policy;
#[cfg(feature = "runtime")]
pub mod proxy;
