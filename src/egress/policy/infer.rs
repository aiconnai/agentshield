use std::collections::HashSet;

use crate::ir::ArgumentSource;
use crate::ir::ScanTarget;
use crate::ir::tool_surface::PermissionType;

use super::domain::{self, DomainPolicy};
use super::merge::{AuditPolicy, RateLimitPolicy};
use super::network::NetworkPolicy;
use super::types::{EgressPolicy, CURRENT_SCHEMA_VERSION};

/// Build a starter egress policy by analyzing all `ScanTarget`s.
///
/// Extracts domains from:
/// - Literal URL arguments in `NetworkOperation` entries
/// - `NetworkAccess` declared permissions with a scope/target URL or domain
///
/// The resulting policy allows all discovered domains and uses safe defaults
/// for network-level blocking and rate limiting.
pub(crate) fn from_scan_targets(targets: &[ScanTarget]) -> EgressPolicy {
    let mut domains = HashSet::new();

    for target in targets {
        // Extract domains from network operations with literal URLs
        for net_op in &target.execution.network_operations {
            if let ArgumentSource::Literal(ref url) = net_op.url_arg {
                if let Some(domain) = domain::extract_domain(url) {
                    domains.insert(domain);
                }
            }
        }

        // Extract domains from tool declared permissions (NetworkAccess)
        for tool in &target.tools {
            for perm in &tool.declared_permissions {
                if matches!(perm.permission_type, PermissionType::NetworkAccess) {
                    if let Some(ref scope) = perm.target {
                        if let Some(domain) = domain::extract_domain(scope) {
                            domains.insert(domain);
                        }
                    }
                }
            }
        }
    }

    let mut allow: Vec<String> = domains.into_iter().collect();
    allow.sort();

    EgressPolicy {
        schema_version: CURRENT_SCHEMA_VERSION,
        domains: DomainPolicy {
            allow,
            deny: vec![],
        },
        networks: NetworkPolicy::default(),
        rate_limits: RateLimitPolicy::default(),
        audit: AuditPolicy::default(),
    }
}
