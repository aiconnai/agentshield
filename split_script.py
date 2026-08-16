import os
import re
import sys

def read_file(path):
    with open(path, "r") as f:
        return f.read()

def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

egress_rs = read_file("src/egress/policy.rs")

def extract(regex, s):
    m = re.search(regex, s, re.DOTALL)
    if not m:
        raise Exception(f"Regex {regex} not found")
    return m.group(1)

# Extract parts for domain.rs
domain_policy = extract(r'(/// Domain-level allow/deny policy.*?})\n\n', egress_rs)
is_domain_allowed = extract(r'(    /// Check if a domain is allowed by this policy\..*?    })\n', egress_rs)
is_domain_allowed = "\n".join(line[4:] if line.startswith("    ") else line for line in is_domain_allowed.split("\n"))
is_domain_allowed = is_domain_allowed.replace("pub fn", "pub(crate) fn").replace("self.domains.", "self.")
extract_domain = extract(r'(/// Extract the hostname from a URL string or bare domain\..*?})\n\n', egress_rs)
extract_domain = extract_domain.replace("pub fn", "pub(crate) fn")
domain_matches = extract(r'(/// Simple glob matching for domain patterns\..*?})\n\n', egress_rs)
domain_matches = domain_matches.replace("fn domain_matches", "pub(crate) fn domain_matches")

domain_rs = f"""use serde::{{Deserialize, Serialize}};

{domain_policy}

impl DomainPolicy {{
{is_domain_allowed}
}}

{domain_matches}

{extract_domain}
"""

# Extract parts for network.rs
network_policy = extract(r'(/// Network-level IP range blocking policy\..*?})\n\n', egress_rs)
default_true = extract(r'(fn default_true\(\) -> bool \{\n    true\n})\n', egress_rs)
impl_default_network = extract(r'(impl Default for NetworkPolicy \{.*?})\n\n', egress_rs)
is_ip_blocked = extract(r'(    /// Check if an IP address is blocked by network policy\..*?    })\n', egress_rs)
is_ip_blocked = "\n".join(line[4:] if line.startswith("    ") else line for line in is_ip_blocked.split("\n"))
is_ip_blocked = is_ip_blocked.replace("pub fn", "pub(crate) fn").replace("self.networks.", "self.")

is_localhost = extract(r'(fn is_localhost.*?})\n\n', egress_rs).replace("fn is_localhost", "pub(crate) fn is_localhost")
is_private_ip = extract(r'(fn is_private_ip.*?})\n\n', egress_rs).replace("fn is_private_ip", "pub(crate) fn is_private_ip")
is_172_private = extract(r'(fn is_172_private.*?})\n\n', egress_rs).replace("fn is_172_private", "pub(crate) fn is_172_private")
is_link_local = extract(r'(fn is_link_local.*?})\n\n', egress_rs).replace("fn is_link_local", "pub(crate) fn is_link_local")
is_metadata_ip = extract(r'(fn is_metadata_ip.*?})\n', egress_rs).replace("fn is_metadata_ip", "pub(crate) fn is_metadata_ip")

network_rs = f"""use serde::{{Deserialize, Serialize}};

{network_policy}

{default_true}

{impl_default_network}

impl NetworkPolicy {{
{is_ip_blocked}
}}

{is_localhost}

{is_private_ip}

{is_172_private}

{is_link_local}

{is_metadata_ip}
"""

# Extract parts for merge.rs
rate_limit_policy = extract(r'(/// Rate limiting configuration for outbound requests\..*?})\n\n', egress_rs)
default_rate_limit = extract(r'(fn default_rate_limit\(\) -> u32 \{\n    60\n})\n', egress_rs)
impl_default_rate = extract(r'(impl Default for RateLimitPolicy \{.*?})\n\n', egress_rs)
rate_limit_for = extract(r'(    /// Get rate limit for a domain \(requests per minute\)\..*?    })\n', egress_rs)
rate_limit_for = "\n".join(line[4:] if line.startswith("    ") else line for line in rate_limit_for.split("\n"))
rate_limit_for = rate_limit_for.replace("pub fn", "pub(crate) fn").replace("self.rate_limits.", "self.")

audit_policy = extract(r'(/// Audit logging configuration for egress events\..*?})\n\n', egress_rs)
default_log_format = extract(r'(fn default_log_format\(\) -> String \{\n    "json"\.to_string\(\)\n})\n', egress_rs)
impl_default_audit = extract(r'(impl Default for AuditPolicy \{.*?})\n\n', egress_rs)

merge_override = extract(r'(    /// Merge with an operator override policy\..*?    })\n', egress_rs)
merge_override = "\n".join(line[4:] if line.startswith("    ") else line for line in merge_override.split("\n"))
merge_override = merge_override.replace("pub fn merge_override(&self, operator: &EgressPolicy) -> EgressPolicy", "pub(crate) fn merge_override(base: &EgressPolicy, operator: &EgressPolicy) -> EgressPolicy")
merge_override = merge_override.replace("self.", "base.")

merge_rs = f"""use std::collections::HashMap;
use std::path::PathBuf;
use serde::{{Deserialize, Serialize}};

use super::{{EgressPolicy, DomainPolicy, NetworkPolicy}};
use super::domain::domain_matches;

{rate_limit_policy}

{default_rate_limit}

{impl_default_rate}

impl RateLimitPolicy {{
{rate_limit_for}
}}

{audit_policy}

{default_log_format}

{impl_default_audit}

{merge_override}
"""

# Extract parts for mod.rs
egress_struct = extract(r'(/// Top-level egress policy loaded from `agentshield\.egress\.toml`\..*?})\n\n', egress_rs)
load_func = extract(r'(    /// Load an egress policy from a TOML file\..*?    })\n', egress_rs)
save_func = extract(r'(    /// Save an egress policy to a TOML file\..*?    })\n', egress_rs)
from_scan_targets = extract(r'(    /// Build a starter egress policy by analyzing all `ScanTarget`s\..*?    })\n', egress_rs)
# add module imports to from_scan_targets
from_scan_targets = from_scan_targets.replace("extract_domain(", "domain::extract_domain(")
starter_toml = extract(r'(    /// Generate a starter policy TOML string for `agentshield init --egress`\..*?    })\n', egress_rs)
tests_block = extract(r'(#\[cfg\(test\)\]\nmod tests \{.*)', egress_rs)

mod_rs = f"""//! Egress policy schema and validation.
//!
//! Parses `agentshield.egress.toml` files that define which domains,
//! IPs, and rate limits are enforced by the `wrap` command proxy.

pub mod domain;
pub mod merge;
pub mod network;

pub use domain::DomainPolicy;
pub use merge::{{AuditPolicy, RateLimitPolicy}};
pub use network::NetworkPolicy;

use serde::{{Deserialize, Serialize}};
use std::path::Path;

use crate::error::ShieldError;
use crate::ir::ScanTarget;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 1;

{egress_struct}

impl EgressPolicy {{
{load_func}

{save_func}

    /// Check if a domain is allowed by this policy.
    ///
    /// Deny rules take precedence over allow rules. If the allow list is
    /// empty, all domains not explicitly denied are allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {{
        self.domains.is_domain_allowed(domain)
    }}

    /// Check if an IP address is blocked by network policy.
    pub fn is_ip_blocked(&self, ip: &str) -> bool {{
        self.networks.is_ip_blocked(ip)
    }}

    /// Get rate limit for a domain (requests per minute).
    ///
    /// Returns the per-domain override if one exists, otherwise the global default.
    pub fn rate_limit_for(&self, domain: &str) -> u32 {{
        self.rate_limits.rate_limit_for(domain)
    }}

{from_scan_targets}

    /// Merge with an operator override policy. The override can only restrict, never expand.
    ///
    /// Merge rules:
    /// - `domains.allow` = intersection(self.allow, override.allow)
    ///   If override.allow is empty, self.allow is kept (empty means "no restriction").
    ///   If self.allow is empty (allow all), operator's allow list becomes the effective list.
    /// - `domains.deny` = union(self.deny, override.deny)
    /// - `networks`: if either policy blocks a range, it is blocked in the result
    /// - `rate_limits.max_requests_per_minute` = min(self, override)
    /// - `rate_limits.per_domain`: min rate per domain; missing entries inherit the global min
    /// - `audit`: operator override wins (operator controls where logs go)
    pub fn merge_override(&self, operator: &EgressPolicy) -> EgressPolicy {{
        merge::merge_override(self, operator)
    }}

{starter_toml}
}}

{tests_block}
"""

write_file("src/egress/policy/domain.rs", domain_rs)
write_file("src/egress/policy/network.rs", network_rs)
write_file("src/egress/policy/merge.rs", merge_rs)
write_file("src/egress/policy/mod.rs", mod_rs)
os.remove("src/egress/policy.rs")

################################################################
# Now parser/python
python_rs = read_file("src/parser/python.rs")

# Extract parts for patterns.rs
patterns_block = extract(r'(// Dangerous subprocess/exec functions.*?)\n// Regex to find function definitions and their parameters', python_rs)
# We need to include FUNC_DEF_RE and SANITIZER_ASSIGN_RE which are just below
func_def_re = extract(r'(// Regex to find function definitions and their parameters\n.*?)\n// Sanitizer assignment:', python_rs)
sanitizer_assign_re = extract(r'(// Sanitizer assignment: valid_path = validate_path\(x\) or valid_path = await validate_path\(x\)\n.*?})\n', python_rs)

patterns_rs = f"""use once_cell::sync::Lazy;
use regex::Regex;

{patterns_block}
{func_def_re}
{sanitizer_assign_re}
"""
patterns_rs = patterns_rs.replace("static ", "pub(crate) static ")

# Extract parts for classify.rs
classify_argument = extract(r'(/// Classify a call argument string to determine its source\.\nfn classify_argument\(.*?)\nfn strip_python_string_literal', python_rs)
strip_python_string_literal = extract(r'(fn strip_python_string_literal\(.*?\)\n.*?})\n', python_rs)
sanitized_var_marker = extract(r'(fn sanitized_var_marker\(.*?\)\n.*?})\n', python_rs)
sanitized_label_for_var = extract(r'(fn sanitized_label_for_var\(.*?\)\n.*?})\n', python_rs)
loc = extract(r'(fn loc\(.*?\)\n.*?})\n', python_rs)
loc_from_range = extract(r'(fn loc_from_range\(.*?\)\n.*?})\n', python_rs)

classify_argument = classify_argument.replace("fn classify_argument", "pub(crate) fn classify_argument")
strip_python_string_literal = strip_python_string_literal.replace("fn strip_python_string_literal", "pub(crate) fn strip_python_string_literal")
sanitized_var_marker = sanitized_var_marker.replace("fn sanitized_var_marker", "pub(crate) fn sanitized_var_marker")
sanitized_label_for_var = sanitized_label_for_var.replace("fn sanitized_label_for_var", "pub(crate) fn sanitized_label_for_var")
loc = loc.replace("fn loc", "pub(crate) fn loc")
loc_from_range = loc_from_range.replace("fn loc_from_range", "pub(crate) fn loc_from_range")

classify_rs = f"""use std::path::Path;
use crate::analysis::cross_file::{{SanitizerCategory, sanitizer_category, sanitizer_label}};
use crate::ir::ArgumentSource;
use crate::ir::SourceLocation;

{classify_argument}

{strip_python_string_literal}

{sanitized_var_marker}

{sanitized_label_for_var}

{loc}

{loc_from_range}
"""

# mod.rs
# imports + struct + impl LanguageParser for PythonParser + tests
header = extract(r'(use std::path::\{Path, PathBuf\};\n.*?\n\npub struct PythonParser;\n)', python_rs)
impl_block = extract(r'(impl LanguageParser for PythonParser \{.*?})\n\n/// Classify a call argument string to determine its source\.', python_rs)
tests_block_py = extract(r'(#\[cfg\(test\)\]\nmod tests \{.*)', python_rs)

# Clean up imports for mod.rs (remove regex, once_cell, add local modules)
header_lines = []
for line in header.split("\n"):
    if "once_cell::sync::Lazy" in line or "regex::Regex" in line or "SanitizerCategory" in line or "looks_sensitive_name" in line:
        continue
    header_lines.append(line)

mod_rs_py = "\n".join(header_lines) + f"""
pub mod classify;
pub mod patterns;

use crate::analysis::cross_file::{{SanitizerCategory, sanitizer_category, sanitizer_label}};
use crate::analysis::sensitivity::looks_sensitive_name;
use patterns::*;
use classify::*;

{impl_block}

{tests_block_py}
"""

write_file("src/parser/python/patterns.rs", patterns_rs)
write_file("src/parser/python/classify.rs", classify_rs)
write_file("src/parser/python/mod.rs", mod_rs_py)
os.remove("src/parser/python.rs")
