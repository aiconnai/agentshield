mod arbitrary_file_access;
mod archive_traversal;
mod capability_mismatch;
mod command_injection;
mod composite_toxic_flow;
mod credential_exfil;
mod cross_session_state_bleed;
mod download_exec;
mod dynamic_exec;
mod dynamic_tool_registration;
mod excessive_permissions;
mod hardcoded_secrets;
mod insecure_bind;
mod insecure_prompt_concat;
mod insecure_temp_file;
pub(crate) mod metadata_ssrf;
mod no_lockfile;
mod overbroad_fs;
mod prompt_injection;
mod runtime_install;
mod secret_leakage;
mod self_modification;
mod sql_injection;
mod ssrf;
mod system_prompt_tampering;
mod typosquat;
mod unpinned_deps;
mod unsafe_deser;
mod unsafe_deser_patterns;
mod webhook_file_exfil;

use super::{ContextDetector, Detector};

/// Returns all built-in target-only detectors (SHIELD-001..019, SHIELD-021..029).
pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(command_injection::CommandInjectionDetector),
        Box::new(credential_exfil::CredentialExfilDetector),
        Box::new(ssrf::SsrfDetector),
        Box::new(arbitrary_file_access::ArbitraryFileAccessDetector),
        Box::new(runtime_install::RuntimeInstallDetector),
        Box::new(self_modification::SelfModificationDetector),
        Box::new(prompt_injection::PromptInjectionDetector),
        Box::new(excessive_permissions::ExcessivePermissionsDetector),
        Box::new(unpinned_deps::UnpinnedDepsDetector),
        Box::new(typosquat::TyposquatDetector),
        Box::new(dynamic_exec::DynamicExecDetector),
        Box::new(no_lockfile::NoLockfileDetector),
        Box::new(metadata_ssrf::MetadataSsrfDetector),
        Box::new(download_exec::DownloadExecDetector),
        Box::new(overbroad_fs::OverbroadFsDetector),
        Box::new(unsafe_deser::UnsafeDeserDetector),
        Box::new(archive_traversal::ArchiveTraversalDetector),
        Box::new(secret_leakage::SecretLeakageDetector),
        Box::new(capability_mismatch::CapabilityMismatchDetector),
        Box::new(sql_injection::SqlInjectionDetector),
        Box::new(webhook_file_exfil::WebhookFileExfilDetector),
        Box::new(system_prompt_tampering::SystemPromptTamperingDetector),
        Box::new(insecure_bind::InsecureBindDetector),
        Box::new(insecure_temp_file::InsecureTempFileDetector),
        Box::new(insecure_prompt_concat::InsecurePromptConcatDetector),
        Box::new(hardcoded_secrets::HardcodedSecretsDetector),
        Box::new(dynamic_tool_registration::DynamicToolRegistrationDetector),
        Box::new(cross_session_state_bleed::CrossSessionStateBleedDetector),
    ]
}

/// Returns all built-in contextual scanners (not target-only).
pub(crate) fn all_context_detectors() -> Vec<Box<dyn ContextDetector>> {
    vec![Box::new(
        composite_toxic_flow::ArbitraryReadExfiltrationDetector,
    )]
}
