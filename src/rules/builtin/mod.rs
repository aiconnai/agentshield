mod arbitrary_file_access;
mod command_injection;
mod credential_exfil;
mod dynamic_exec;
mod excessive_permissions;
mod metadata_ssrf;
mod no_lockfile;
mod prompt_injection;
mod runtime_install;
mod self_modification;
mod ssrf;
mod typosquat;
mod unpinned_deps;

use super::Detector;

/// Returns all built-in detectors (13 rules: SHIELD-001..013).
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
    ]
}
