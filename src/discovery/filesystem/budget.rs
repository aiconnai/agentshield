#[cfg(unix)]
#[derive(Debug, Default)]
pub(super) struct DiscoveryBudget {
    pub(super) directories: usize,
    pub(super) candidate_files: usize,
    pub(super) opened_configs: usize,
    pub(super) bytes: usize,
}
