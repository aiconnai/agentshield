use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
use crate::ir::execution_surface::FileOpType;
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-014: Download-Write-Execute Chain
///
/// Detects when data flows from HTTP download to file write to process execution
/// — a classic supply chain attack pattern (CWE-494).
pub struct DownloadExecDetector;

impl Detector for DownloadExecDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-014".into(),
            name: "Download-Write-Execute Chain".into(),
            description: "Data flows from HTTP download to file write to process execution \
                          — classic supply chain attack pattern"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::SupplyChain,
            cwe_id: Some("CWE-494".into()),
            owasp_mcp: Some(OwaspMcp::SupplyChain),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Check taint paths for HttpResponse -> FileWrite chains,
        // then look for a ProcessExec sink in the same target.
        let has_http_to_file = target.data.taint_paths.iter().any(|p| {
            matches!(p.source.source_type, TaintSourceType::HttpResponse)
                && matches!(p.sink.sink_type, TaintSinkType::FileWrite)
        });

        let has_process_exec_sink = target
            .data
            .taint_paths
            .iter()
            .any(|p| matches!(p.sink.sink_type, TaintSinkType::ProcessExec));

        if has_http_to_file && has_process_exec_sink {
            // Find the specific paths to build evidence
            let http_to_file = target.data.taint_paths.iter().find(|p| {
                matches!(p.source.source_type, TaintSourceType::HttpResponse)
                    && matches!(p.sink.sink_type, TaintSinkType::FileWrite)
            });

            let file_to_exec = target
                .data
                .taint_paths
                .iter()
                .find(|p| matches!(p.sink.sink_type, TaintSinkType::ProcessExec));

            let mut evidence = Vec::new();
            let mut location = None;

            if let Some(path) = http_to_file {
                evidence.push(Evidence {
                    description: format!("HTTP download: '{}'", path.source.description),
                    location: Some(path.source.location.clone()),
                    snippet: None,
                });
                evidence.push(Evidence {
                    description: format!("File write: '{}'", path.sink.description),
                    location: Some(path.sink.location.clone()),
                    snippet: None,
                });
            }

            if let Some(path) = file_to_exec {
                location = Some(path.sink.location.clone());
                evidence.push(Evidence {
                    description: format!("Process execution: '{}'", path.sink.description),
                    location: Some(path.sink.location.clone()),
                    snippet: None,
                });
            }

            findings.push(Finding {
                rule_id: "SHIELD-014".into(),
                rule_name: "Download-Write-Execute Chain".into(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                attack_category: AttackCategory::SupplyChain,
                message: "Detected download-write-execute chain: HTTP response flows to \
                          file write, and a process execution sink exists in the same scope"
                    .into(),
                location,
                evidence,
                taint_path: None,
                remediation: Some(
                    "Verify downloaded content integrity using checksums or signatures \
                     before writing to disk. Never execute downloaded files directly. \
                     Use package managers with lockfiles instead of custom download logic."
                        .into(),
                ),
                cwe_id: Some("CWE-494".into()),
            });
        }

        // Phase 2: Heuristic — check ExecutionSurface for co-occurrence of
        // network download + file write + command execution in the same target.
        let has_download = !target.execution.network_operations.is_empty();
        let has_write = target
            .execution
            .file_operations
            .iter()
            .any(|f| f.operation == FileOpType::Write);
        let has_exec = !target.execution.commands.is_empty();

        if has_download && has_write && has_exec {
            // Avoid duplicate if we already found via taint paths
            if findings.is_empty() {
                let mut evidence = Vec::new();

                if let Some(net_op) = target.execution.network_operations.first() {
                    evidence.push(Evidence {
                        description: format!("Network operation: '{}'", net_op.function),
                        location: Some(net_op.location.clone()),
                        snippet: None,
                    });
                }

                if let Some(file_op) = target
                    .execution
                    .file_operations
                    .iter()
                    .find(|f| f.operation == FileOpType::Write)
                {
                    evidence.push(Evidence {
                        description: "File write operation".into(),
                        location: Some(file_op.location.clone()),
                        snippet: None,
                    });
                }

                if let Some(cmd) = target.execution.commands.first() {
                    evidence.push(Evidence {
                        description: format!("Command execution: '{}'", cmd.function),
                        location: Some(cmd.location.clone()),
                        snippet: None,
                    });
                }

                let location = target
                    .execution
                    .commands
                    .first()
                    .map(|c| c.location.clone());

                findings.push(Finding {
                    rule_id: "SHIELD-014".into(),
                    rule_name: "Download-Write-Execute Chain".into(),
                    severity: Severity::Critical,
                    confidence: Confidence::Medium,
                    attack_category: AttackCategory::SupplyChain,
                    message: "Potential download-write-execute chain: network operation, \
                              file write, and command execution found in the same target"
                        .into(),
                    location,
                    evidence,
                    taint_path: None,
                    remediation: Some(
                        "Verify downloaded content integrity using checksums or signatures \
                         before writing to disk. Never execute downloaded files directly. \
                         Use package managers with lockfiles instead of custom download logic."
                            .into(),
                    ),
                    cwe_id: Some("CWE-494".into()),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::data_surface::*;
    use crate::ir::execution_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn loc() -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("test.py"),
            line: 5,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    fn empty_target() -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface::default(),
            data: DataSurface::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    #[test]
    fn detects_download_write_exec_via_taint_paths() {
        let mut target = empty_target();

        // HTTP response -> file write
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::HttpResponse,
                description: "requests.get response".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::FileWrite,
                description: "open('/tmp/script.sh', 'w')".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });

        // File content -> process exec
        target.data.taint_paths.push(TaintPath {
            source: TaintSource {
                source_type: TaintSourceType::FileContent,
                description: "script.sh".into(),
                location: loc(),
            },
            sink: TaintSink {
                sink_type: TaintSinkType::ProcessExec,
                description: "subprocess.run".into(),
                location: loc(),
            },
            through: vec![],
            confidence: 0.9,
        });

        let findings = DownloadExecDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-014");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].evidence.len(), 3);
    }

    #[test]
    fn detects_download_write_exec_via_execution_surface() {
        let mut target = empty_target();

        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("https://example.com/script.sh".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Write,
            path_arg: ArgumentSource::Literal("/tmp/script.sh".into()),
            location: loc(),
        });

        target.execution.commands.push(CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: ArgumentSource::Literal("/tmp/script.sh".into()),
            location: loc(),
        });

        let findings = DownloadExecDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-014");
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn no_finding_without_write() {
        let mut target = empty_target();

        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("https://api.example.com/data".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        target.execution.commands.push(CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: ArgumentSource::Literal("ls -la".into()),
            location: loc(),
        });

        // No file write — should not trigger
        let findings = DownloadExecDetector.run(&target);
        assert!(findings.is_empty());
    }
}
