use crate::ir::data_surface::{TaintSinkType, TaintSourceType};
use crate::ir::execution_surface::{
    CommandInvocation, FileOpType, FileOperation, NetworkOperation,
};
use crate::ir::{ArgumentSource, ScanTarget};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-014: Download-Write-Execute Chain
///
/// Detects when data flows from HTTP download to file write to process execution
/// — a classic supply chain attack pattern (CWE-494).
pub struct DownloadExecDetector;

const SCRIPT_OR_EXECUTABLE_EXTENSIONS: &[&str] = &[
    "appimage", "apk", "bash", "bat", "bin", "cjs", "cmd", "com", "deb", "dmg", "exe", "elf",
    "fish", "jar", "js", "mjs", "msi", "out", "pl", "ps1", "py", "py3", "rb", "rpm", "run", "sh",
    "ts", "tsx", "war", "zsh",
];
const COMMAND_TOKEN_SEPARATORS: &str = "'\";&|()[],";

fn is_download(operation: &NetworkOperation) -> bool {
    !operation.sends_data
        && operation
            .method
            .as_deref()
            .map(|method| method.eq_ignore_ascii_case("GET"))
            .unwrap_or(true)
}

fn is_script_or_executable_path(argument: &ArgumentSource) -> bool {
    let ArgumentSource::Literal(value) = argument else {
        return false;
    };

    let path = value.split(['?', '#']).next().unwrap_or(value);
    let filename = path.rsplit('/').next().unwrap_or(path);
    let Some((_, extension)) = filename.rsplit_once('.') else {
        return false;
    };

    let extension = extension.to_ascii_lowercase();
    SCRIPT_OR_EXECUTABLE_EXTENSIONS
        .iter()
        .any(|candidate| *candidate == extension)
}

fn is_dynamic_path(argument: &ArgumentSource) -> bool {
    matches!(
        argument,
        ArgumentSource::Parameter { .. }
            | ArgumentSource::EnvVar { .. }
            | ArgumentSource::Interpolated
            | ArgumentSource::Unknown
    )
}

fn path_arguments_match(file_path: &ArgumentSource, command: &ArgumentSource) -> bool {
    match (file_path, command) {
        (ArgumentSource::Literal(path), ArgumentSource::Literal(command)) => {
            command == path
                || command
                    .split_whitespace()
                    .map(|token| {
                        token.trim_matches(|character: char| {
                            COMMAND_TOKEN_SEPARATORS.contains(character)
                        })
                    })
                    .any(|token| !token.is_empty() && token == path)
        }
        (
            ArgumentSource::Parameter { name: file_name },
            ArgumentSource::Parameter { name: command_name },
        )
        | (
            ArgumentSource::EnvVar { name: file_name },
            ArgumentSource::EnvVar { name: command_name },
        ) => file_name == command_name,
        _ => false,
    }
}

fn find_executed_write(target: &ScanTarget) -> Option<(&FileOperation, &CommandInvocation)> {
    target
        .execution
        .file_operations
        .iter()
        .filter(|file_op| file_op.operation == FileOpType::Write)
        .find_map(|file_op| {
            let path_is_script = is_script_or_executable_path(&file_op.path_arg);
            let path_is_dynamic = is_dynamic_path(&file_op.path_arg);

            target.execution.commands.iter().find_map(|command| {
                (path_arguments_match(&file_op.path_arg, &command.command_arg)
                    && (path_is_script || path_is_dynamic))
                    .then_some((file_op, command))
            })
        })
}

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

        // Phase 2: conservative fallback for parsers that cannot build a taint path.
        // Require a download-like request and execution of the same script/executable
        // path that was written. Dynamic paths are retained because they cannot be
        // classified by extension, but must still match between the write and exec.
        if findings.is_empty() {
            if let Some(network) = target
                .execution
                .network_operations
                .iter()
                .find(|operation| is_download(operation))
            {
                if let Some((file_op, command)) = find_executed_write(target) {
                    let mut evidence = vec![Evidence {
                        description: format!("Network operation: '{}'", network.function),
                        location: Some(network.location.clone()),
                        snippet: None,
                    }];
                    evidence.push(Evidence {
                        description: "File write operation".into(),
                        location: Some(file_op.location.clone()),
                        snippet: None,
                    });
                    evidence.push(Evidence {
                        description: format!("Command execution: '{}'", command.function),
                        location: Some(command.location.clone()),
                        snippet: None,
                    });

                    findings.push(Finding {
                        rule_id: "SHIELD-014".into(),
                        rule_name: "Download-Write-Execute Chain".into(),
                        severity: Severity::Critical,
                        confidence: Confidence::Medium,
                        attack_category: AttackCategory::SupplyChain,
                        message: "Potential download-write-execute chain: a downloaded script or \
                                  executable is written and the same path is executed"
                            .into(),
                        location: Some(command.location.clone()),
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
    fn does_not_detect_without_taint_chain() {
        let mut target = empty_target();

        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Parameter { name: "url".into() },
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Write,
            path_arg: ArgumentSource::Parameter {
                name: "output_path".into(),
            },
            location: loc(),
        });

        target.execution.commands.push(CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: ArgumentSource::Parameter {
                name: "command".into(),
            },
            location: loc(),
        });

        let findings = DownloadExecDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_for_unrelated_non_executable_write() {
        let mut target = empty_target();

        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Literal("https://example.com/data.json".into()),
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Write,
            path_arg: ArgumentSource::Literal("/tmp/data.json".into()),
            location: loc(),
        });

        target.execution.commands.push(CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: ArgumentSource::Literal("ls -la".into()),
            location: loc(),
        });

        let findings = DownloadExecDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_when_execution_targets_a_different_path() {
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
            command_arg: ArgumentSource::Literal("/tmp/other.sh".into()),
            location: loc(),
        });

        let findings = DownloadExecDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_dynamic_path_when_write_and_exec_share_argument() {
        let mut target = empty_target();

        target.execution.network_operations.push(NetworkOperation {
            function: "requests.get".into(),
            url_arg: ArgumentSource::Parameter { name: "url".into() },
            method: Some("GET".into()),
            sends_data: false,
            location: loc(),
        });

        let output_path = ArgumentSource::Parameter {
            name: "output_path".into(),
        };
        target.execution.file_operations.push(FileOperation {
            operation: FileOpType::Write,
            path_arg: output_path.clone(),
            location: loc(),
        });
        target.execution.commands.push(CommandInvocation {
            function: "subprocess.run".into(),
            command_arg: output_path,
            location: loc(),
        });

        let findings = DownloadExecDetector.run(&target);
        assert_eq!(findings.len(), 1);
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
