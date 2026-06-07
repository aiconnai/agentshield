//! Unified Intermediate Representation for agent extension analysis.
//!
//! All adapters produce a `ScanTarget`. All detectors consume a `ScanTarget`.
//! This decouples framework-specific parsing from security analysis.

pub mod data_surface;
pub mod dependency_surface;
pub mod execution_surface;
pub mod provenance_surface;
pub mod taint_builder;
pub mod tool_surface;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use data_surface::DataSurface;
pub use dependency_surface::DependencySurface;
pub use execution_surface::ExecutionSurface;
pub use provenance_surface::ProvenanceSurface;
pub use tool_surface::ToolSurface;

/// Complete scan target — the unified IR that all analysis operates on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Human-readable name of the extension.
    pub name: String,
    /// Framework that produced this target.
    pub framework: Framework,
    /// Root directory of the extension.
    pub root_path: PathBuf,
    /// Tool definitions declared by the extension.
    pub tools: Vec<ToolSurface>,
    /// Execution capabilities discovered in source code.
    pub execution: ExecutionSurface,
    /// Data flow surfaces (inputs, outputs, sources, sinks).
    pub data: DataSurface,
    /// Dependency information.
    pub dependencies: DependencySurface,
    /// Provenance metadata (author, repo, signatures).
    pub provenance: ProvenanceSurface,
    /// Raw source files included in the scan.
    pub source_files: Vec<SourceFile>,
}

/// Which agent framework this extension targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Mcp,
    OpenClaw,
    HermesAgent,
    LangChain,
    CrewAi,
    GptActions,
    CursorRules,
    Unknown,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mcp => write!(f, "MCP"),
            Self::OpenClaw => write!(f, "OpenClaw"),
            Self::HermesAgent => write!(f, "Hermes Agent"),
            Self::LangChain => write!(f, "LangChain"),
            Self::CrewAi => write!(f, "CrewAI"),
            Self::GptActions => write!(f, "GPT Actions"),
            Self::CursorRules => write!(f, "Cursor Rules"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A source file included in the scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub language: Language,
    pub content: String,
    pub size_bytes: u64,
    pub content_hash: String,
}

/// Programming language of a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Python,
    TypeScript,
    JavaScript,
    Shell,
    Json,
    Toml,
    Yaml,
    Markdown,
    Unknown,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "py" => Self::Python,
            "ts" | "tsx" => Self::TypeScript,
            "js" | "jsx" | "mjs" | "cjs" => Self::JavaScript,
            "sh" | "bash" | "zsh" => Self::Shell,
            "json" => Self::Json,
            "toml" => Self::Toml,
            "yml" | "yaml" => Self::Yaml,
            "md" | "markdown" => Self::Markdown,
            _ => Self::Unknown,
        }
    }
}

/// Location in source code.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
}

/// Where a function argument originates — the key taint abstraction.
///
/// Detectors don't need full taint analysis. They just need to know
/// where a function argument came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentSource {
    /// Hardcoded literal string — generally safe.
    Literal(String),
    /// Comes from function parameter — potentially user/LLM-controlled.
    Parameter { name: String },
    /// Comes from environment variable.
    EnvVar { name: String },
    /// Constructed via string formatting/concatenation — dangerous.
    Interpolated,
    /// Unable to determine statically.
    Unknown,
    /// Parameter was sanitized before being passed (e.g., via `validatePath`).
    Sanitized { sanitizer: String },
}

/// The family of sink an argument flows into.
///
/// A sanitizer only neutralizes taint for the sink family it actually protects:
/// a path validator makes a value safe for a file sink but not for a network
/// sink, and a type coercion (`str()`/`Number()`) does not sanitize any
/// injection sink. Detectors pass the sink they guard so a `Sanitized` argument
/// is only treated as safe when its sanitizer category matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkClass {
    /// Shell/command execution.
    Command,
    /// Filesystem path.
    FilePath,
    /// Network URL/host.
    NetworkUrl,
    /// Dynamic code execution (eval and friends).
    DynamicExec,
}

impl ArgumentSource {
    /// Whether this source is potentially attacker-controlled, ignoring sink
    /// category. Treats any `Sanitized` value as safe.
    ///
    /// Prefer [`ArgumentSource::is_tainted_for_sink`] in sink detectors: a
    /// sanitizer of the wrong category (e.g. a URL validator guarding a file
    /// path) must not suppress the finding.
    pub fn is_tainted(&self) -> bool {
        !matches!(self, Self::Literal(_) | Self::Sanitized { .. })
    }

    /// Whether this source is tainted for a specific sink family.
    ///
    /// A `Sanitized` value is safe only when its sanitizer category protects
    /// `sink`; otherwise it stays tainted. `Literal` is always safe; every
    /// other source is always tainted.
    pub fn is_tainted_for_sink(&self, sink: SinkClass) -> bool {
        match self {
            Self::Literal(_) => false,
            Self::Sanitized { sanitizer } => {
                !crate::analysis::cross_file::sanitizer_allows_sink(sanitizer, sink)
            }
            _ => true,
        }
    }
}
