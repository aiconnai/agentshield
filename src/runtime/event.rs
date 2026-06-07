use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSchemaVersion {
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAction {
    ToolCall,
    Command,
    FileRead,
    FileWrite,
    NetworkRequest,
    SecretObserved,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventSource {
    Mcp,
    OpenClaw,
    CrewAi,
    LangChain,
    Stdin,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeVerdict {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub schema_version: RuntimeSchemaVersion,
    pub source: RuntimeEventSource,
    pub action: RuntimeAction,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub arguments: serde_json::Value,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeGuardFinding {
    pub rule_id: String,
    pub severity: RuntimeSeverity,
    pub message: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeGuardResult {
    pub schema_version: RuntimeSchemaVersion,
    pub verdict: RuntimeVerdict,
    pub findings: Vec<RuntimeGuardFinding>,
    pub redacted: bool,
}
