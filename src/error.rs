use thiserror::Error;

pub type Result<T> = std::result::Result<T, ShieldError>;

#[derive(Error, Debug)]
pub enum ShieldError {
    #[error("Parse error in {file}: {message}")]
    Parse { file: String, message: String },

    #[error("Adapter error ({framework}): {message}")]
    Adapter { framework: String, message: String },

    #[error("No suitable adapter found for directory: {0}")]
    NoAdapter(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Rule error ({rule_id}): {message}")]
    Rule { rule_id: String, message: String },

    #[error("Output error: {0}")]
    Output(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl ShieldError {
    pub fn exit_code(&self) -> i32 {
        2
    }
}
