use crate::ir::tool_surface::Capability;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DescriptionCapability {
    pub(crate) capability: Capability,
    pub(crate) phrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DescriptionToken {
    Word(String),
    Boundary,
}

pub(crate) struct PhrasePattern {
    pub(crate) capability: Capability,
    pub(crate) tokens: &'static [&'static str],
}

macro_rules! phrase {
    ($capability:ident, $($token:literal),+ $(,)?) => {
        $crate::ir::capability::types::PhrasePattern {
            capability: $crate::ir::tool_surface::Capability::$capability,
            tokens: &[$($token),+],
        }
    };
}

pub(crate) const DESCRIPTION_PHRASES: &[PhrasePattern] = &[
    phrase!(FsRead, "read", "file"),
    phrase!(FsRead, "read", "files"),
    phrase!(FsRead, "list", "directory"),
    phrase!(FsRead, "list", "directories"),
    phrase!(FsRead, "inspect", "file"),
    phrase!(FsRead, "inspect", "files"),
    phrase!(FsWrite, "write", "file"),
    phrase!(FsWrite, "write", "files"),
    phrase!(FsWrite, "create", "file"),
    phrase!(FsWrite, "create", "files"),
    phrase!(FsWrite, "delete", "file"),
    phrase!(FsWrite, "delete", "files"),
    phrase!(FsWrite, "modify", "file"),
    phrase!(FsWrite, "modify", "files"),
    phrase!(NetworkEgress, "fetch", "url"),
    phrase!(NetworkEgress, "fetch", "urls"),
    phrase!(NetworkEgress, "http", "request"),
    phrase!(NetworkEgress, "http", "requests"),
    phrase!(NetworkEgress, "call", "api"),
    phrase!(NetworkEgress, "call", "apis"),
    phrase!(NetworkEgress, "from", "url"),
    phrase!(NetworkEgress, "from", "urls"),
    phrase!(NetworkEgress, "from", "http"),
    phrase!(NetworkEgress, "from", "https"),
    phrase!(NetworkEgress, "from", "web"),
    phrase!(NetworkEgress, "download", "url"),
    phrase!(NetworkEgress, "download", "urls"),
    phrase!(ProcessExec, "run", "command"),
    phrase!(ProcessExec, "run", "commands"),
    phrase!(ProcessExec, "execute", "command"),
    phrase!(ProcessExec, "execute", "commands"),
    phrase!(ProcessExec, "shell", "command"),
    phrase!(ProcessExec, "shell", "commands"),
    phrase!(ProcessExec, "subprocess"),
    phrase!(EnvRead, "read", "environment", "variable"),
    phrase!(EnvRead, "read", "environment", "variables"),
    phrase!(EnvRead, "inspect", "environment"),
    phrase!(CredentialAccess, "read", "secret"),
    phrase!(CredentialAccess, "read", "secrets"),
    phrase!(CredentialAccess, "load", "secret"),
    phrase!(CredentialAccess, "load", "secrets"),
    phrase!(CredentialAccess, "access", "credential"),
    phrase!(CredentialAccess, "access", "credentials"),
    phrase!(CredentialAccess, "read", "api", "key", "from", "store"),
    phrase!(CredentialAccess, "read", "api", "keys", "from", "store"),
    phrase!(CredentialAccess, "load", "api", "key", "from", "store"),
    phrase!(CredentialAccess, "load", "api", "keys", "from", "store"),
    phrase!(DynamicEval, "evaluate", "arbitrary", "code"),
    phrase!(DynamicEval, "execute", "arbitrary", "code"),
    phrase!(DynamicEval, "dynamic", "code", "evaluation"),
    phrase!(PackageInstall, "install", "package"),
    phrase!(PackageInstall, "install", "packages"),
    phrase!(PackageInstall, "add", "dependency"),
    phrase!(PackageInstall, "add", "dependencies"),
    phrase!(DatabaseRead, "query", "database"),
    phrase!(DatabaseRead, "read", "database"),
    phrase!(DatabaseRead, "search", "records"),
    phrase!(DatabaseWrite, "write", "database"),
    phrase!(DatabaseWrite, "update", "record"),
    phrase!(DatabaseWrite, "update", "records"),
    phrase!(DatabaseWrite, "delete", "record"),
    phrase!(DatabaseWrite, "delete", "records"),
];
