use std::io;

/// Errors produced by core validation and durable state operations.
///
/// Error messages intentionally never include configuration or state payloads.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("configuration is not valid schema-v1 TOML")]
    ConfigParse,
    #[error("configuration field `{field}` is invalid: {reason}")]
    ConfigValidation {
        field: &'static str,
        reason: &'static str,
    },
    #[error("value cannot be represented as canonical JSON")]
    CanonicalSerialization,
    #[error("plan digest must have the form `sha256:<64 lowercase hexadecimal characters>`")]
    InvalidPlanDigest,
    #[error("service id is invalid")]
    InvalidServiceId,
    #[error("deployment state is not valid: {0}")]
    InvalidState(&'static str),
    #[error("deployment state integrity check failed")]
    Integrity,
    #[error("deployment state is already locked by another process")]
    Locked,
    #[error("deployment state contains an unsupported schema version")]
    UnsupportedStateSchema,
    #[error("deployment state could not be decoded")]
    StateDecode,
    #[error("unsafe filesystem object at the deployment state path")]
    UnsafeFilesystemObject,
    #[error("deployment state filesystem ownership is not the current user")]
    WrongOwner,
    #[error("deployment state I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl CoreError {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
