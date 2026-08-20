//! Service-scoped installation and verification of `dirextalk-connect`.
//!
//! The crate deliberately has no npm, shell, local MCP listener, proxy, or
//! generic agent fallback. It downloads a checksummed GitHub Release asset,
//! renders one Matrix bridge, and verifies the remote Streamable HTTP MCP
//! endpoint directly.

mod capability;
mod config;
mod daemon;
mod files;
mod mcp;
mod paths;
mod release;
mod status;

pub use capability::{
    AgentCapability, AgentSelection, ConnectAgent, HostRuntime, resolve_capability,
};
pub use config::{ConnectConfig, MatrixSession, McpInjection, ProjectConfig, render_matrix_config};
pub use daemon::{
    CommandExecutor, CommandOutput, DaemonController, DaemonEvidence, DaemonState, FixedCommand,
    ProcessExecutor,
};
pub use files::{CredentialProfile, Credentials, write_connect_config, write_credentials};
pub use mcp::{
    HttpMcpTransport, McpCheck, McpClient, McpError, McpTool, McpTransport, ReadOnlySmoke,
};
pub use paths::{LocalPlatform, RenderedServicePaths, ServicePaths};
pub use release::{
    CONNECT_GITHUB_REPOSITORY, ReleaseAsset, ReleaseChannel, ReleaseError, ReleaseResolver,
    VerifiedAsset,
};
pub use status::{ConnectStatus, Redactor};

pub(crate) fn ensure_tls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid service id: {0}")]
    InvalidServiceId(String),
    #[error("unsupported local platform: {0}")]
    UnsupportedPlatform(String),
    #[error("unsupported connect agent: {0}")]
    UnsupportedAgent(String),
    #[error("invalid agent selection: {0}")]
    InvalidAgentSelection(String),
    #[error("invalid Matrix bridge configuration: {0}")]
    InvalidConfig(String),
    #[error("filesystem operation failed: {0}")]
    Filesystem(#[from] std::io::Error),
    #[error("TOML rendering failed: {0}")]
    Toml(#[from] toml::ser::Error),
    #[error("daemon verification failed: {0}")]
    Daemon(String),
}
