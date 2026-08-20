//! Command parsing, secret-free output, and lifecycle orchestration for the
//! Dirextalk GCP deployer.

pub mod application;
pub mod cli;
pub mod engine;
mod host_mcp;
mod live_product;
pub mod output;
pub mod product;
pub mod release;
pub mod runtime;
pub mod store;

pub(crate) fn ensure_tls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
