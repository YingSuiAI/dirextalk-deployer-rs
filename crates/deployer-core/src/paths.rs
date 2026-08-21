use std::path::{Path, PathBuf};

use directories::BaseDirs;
use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

/// Computes a stable, path-safe service id bound to deployment and project.
///
/// # Errors
///
/// Returns [`CoreError::InvalidServiceId`] for an invalid deployment name or
/// zero project number.
pub fn service_id(deployment_name: &str, project_number: u64) -> Result<String> {
    if project_number == 0 || !valid_name(deployment_name) {
        return Err(CoreError::InvalidServiceId);
    }
    let binding = format!("{deployment_name}\0{project_number}");
    let suffix = hex::encode(Sha256::digest(binding.as_bytes()));
    let id = format!("{deployment_name}-{}", &suffix[..12]);
    validate_service_id(&id)?;
    Ok(id)
}

/// Rejects traversal, platform separators, and non-canonical service ids.
///
/// # Errors
///
/// Returns [`CoreError::InvalidServiceId`] unless `value` is a bounded,
/// lowercase, path-safe identifier.
pub fn validate_service_id(value: &str) -> Result<()> {
    if !(3..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(CoreError::InvalidServiceId);
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// Canonical paths for one service-scoped deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePaths {
    root: PathBuf,
}

impl NodePaths {
    /// Builds paths below an explicit nodes root (normally
    /// `~/.dirextalk/nodes`).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidServiceId`] when `service_id` is unsafe.
    pub fn new(nodes_root: impl AsRef<Path>, service_id: &str) -> Result<Self> {
        validate_service_id(service_id)?;
        Ok(Self {
            root: nodes_root.as_ref().join(service_id),
        })
    }

    /// Resolves the current user's canonical `~/.dirextalk/nodes` root.
    ///
    /// # Errors
    ///
    /// Returns an error if the user home is unavailable or `service_id` is
    /// unsafe.
    pub fn for_current_user(service_id: &str) -> Result<Self> {
        let base = BaseDirs::new().ok_or(CoreError::InvalidState(
            "current user home directory is unavailable",
        ))?;
        Self::new(base.home_dir().join(".dirextalk/nodes"), service_id)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }

    #[must_use]
    pub fn lock_file(&self) -> PathBuf {
        self.root.join("state.lock")
    }

    #[must_use]
    pub fn credential_file(&self) -> PathBuf {
        self.root.join("credentials.json")
    }

    /// Restrictive local key used only to authenticate `state.json`.
    #[must_use]
    pub fn state_seal_key_file(&self) -> PathBuf {
        self.root.join("state.key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_id_is_stable_and_project_bound() {
        let first = service_id("production", 42).unwrap();
        assert_eq!(first, service_id("production", 42).unwrap());
        assert_ne!(first, service_id("production", 43).unwrap());
        assert!(first.starts_with("production-"));
        assert!(service_id("a1", 42).unwrap().starts_with("a1-"));
    }

    #[test]
    fn path_helpers_reject_traversal() {
        assert!(NodePaths::new("/tmp/nodes", "../production").is_err());
        assert!(NodePaths::new("/tmp/nodes", "prod/child").is_err());
    }
}
