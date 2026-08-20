use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tempfile::NamedTempFile;

use crate::ConnectError;

#[derive(Clone, Serialize)]
pub struct CredentialProfile {
    pub password: String,
    pub access_token: String,
    pub agent_token: String,
    pub agent_room_id: String,
    pub agent_node_id: String,
    pub mcp_url: String,
}

#[derive(Clone, Serialize)]
pub struct Credentials {
    pub profiles: CredentialProfiles,
}

#[derive(Clone, Serialize)]
pub struct CredentialProfiles {
    pub default: CredentialProfile,
}

impl Credentials {
    #[must_use]
    pub fn with_default(default: CredentialProfile) -> Self {
        Self {
            profiles: CredentialProfiles { default },
        }
    }
}

/// Atomically writes credentials with restrictive permissions.
///
/// # Errors
///
/// Returns an error on serialization, replacement, or durability failure.
pub fn write_credentials(path: &Path, credentials: &Credentials) -> Result<(), ConnectError> {
    let mut bytes = serde_json::to_vec_pretty(credentials)
        .map_err(|error| ConnectError::InvalidConfig(error.to_string()))?;
    bytes.push(b'\n');
    atomic_restrictive_write(path, &bytes)
}

/// Atomically writes the secret-bearing config with restrictive permissions.
///
/// # Errors
///
/// Returns an error on replacement or durability failure.
pub fn write_connect_config(path: &Path, rendered: &str) -> Result<(), ConnectError> {
    atomic_restrictive_write(path, rendered.as_bytes())
}

fn atomic_restrictive_write(path: &Path, contents: &[u8]) -> Result<(), ConnectError> {
    let parent = path.parent().ok_or_else(|| {
        ConnectError::Filesystem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination has no parent directory",
        ))
    })?;
    create_restrictive_dir(parent)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    set_file_restrictive(temporary.as_file())?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| ConnectError::Filesystem(error.error))?;
    sync_dir(parent)?;
    Ok(())
}

fn create_restrictive_dir(path: &Path) -> Result<(), ConnectError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_file_restrictive(file: &fs::File) -> Result<(), ConnectError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), ConnectError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<(), ConnectError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(password: &str) -> Credentials {
        Credentials::with_default(CredentialProfile {
            password: password.into(),
            access_token: "owner-secret".into(),
            agent_token: "agent-secret".into(),
            agent_room_id: "!real:example.com".into(),
            agent_node_id: "node".into(),
            mcp_url: "https://example.com/mcp".into(),
        })
    }

    #[test]
    fn atomically_replaces_restrictive_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("service").join("credentials.json");
        write_credentials(&path, &credentials("12345678")).unwrap();
        write_credentials(&path, &credentials("87654321")).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("87654321"));
        assert!(!text.contains("12345678"));
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
}
