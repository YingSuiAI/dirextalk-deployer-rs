#![allow(clippy::missing_errors_doc)]

use std::fs;
use std::io::Write as _;
use std::path::Path;

use async_trait::async_trait;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::engine::{EngineError, Result};
use crate::product::{MatrixSession, ProductApi, ProductBootstrap, ProductSessions};

const MAX_PRODUCT_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
struct ProductActionWire {
    user_id: String,
    device_id: String,
    homeserver: String,
    access_token: SecretString,
    #[serde(default)]
    agent_room_id: Option<String>,
}

pub(crate) struct HttpProductApi {
    client: reqwest::Client,
}

impl HttpProductApi {
    pub(crate) fn new() -> Result<Self> {
        crate::ensure_tls_provider();
        let client = reqwest::Client::builder()
            .https_only(true)
            .build()
            .map_err(|error| EngineError::Backend(format!("HTTPS client failed: {error}")))?;
        Ok(Self { client })
    }

    async fn action(
        &self,
        origin: &str,
        action: &'static str,
        params: serde_json::Value,
        bearer: Option<&SecretString>,
    ) -> Result<MatrixSession> {
        let mut request = self
            .client
            .post(format!("{origin}/_p2p/command"))
            .json(&json!({"action": action, "params": params}));
        if let Some(token) = bearer {
            request = request.bearer_auth(token.expose_secret());
        }
        let response = request
            .send()
            .await
            .map_err(|_| EngineError::Backend(format!("{action} request failed")))?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PRODUCT_RESPONSE_BYTES as u64)
        {
            return Err(EngineError::Backend(format!(
                "{action} response exceeded its size limit"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| EngineError::Backend(format!("{action} response could not be read")))?;
        if !status.is_success() || bytes.len() > MAX_PRODUCT_RESPONSE_BYTES {
            return Err(EngineError::Backend(format!(
                "{action} returned HTTP {status}"
            )));
        }
        let wire: ProductActionWire = serde_json::from_slice(&bytes)
            .map_err(|_| EngineError::Backend(format!("{action} response is invalid")))?;
        Ok(MatrixSession {
            user_id: wire.user_id,
            device_id: wire.device_id,
            homeserver: wire.homeserver,
            access_token: wire.access_token,
            agent_room_id: wire.agent_room_id,
        })
    }
}

#[async_trait]
impl ProductApi for HttpProductApi {
    async fn portal_auth(&self, origin: &str, code: &SecretString) -> Result<MatrixSession> {
        self.action(
            origin,
            "portal.auth",
            json!({
                "password": code.expose_secret(),
                "device_id": "DIREXTALK_DEPLOYER_OWNER"
            }),
            None,
        )
        .await
    }

    async fn create_agent_session(
        &self,
        origin: &str,
        agent_token: &SecretString,
    ) -> Result<MatrixSession> {
        self.action(
            origin,
            "agent.matrix_session.create",
            json!({"device_id": "DIREXTALK_CONNECT"}),
            Some(agent_token),
        )
        .await
    }
}

pub(crate) struct StoredProductSecrets {
    pub(crate) initialization_code: SecretString,
    pub(crate) agent_token: SecretString,
    pub(crate) agent_room_id: String,
    pub(crate) agent_node_id: String,
    pub(crate) origin: String,
    pub(crate) owner: MatrixSession,
    pub(crate) agent: MatrixSession,
}

impl StoredProductSecrets {
    pub(crate) fn from_initialized(
        bootstrap: &ProductBootstrap,
        sessions: ProductSessions,
        node_id: &str,
    ) -> Self {
        Self {
            initialization_code: bootstrap.initialization_code().clone(),
            agent_token: bootstrap.agent_token().clone(),
            agent_room_id: bootstrap.agent_room_id().to_owned(),
            agent_node_id: node_id.to_owned(),
            origin: bootstrap.origin().to_owned(),
            owner: sessions.owner,
            agent: sessions.agent,
        }
    }

    pub(crate) fn write(&self, credentials_path: &Path, matrix_path: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct Profile<'a> {
            password: &'a str,
            access_token: &'a str,
            agent_token: &'a str,
            agent_room_id: &'a str,
            agent_node_id: &'a str,
            mcp_url: String,
            owner_user_id: &'a str,
            owner_device_id: &'a str,
            owner_homeserver: &'a str,
        }
        #[derive(Serialize)]
        struct Profiles<'a> {
            default: Profile<'a>,
        }
        #[derive(Serialize)]
        struct Credentials<'a> {
            profiles: Profiles<'a>,
        }
        #[derive(Serialize)]
        struct AgentSession<'a> {
            access_token: &'a str,
            user_id: &'a str,
            device_id: &'a str,
            homeserver: &'a str,
            room_id: &'a str,
        }

        let credentials = Credentials {
            profiles: Profiles {
                default: Profile {
                    password: self.initialization_code.expose_secret(),
                    access_token: self.owner.access_token.expose_secret(),
                    agent_token: self.agent_token.expose_secret(),
                    agent_room_id: &self.agent_room_id,
                    agent_node_id: &self.agent_node_id,
                    mcp_url: format!("{}/mcp", self.origin),
                    owner_user_id: &self.owner.user_id,
                    owner_device_id: &self.owner.device_id,
                    owner_homeserver: &self.owner.homeserver,
                },
            },
        };
        let matrix = AgentSession {
            access_token: self.agent.access_token.expose_secret(),
            user_id: &self.agent.user_id,
            device_id: &self.agent.device_id,
            homeserver: &self.agent.homeserver,
            room_id: &self.agent_room_id,
        };
        let credentials_bytes = Zeroizing::new(
            serde_json::to_vec(&credentials)
                .map_err(|_| EngineError::State("credentials could not be encoded".into()))?,
        );
        let matrix_bytes = Zeroizing::new(
            serde_json::to_vec(&matrix)
                .map_err(|_| EngineError::State("Matrix session could not be encoded".into()))?,
        );
        restrictive_replace(credentials_path, &credentials_bytes)?;
        restrictive_replace(matrix_path, &matrix_bytes)
    }

    pub(crate) fn read(credentials_path: &Path, matrix_path: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Profile {
            password: SecretString,
            access_token: SecretString,
            agent_token: SecretString,
            agent_room_id: String,
            agent_node_id: String,
            mcp_url: String,
            owner_user_id: String,
            owner_device_id: String,
            owner_homeserver: String,
        }
        #[derive(Deserialize)]
        struct Profiles {
            default: Profile,
        }
        #[derive(Deserialize)]
        struct Credentials {
            profiles: Profiles,
        }
        #[derive(Deserialize)]
        struct AgentSession {
            access_token: SecretString,
            user_id: String,
            device_id: String,
            homeserver: String,
            room_id: String,
        }
        let credentials_bytes = Zeroizing::new(read_restrictive(credentials_path)?);
        let matrix_bytes = Zeroizing::new(read_restrictive(matrix_path)?);
        let credentials: Credentials = serde_json::from_slice(&credentials_bytes)
            .map_err(|_| EngineError::State("credentials are invalid".into()))?;
        let matrix: AgentSession = serde_json::from_slice(&matrix_bytes)
            .map_err(|_| EngineError::State("Matrix session is invalid".into()))?;
        let profile = credentials.profiles.default;
        let expected_mcp = profile
            .mcp_url
            .strip_suffix("/mcp")
            .ok_or_else(|| EngineError::State("stored MCP endpoint is invalid".into()))?;
        if expected_mcp != matrix.homeserver
            || profile.agent_room_id != matrix.room_id
            || profile.owner_homeserver != matrix.homeserver
        {
            return Err(EngineError::State(
                "stored product credential identities differ".into(),
            ));
        }
        Ok(Self {
            initialization_code: profile.password,
            agent_token: profile.agent_token,
            agent_room_id: profile.agent_room_id,
            agent_node_id: profile.agent_node_id,
            origin: matrix.homeserver.clone(),
            owner: MatrixSession {
                user_id: profile.owner_user_id,
                device_id: profile.owner_device_id,
                homeserver: profile.owner_homeserver,
                access_token: profile.access_token,
                agent_room_id: Some(matrix.room_id.clone()),
            },
            agent: MatrixSession {
                user_id: matrix.user_id,
                device_id: matrix.device_id,
                homeserver: matrix.homeserver,
                access_token: matrix.access_token,
                agent_room_id: Some(matrix.room_id),
            },
        })
    }
}

pub(crate) fn restrictive_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| EngineError::State("credential path has no parent".into()))?;
    fs::create_dir_all(parent)
        .map_err(|_| EngineError::State("credential directory could not be created".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| EngineError::State("credential directory is not private".into()))?;
    }
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(EngineError::State("credential path is unsafe".into()));
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".credential-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|_| EngineError::State("credential temporary file failed".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| EngineError::State("credential file is not private".into()))?;
    }
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| EngineError::State("credential file could not be synchronized".into()))?;
    temporary
        .persist(path)
        .map_err(|_| EngineError::State("credential file could not be replaced".into()))?;
    Ok(())
}

pub(crate) fn read_restrictive(path: &Path) -> Result<Vec<u8>> {
    read_restrictive_optional(path)?
        .ok_or_else(|| EngineError::State("credential file is unavailable".into()))
}

pub(crate) fn read_restrictive_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(EngineError::State("credential file is unavailable".into())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(EngineError::State("credential path is unsafe".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != unsafe_owner_uid() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(EngineError::State("credential file is not private".into()));
        }
    }
    fs::read(path)
        .map(Some)
        .map_err(|_| EngineError::State("credential file could not be read".into()))
}

#[cfg(unix)]
fn unsafe_owner_uid() -> u32 {
    // The standard library exposes the file UID but not getuid. A just-opened
    // process-owned temporary file gives the immutable owner identity without
    // adding a libc/unsafe boundary to this crate.
    tempfile::tempfile()
        .ok()
        .and_then(|file| file.metadata().ok())
        .map_or(u32::MAX, |metadata| {
            use std::os::unix::fs::MetadataExt as _;
            metadata.uid()
        })
}
