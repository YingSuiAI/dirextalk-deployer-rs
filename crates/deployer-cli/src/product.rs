#![allow(clippy::missing_errors_doc)]

use async_trait::async_trait;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::engine::{EngineError, Result};

pub struct ProductBootstrap {
    domain: String,
    origin: String,
    initialization_code: SecretString,
    agent_token: SecretString,
    agent_room_id: String,
}

impl std::fmt::Debug for ProductBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductBootstrap")
            .field("domain", &self.domain)
            .field("origin", &self.origin)
            .field("initialization_code", &"[REDACTED]")
            .field("agent_token", &"[REDACTED]")
            .field("agent_room_id", &self.agent_room_id)
            .finish()
    }
}

impl ProductBootstrap {
    pub fn parse(domain: &str, bytes: &deployer_transport::SecretBytes) -> Result<Self> {
        Self::parse_bytes(domain, bytes.expose())
    }

    fn parse_bytes(domain: &str, bytes: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Wire {
            password: SecretString,
            access_token: SecretString,
            agent_token: SecretString,
            agent_room_id: String,
            #[serde(default)]
            as_url: Option<String>,
        }

        let wire: Wire = serde_json::from_slice(bytes)
            .map_err(|_| EngineError::Backend("product bootstrap receipt is invalid".into()))?;
        let expected_origin = format!("https://{domain}");
        let origin = wire.as_url.unwrap_or_else(|| expected_origin.clone());
        if origin != expected_origin
            || !wire
                .password
                .expose_secret()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            || wire.password.expose_secret().len() != 8
            || wire.access_token.expose_secret().is_empty()
            || wire.agent_token.expose_secret().is_empty()
            || !wire.agent_room_id.starts_with('!')
            || wire.agent_room_id.starts_with("!agent:")
        {
            return Err(EngineError::Backend(
                "product bootstrap receipt violates the completion contract".into(),
            ));
        }
        Ok(Self {
            domain: domain.into(),
            origin,
            initialization_code: wire.password,
            agent_token: wire.agent_token,
            agent_room_id: wire.agent_room_id,
        })
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    #[must_use]
    pub fn agent_room_id(&self) -> &str {
        &self.agent_room_id
    }

    pub(crate) fn initialization_code(&self) -> &SecretString {
        &self.initialization_code
    }

    pub(crate) fn agent_token(&self) -> &SecretString {
        &self.agent_token
    }
}

pub struct MatrixSession {
    pub user_id: String,
    pub device_id: String,
    pub homeserver: String,
    pub access_token: SecretString,
    pub agent_room_id: Option<String>,
}

impl std::fmt::Debug for MatrixSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MatrixSession")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("homeserver", &self.homeserver)
            .field("access_token", &"[REDACTED]")
            .field("agent_room_id", &self.agent_room_id)
            .finish()
    }
}

pub struct ProductSessions {
    pub owner: MatrixSession,
    pub agent: MatrixSession,
}

#[async_trait]
pub trait ProductApi: Send + Sync {
    async fn portal_auth(&self, origin: &str, code: &SecretString) -> Result<MatrixSession>;
    async fn create_agent_session(
        &self,
        origin: &str,
        agent_token: &SecretString,
    ) -> Result<MatrixSession>;
}

pub async fn initialize_product<A: ProductApi>(
    api: &A,
    bootstrap: &ProductBootstrap,
) -> Result<ProductSessions> {
    let owner = api
        .portal_auth(&bootstrap.origin, &bootstrap.initialization_code)
        .await?;
    if owner.user_id != format!("@owner:{}", bootstrap.domain)
        || owner.homeserver != bootstrap.origin
        || owner.device_id.is_empty()
        || owner.access_token.expose_secret().is_empty()
        || owner.agent_room_id.as_deref() != Some(bootstrap.agent_room_id())
    {
        return Err(EngineError::Backend(
            "portal.auth returned a non-canonical owner session".into(),
        ));
    }
    let agent = api
        .create_agent_session(&bootstrap.origin, &bootstrap.agent_token)
        .await?;
    if agent.user_id != format!("@agent:{}", bootstrap.domain)
        || agent.homeserver != bootstrap.origin
        || agent.device_id.is_empty()
        || agent.access_token.expose_secret().is_empty()
        || agent
            .agent_room_id
            .as_deref()
            .is_some_and(|room_id| room_id != bootstrap.agent_room_id())
    {
        return Err(EngineError::Backend(
            "agent.matrix_session.create returned a non-canonical agent session".into(),
        ));
    }
    Ok(ProductSessions { owner, agent })
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    struct FakeApi;

    #[async_trait]
    impl ProductApi for FakeApi {
        async fn portal_auth(&self, origin: &str, _code: &SecretString) -> Result<MatrixSession> {
            Ok(MatrixSession {
                user_id: "@owner:talk.example.com".into(),
                device_id: "owner-device".into(),
                homeserver: origin.into(),
                access_token: SecretString::from("owner-matrix-token"),
                agent_room_id: Some("!realRoom:talk.example.com".into()),
            })
        }

        async fn create_agent_session(
            &self,
            origin: &str,
            _agent_token: &SecretString,
        ) -> Result<MatrixSession> {
            Ok(MatrixSession {
                user_id: "@agent:talk.example.com".into(),
                device_id: "agent-device".into(),
                homeserver: origin.into(),
                access_token: SecretString::from("agent-matrix-token"),
                agent_room_id: Some("!realRoom:talk.example.com".into()),
            })
        }
    }

    #[tokio::test]
    async fn validates_real_room_and_canonical_matrix_identities_without_debugging_secrets() {
        let bootstrap = ProductBootstrap::parse_bytes(
            "talk.example.com",
            r#"{"password":"12345678","access_token":"owner-bootstrap","agent_token":"agent-bootstrap","agent_room_id":"!realRoom:talk.example.com","as_url":"https://talk.example.com"}"#.as_bytes(),
        )
        .expect("bootstrap");
        let debug = format!("{bootstrap:?}");
        assert!(!debug.contains("12345678"));
        assert!(!debug.contains("owner-bootstrap"));
        assert!(!debug.contains("agent-bootstrap"));
        let sessions = initialize_product(&FakeApi, &bootstrap)
            .await
            .expect("sessions");
        assert_eq!(sessions.agent.user_id, "@agent:talk.example.com");
        assert!(!format!("{:?}", sessions.agent).contains("agent-matrix-token"));
    }

    #[test]
    fn rejects_legacy_pseudo_room_and_non_exact_initialization_code() {
        let pseudo = r#"{"password":"12345678","access_token":"owner","agent_token":"agent","agent_room_id":"!agent:talk.example.com"}"#;
        assert!(ProductBootstrap::parse_bytes("talk.example.com", pseudo.as_bytes()).is_err());
        let wrong_code = r#"{"password":"1234567x","access_token":"owner","agent_token":"agent","agent_room_id":"!real:talk.example.com"}"#;
        assert!(ProductBootstrap::parse_bytes("talk.example.com", wrong_code.as_bytes()).is_err());
    }
}
