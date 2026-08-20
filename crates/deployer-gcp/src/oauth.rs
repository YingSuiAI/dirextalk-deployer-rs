use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{GcpError, Result, SecretStore};

const REFRESH_TOKEN_ACCOUNT: &str = "google-oauth-refresh-token";

#[derive(Debug, Clone)]
pub struct InstalledAppConfig {
    pub client_id: String,
    pub client_secret: Option<SecretString>,
    pub scopes: Vec<String>,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub revocation_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub callback_timeout: Duration,
}

impl InstalledAppConfig {
    /// Resolves the native public client id without embedding a credential.
    /// Release builds may provide `DIREXTALK_GOOGLE_OAUTH_CLIENT_ID` at compile
    /// time; development may set the same name at runtime.
    pub fn from_environment() -> Result<Self> {
        let client_id = std::env::var("DIREXTALK_GOOGLE_OAUTH_CLIENT_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                option_env!("DIREXTALK_GOOGLE_OAUTH_CLIENT_ID")
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_owned)
            })
            .ok_or_else(|| {
                GcpError::Contract(
                    "Google OAuth client id is not configured; set DIREXTALK_GOOGLE_OAUTH_CLIENT_ID for development or embed it in the release build"
                        .into(),
                )
            })?;
        Self::google(client_id)
    }

    pub fn google(client_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            client_id: client_id.into(),
            client_secret: None,
            scopes: vec![
                "openid".into(),
                "email".into(),
                "https://www.googleapis.com/auth/cloud-platform".into(),
            ],
            authorization_endpoint: Url::parse("https://accounts.google.com/o/oauth2/v2/auth")?,
            token_endpoint: Url::parse("https://oauth2.googleapis.com/token")?,
            revocation_endpoint: Url::parse("https://oauth2.googleapis.com/revoke")?,
            userinfo_endpoint: Url::parse("https://openidconnect.googleapis.com/v1/userinfo")?,
            callback_timeout: Duration::from_mins(5),
        })
    }
}

pub trait BrowserLauncher: Send + Sync {
    fn open(&self, url: &Url) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBrowser;

impl BrowserLauncher for SystemBrowser {
    fn open(&self, url: &Url) -> Result<()> {
        open::that(url.as_str()).map_err(|error| {
            GcpError::Infrastructure(format!("could not open the system browser: {error}"))
        })
    }
}

pub struct GoogleInstalledApp {
    config: InstalledAppConfig,
    secrets: Arc<dyn SecretStore>,
    browser: Arc<dyn BrowserLauncher>,
    client: reqwest::Client,
}

impl std::fmt::Debug for GoogleInstalledApp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GoogleInstalledApp")
            .field("client_id", &self.config.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("scopes", &self.config.scopes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub authorization_url: Url,
    redirect_uri: Url,
    state: SecretString,
    verifier: SecretString,
}

pub struct OAuthToken {
    pub access_token: SecretString,
    pub principal: String,
    pub expires_at: Option<Instant>,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthToken")
            .field("access_token", &"[REDACTED]")
            .field("principal", &self.principal)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct UserInfo {
    email: String,
    email_verified: Option<bool>,
}

impl GoogleInstalledApp {
    #[must_use]
    pub fn new(
        config: InstalledAppConfig,
        secrets: Arc<dyn SecretStore>,
        browser: Arc<dyn BrowserLauncher>,
    ) -> Self {
        Self {
            config,
            secrets,
            browser,
            client: reqwest::Client::new(),
        }
    }

    /// Runs the installed-app loopback flow. The listener binds only IPv4
    /// loopback, and the callback must carry both the exact CSRF state and a
    /// single authorization code.
    pub async fn login(&self) -> Result<OAuthToken> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let redirect_uri = Url::parse(&format!(
            "http://127.0.0.1:{}/oauth/callback",
            address.port()
        ))?;
        let request = self.login_request(redirect_uri);
        self.browser.open(&request.authorization_url)?;

        let timeout = self.config.callback_timeout;
        let raw_callback =
            tokio::task::spawn_blocking(move || receive_callback(&listener, timeout))
                .await
                .map_err(|error| {
                    GcpError::Infrastructure(format!("OAuth listener failed: {error}"))
                })??;
        let code = Self::validate_callback(&raw_callback, &request)?;
        self.exchange_code(&code, &request).await
    }

    pub async fn refresh(&self) -> Result<Option<OAuthToken>> {
        let Some(refresh_token) = self.secrets.get(REFRESH_TOKEN_ACCOUNT)? else {
            return Ok(None);
        };
        let mut fields = vec![
            ("client_id", self.config.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_secret()),
        ];
        if let Some(secret) = &self.config.client_secret {
            fields.push(("client_secret", secret.expose_secret()));
        }
        let response = self
            .client
            .post(self.config.token_endpoint.clone())
            .form(&fields)
            .send()
            .await
            .map_err(|error| {
                GcpError::Infrastructure(format!("OAuth token request failed: {error}"))
            })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            GcpError::Infrastructure(format!("OAuth token response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(GcpError::safe_api(status.as_u16(), &bytes));
        }
        let token: TokenResponse = serde_json::from_slice(&bytes)
            .map_err(|_| GcpError::Authentication("token response was invalid".into()))?;
        self.finish_token(token).await.map(Some)
    }

    pub async fn logout(&self) -> Result<()> {
        let token = self.secrets.get(REFRESH_TOKEN_ACCOUNT)?;
        if let Some(token) = token {
            let response = self
                .client
                .post(self.config.revocation_endpoint.clone())
                .form(&[("token", token.expose_secret())])
                .send()
                .await
                .map_err(|error| {
                    GcpError::Infrastructure(format!("OAuth revocation failed: {error}"))
                })?;
            if !response.status().is_success() {
                let status = response.status().as_u16();
                let bytes = response.bytes().await.map_err(|error| {
                    GcpError::Infrastructure(format!("OAuth revocation response failed: {error}"))
                })?;
                return Err(GcpError::safe_api(status, &bytes));
            }
        }
        self.secrets.delete(REFRESH_TOKEN_ACCOUNT)
    }

    fn login_request(&self, redirect_uri: Url) -> LoginRequest {
        let state = random_secret(32);
        let verifier = random_secret(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose_secret().as_bytes()));
        let mut authorization_url = self.config.authorization_endpoint.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", state.expose_secret())
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");
        LoginRequest {
            authorization_url,
            redirect_uri,
            state,
            verifier,
        }
    }

    fn validate_callback(raw_target: &str, request: &LoginRequest) -> Result<String> {
        let callback = request.redirect_uri.join(raw_target)?;
        if callback.scheme() != "http"
            || callback.host_str() != Some("127.0.0.1")
            || callback.port() != request.redirect_uri.port()
            || callback.path() != request.redirect_uri.path()
        {
            return Err(GcpError::OAuthValidation(
                "callback did not target the bound loopback redirect".into(),
            ));
        }
        let values: HashMap<_, _> = callback.query_pairs().into_owned().collect();
        if values.get("state").map(String::as_str) != Some(request.state.expose_secret()) {
            return Err(GcpError::OAuthValidation("CSRF state did not match".into()));
        }
        if let Some(error) = values.get("error") {
            return Err(GcpError::Authentication(format!(
                "authorization server returned {error}"
            )));
        }
        values
            .get("code")
            .filter(|code| !code.is_empty())
            .cloned()
            .ok_or_else(|| GcpError::OAuthValidation("authorization code was missing".into()))
    }

    async fn exchange_code(&self, code: &str, request: &LoginRequest) -> Result<OAuthToken> {
        let mut fields = vec![
            ("client_id", self.config.client_id.as_str()),
            ("code", code),
            ("code_verifier", request.verifier.expose_secret()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", request.redirect_uri.as_str()),
        ];
        if let Some(secret) = &self.config.client_secret {
            fields.push(("client_secret", secret.expose_secret()));
        }
        let response = self
            .client
            .post(self.config.token_endpoint.clone())
            .form(&fields)
            .send()
            .await
            .map_err(|error| {
                GcpError::Infrastructure(format!("OAuth code exchange failed: {error}"))
            })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            GcpError::Infrastructure(format!("OAuth code response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(GcpError::safe_api(status.as_u16(), &bytes));
        }
        let token: TokenResponse = serde_json::from_slice(&bytes)
            .map_err(|_| GcpError::Authentication("token response was invalid".into()))?;
        self.finish_token(token).await
    }

    async fn finish_token(&self, token: TokenResponse) -> Result<OAuthToken> {
        if let Some(refresh_token) = &token.refresh_token {
            self.secrets.set(REFRESH_TOKEN_ACCOUNT, refresh_token)?;
        }
        let response = self
            .client
            .get(self.config.userinfo_endpoint.clone())
            .bearer_auth(token.access_token.expose_secret())
            .send()
            .await
            .map_err(|error| {
                GcpError::Infrastructure(format!("OAuth userinfo request failed: {error}"))
            })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            GcpError::Infrastructure(format!("OAuth userinfo response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(GcpError::safe_api(status.as_u16(), &bytes));
        }
        let user: UserInfo = serde_json::from_slice(&bytes)
            .map_err(|_| GcpError::Authentication("userinfo response was invalid".into()))?;
        if user.email_verified == Some(false) {
            return Err(GcpError::Authentication(
                "Google account email is not verified".into(),
            ));
        }
        Ok(OAuthToken {
            access_token: token.access_token,
            principal: user.email,
            expires_at: token
                .expires_in
                .map(|seconds| Instant::now() + Duration::from_secs(seconds)),
        })
    }
}

fn random_secret(bytes: usize) -> SecretString {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    SecretString::from(URL_SAFE_NO_PAD.encode(value))
}

fn receive_callback(listener: &TcpListener, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(GcpError::OAuthValidation(
                        "timed out waiting for browser callback".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error.into()),
        }
    };
    if !peer.ip().is_loopback() {
        return Err(GcpError::OAuthValidation(
            "callback peer was not loopback".into(),
        ));
    }
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = [0_u8; 8192];
    let count = stream.read(&mut buffer)?;
    let request = std::str::from_utf8(&buffer[..count])
        .map_err(|_| GcpError::OAuthValidation("callback was not valid HTTP".into()))?;
    let first_line = request.lines().next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    if parts.next() != Some("GET") {
        return Err(GcpError::OAuthValidation(
            "callback method was not GET".into(),
        ));
    }
    let target = parts
        .next()
        .ok_or_else(|| GcpError::OAuthValidation("callback target was missing".into()))?;
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: 55\r\n\r\nAuthorization received. You may close this browser window.")?;
    Ok(target.to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secrecy::SecretString;
    use url::Url;

    use super::{BrowserLauncher, GoogleInstalledApp, InstalledAppConfig};
    use crate::{GcpError, Result, SecretStore};

    struct NoBrowser;
    impl BrowserLauncher for NoBrowser {
        fn open(&self, _url: &Url) -> Result<()> {
            Ok(())
        }
    }
    struct NoSecrets;
    impl SecretStore for NoSecrets {
        fn get(&self, _account: &str) -> Result<Option<SecretString>> {
            Ok(None)
        }
        fn set(&self, _account: &str, _value: &SecretString) -> Result<()> {
            Ok(())
        }
        fn delete(&self, _account: &str) -> Result<()> {
            Ok(())
        }
    }

    fn app() -> GoogleInstalledApp {
        GoogleInstalledApp::new(
            InstalledAppConfig::google("client-id").expect("config"),
            Arc::new(NoSecrets),
            Arc::new(NoBrowser),
        )
    }

    #[test]
    fn login_request_uses_pkce_s256_and_callback_rejects_wrong_state() {
        let app = app();
        let redirect = Url::parse("http://127.0.0.1:12345/oauth/callback").expect("url");
        let request = app.login_request(redirect);
        let params: std::collections::HashMap<_, _> = request
            .authorization_url
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(
            params
                .get("code_challenge")
                .is_some_and(|value| !value.is_empty())
        );
        let error = GoogleInstalledApp::validate_callback(
            "/oauth/callback?state=attacker&code=secret-code",
            &request,
        )
        .expect_err("wrong state must fail");
        assert!(matches!(error, GcpError::OAuthValidation(_)));
        assert!(!format!("{error:?}").contains("secret-code"));
    }

    #[test]
    fn callback_requires_exact_loopback_path_and_code() {
        let app = app();
        let redirect = Url::parse("http://127.0.0.1:12345/oauth/callback").expect("url");
        let request = app.login_request(redirect);
        let state = request
            .authorization_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .expect("state")
            .1
            .into_owned();
        let wrong_path = format!("/other?state={state}&code=code");
        assert!(GoogleInstalledApp::validate_callback(&wrong_path, &request).is_err());
        let valid = format!("/oauth/callback?state={state}&code=one-time-code");
        assert_eq!(
            GoogleInstalledApp::validate_callback(&valid, &request).expect("valid"),
            "one-time-code"
        );
    }
}
