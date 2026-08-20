use std::io::{Read, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{GcpError, Result, SecretStore};

const REFRESH_TOKEN_ACCOUNT: &str = "google-oauth-refresh-token";
const MAX_CALLBACK_HEADER_BYTES: usize = 8192;
const ACCESS_TOKEN_EXPIRY_MARGIN: Duration = Duration::from_mins(1);

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
    /// Resolves the product-owned native public client id embedded by the
    /// build. Runtime user input and environment overrides are never accepted.
    pub fn from_build() -> Result<Self> {
        let client_id = resolve_client_id(option_env!("DIREXTALK_GOOGLE_OAUTH_CLIENT_ID"))?;
        Self::google(client_id)
    }

    pub fn google(client_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            client_id: client_id.into(),
            client_secret: None,
            scopes: vec![
                "openid".into(),
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

fn resolve_client_id(compiled: Option<&str>) -> Result<String> {
    match compiled {
        Some(value) if !value.trim().is_empty() => Ok(value.to_owned()),
        Some(_) => Err(GcpError::Contract(
            "embedded Google OAuth client id is empty".into(),
        )),
        None => Err(GcpError::Contract(
            "Google OAuth client id is not embedded in this product build".into(),
        )),
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
    refresh_lock: tokio::sync::Mutex<()>,
    token_cache: std::sync::Mutex<Option<CachedToken>>,
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

#[derive(Clone)]
pub struct OAuthToken {
    pub access_token: SecretString,
    /// Stable Google OIDC subject (`sub`) used for authorization
    /// and persisted identity comparisons.
    pub principal: String,
    pub expires_at: Option<Instant>,
}

struct CachedToken {
    credential_fingerprint: [u8; 32],
    token: OAuthToken,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthToken")
            .field("access_token", &"[REDACTED]")
            .field("principal", &"[REDACTED]")
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
    #[serde(default)]
    sub: String,
}

#[derive(Debug, Clone, Copy)]
enum TokenFlow {
    Login,
    Refresh,
}

impl GoogleInstalledApp {
    #[must_use]
    pub fn new(
        config: InstalledAppConfig,
        secrets: Arc<dyn SecretStore>,
        browser: Arc<dyn BrowserLauncher>,
    ) -> Self {
        crate::ensure_tls_provider();
        Self {
            config,
            secrets,
            browser,
            client: reqwest::Client::new(),
            refresh_lock: tokio::sync::Mutex::new(()),
            token_cache: std::sync::Mutex::new(None),
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
        eprintln!(
            "Open this Google authorization URL if the browser did not open automatically:\n{}",
            request.authorization_url
        );
        if let Err(error) = self.browser.open(&request.authorization_url) {
            eprintln!("The system browser could not be opened ({error}); use the URL above.");
        }

        let timeout = self.config.callback_timeout;
        let raw_callback =
            tokio::task::spawn_blocking(move || receive_callback(&listener, timeout))
                .await
                .map_err(|error| {
                    GcpError::Infrastructure(format!("OAuth listener failed: {error}"))
                })??;
        let code = Self::validate_callback(&raw_callback, &request)?;
        let _refresh = self.refresh_lock.lock().await;
        self.exchange_code(&code, &request).await
    }

    pub async fn refresh(&self) -> Result<Option<OAuthToken>> {
        self.usable_token().await
    }

    pub async fn usable_token(&self) -> Result<Option<OAuthToken>> {
        let _refresh = self.refresh_lock.lock().await;
        let Some(refresh_token) = self.secrets.get(REFRESH_TOKEN_ACCOUNT)? else {
            self.clear_token_cache()?;
            return Ok(None);
        };
        let credential_fingerprint = self.credential_fingerprint(&refresh_token);
        if let Some(token) = self.cached_token(&credential_fingerprint)? {
            return Ok(Some(token));
        }
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
        let rotated_refresh = token.refresh_token.clone();
        let token = self.finish_token(token, TokenFlow::Refresh).await?;
        let cache_fingerprint = rotated_refresh.as_ref().map_or_else(
            || credential_fingerprint,
            |refresh_token| self.credential_fingerprint(refresh_token),
        );
        self.store_cached_token(cache_fingerprint, &token)?;
        Ok(Some(token))
    }

    pub async fn logout(&self) -> Result<()> {
        let _refresh = self.refresh_lock.lock().await;
        self.clear_token_cache()?;
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
        let values: Vec<_> = callback.query_pairs().into_owned().collect();
        let state = unique_parameter(&values, "state")?;
        if state.as_deref() != Some(request.state.expose_secret()) {
            return Err(GcpError::OAuthValidation("CSRF state did not match".into()));
        }
        if let Some(error) = unique_parameter(&values, "error")? {
            return Err(GcpError::Authentication(format!(
                "authorization server returned {error}"
            )));
        }
        unique_parameter(&values, "code")?
            .filter(|code| !code.is_empty())
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
        self.finish_token(token, TokenFlow::Login).await
    }

    async fn finish_token(&self, token: TokenResponse, flow: TokenFlow) -> Result<OAuthToken> {
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
        self.complete_token(token, user, flow)
    }

    fn complete_token(
        &self,
        token: TokenResponse,
        user: UserInfo,
        flow: TokenFlow,
    ) -> Result<OAuthToken> {
        let principal = validate_user_info(user)?;
        match (flow, token.refresh_token.as_ref()) {
            (TokenFlow::Login, None) => {
                return Err(GcpError::Authentication(
                    "login did not return an offline refresh credential; existing credential was not changed"
                        .into(),
                ));
            }
            (TokenFlow::Login | TokenFlow::Refresh, Some(refresh_token)) => {
                self.secrets.set(REFRESH_TOKEN_ACCOUNT, refresh_token)?;
                self.clear_token_cache()?;
            }
            (TokenFlow::Refresh, None) => {}
        }
        Ok(OAuthToken {
            access_token: token.access_token,
            principal,
            expires_at: token
                .expires_in
                .map(|seconds| Instant::now() + Duration::from_secs(seconds)),
        })
    }

    fn credential_fingerprint(&self, refresh_token: &SecretString) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"dirextalk-google-oauth-cache-v1\0");
        digest.update(self.config.client_id.as_bytes());
        digest.update(b"\0");
        digest.update(refresh_token.expose_secret().as_bytes());
        digest.finalize().into()
    }

    fn cached_token(&self, credential_fingerprint: &[u8; 32]) -> Result<Option<OAuthToken>> {
        let cache = self.token_cache.lock().map_err(|_| {
            GcpError::Infrastructure("OAuth access-token cache lock was poisoned".into())
        })?;
        Ok(cache
            .as_ref()
            .filter(|cached| {
                &cached.credential_fingerprint == credential_fingerprint
                    && token_is_usable(&cached.token, Instant::now())
            })
            .map(|cached| cached.token.clone()))
    }

    fn store_cached_token(
        &self,
        credential_fingerprint: [u8; 32],
        token: &OAuthToken,
    ) -> Result<()> {
        let mut cache = self.token_cache.lock().map_err(|_| {
            GcpError::Infrastructure("OAuth access-token cache lock was poisoned".into())
        })?;
        *cache = token_is_usable(token, Instant::now()).then(|| CachedToken {
            credential_fingerprint,
            token: token.clone(),
        });
        Ok(())
    }

    fn clear_token_cache(&self) -> Result<()> {
        let mut cache = self.token_cache.lock().map_err(|_| {
            GcpError::Infrastructure("OAuth access-token cache lock was poisoned".into())
        })?;
        *cache = None;
        Ok(())
    }
}

fn token_is_usable(token: &OAuthToken, now: Instant) -> bool {
    token
        .expires_at
        .is_some_and(|expires_at| expires_at > now + ACCESS_TOKEN_EXPIRY_MARGIN)
}

fn validate_user_info(user: UserInfo) -> Result<String> {
    if user.sub.trim().is_empty() {
        return Err(GcpError::Authentication(
            "Google userinfo subject was missing".into(),
        ));
    }
    Ok(user.sub)
}

fn unique_parameter(values: &[(String, String)], key: &str) -> Result<Option<String>> {
    let mut matches = values.iter().filter(|(name, _)| name == key);
    let value = matches.next().map(|(_, value)| value.clone());
    if matches.next().is_some() {
        return Err(GcpError::OAuthValidation(format!(
            "OAuth callback contained duplicate {key} parameters"
        )));
    }
    Ok(value)
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
    let bytes = read_callback_headers(&mut stream)?;
    let request = std::str::from_utf8(&bytes)
        .map_err(|_| GcpError::OAuthValidation("callback was not valid HTTP".into()))?;
    let mut lines = request
        .strip_suffix("\r\n\r\n")
        .unwrap_or(request)
        .split("\r\n");
    let first_line = lines.next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    if parts.next() != Some("GET")
        || parts.next().is_none()
        || !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || parts.next().is_some()
    {
        return Err(GcpError::OAuthValidation(
            "callback request line was invalid".into(),
        ));
    }
    let target = first_line
        .split_whitespace()
        .nth(1)
        .expect("validated request line has a target");
    if lines.any(|line| {
        line.split_once(':')
            .is_none_or(|(name, _)| name.is_empty() || name.contains([' ', '\t']))
    }) {
        return Err(GcpError::OAuthValidation(
            "callback headers were malformed".into(),
        ));
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: 55\r\n\r\nAuthorization received. You may close this browser window.")?;
    Ok(target.to_owned())
}

fn read_callback_headers(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let remaining = MAX_CALLBACK_HEADER_BYTES.saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(GcpError::OAuthValidation(
                "callback headers exceeded the size limit".into(),
            ));
        }
        let read_limit = remaining.min(chunk.len());
        let count = reader.read(&mut chunk[..read_limit])?;
        if count == 0 {
            return Err(GcpError::OAuthValidation(
                "callback headers were incomplete".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            if bytes[end..].iter().any(|byte| !byte.is_ascii_whitespace()) {
                return Err(GcpError::OAuthValidation(
                    "callback contained unexpected trailing data".into(),
                ));
            }
            bytes.truncate(end);
            return Ok(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use secrecy::{ExposeSecret as _, SecretString};
    use url::Url;

    use super::{
        BrowserLauncher, GoogleInstalledApp, InstalledAppConfig, OAuthToken, TokenFlow,
        TokenResponse, UserInfo, read_callback_headers, resolve_client_id, token_is_usable,
        validate_user_info,
    };
    use crate::{GcpError, Result, SecretStore};

    struct NoBrowser;
    impl BrowserLauncher for NoBrowser {
        fn open(&self, _url: &Url) -> Result<()> {
            Ok(())
        }
    }

    struct FragmentedReader {
        fragments: VecDeque<Vec<u8>>,
    }

    impl Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let Some(mut fragment) = self.fragments.pop_front() else {
                return Ok(0);
            };
            let count = fragment.len().min(buffer.len());
            buffer[..count].copy_from_slice(&fragment[..count]);
            if count < fragment.len() {
                fragment.drain(..count);
                self.fragments.push_front(fragment);
            }
            Ok(count)
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

    struct RecordingSecrets {
        value: Mutex<Option<String>>,
        set_calls: AtomicUsize,
    }

    impl RecordingSecrets {
        fn with_value(value: &str) -> Self {
            Self {
                value: Mutex::new(Some(value.to_owned())),
                set_calls: AtomicUsize::new(0),
            }
        }

        fn value(&self) -> Option<String> {
            self.value.lock().expect("credential lock").clone()
        }
    }

    impl SecretStore for RecordingSecrets {
        fn get(&self, _account: &str) -> Result<Option<SecretString>> {
            Ok(self.value().map(SecretString::from))
        }

        fn set(&self, _account: &str, value: &SecretString) -> Result<()> {
            self.set_calls.fetch_add(1, Ordering::SeqCst);
            *self.value.lock().expect("credential lock") = Some(value.expose_secret().to_owned());
            Ok(())
        }

        fn delete(&self, _account: &str) -> Result<()> {
            *self.value.lock().expect("credential lock") = None;
            Ok(())
        }
    }

    fn app_with_secrets(secrets: Arc<dyn SecretStore>) -> GoogleInstalledApp {
        GoogleInstalledApp::new(
            InstalledAppConfig::google("client-id").expect("config"),
            secrets,
            Arc::new(NoBrowser),
        )
    }

    fn app() -> GoogleInstalledApp {
        app_with_secrets(Arc::new(NoSecrets))
    }

    fn token(refresh_token: Option<&str>) -> TokenResponse {
        TokenResponse {
            access_token: SecretString::from("access-token-secret"),
            refresh_token: refresh_token.map(SecretString::from),
            expires_in: Some(3600),
        }
    }

    fn user(sub: &str) -> UserInfo {
        UserInfo {
            sub: sub.to_owned(),
        }
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
    fn client_id_must_be_embedded_by_the_product_build() {
        assert_eq!(
            resolve_client_id(Some("audited-compiled-id")).expect("compiled id"),
            "audited-compiled-id"
        );
        assert!(resolve_client_id(Some("")).is_err());
        assert!(resolve_client_id(None).is_err());
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
        let duplicate = format!("/oauth/callback?state={state}&state={state}&code=one-time-code");
        assert!(GoogleInstalledApp::validate_callback(&duplicate, &request).is_err());
    }

    #[test]
    fn callback_headers_may_arrive_fragmented_but_not_pipelined() {
        let mut fragmented = FragmentedReader {
            fragments: [
                b"GET /oauth/call".to_vec(),
                b"back?state=s&code=c HTTP/1.1\r\nHo".to_vec(),
                b"st: 127.0.0.1\r\n\r\n".to_vec(),
            ]
            .into(),
        };
        let headers = read_callback_headers(&mut fragmented).expect("fragmented headers");
        assert_eq!(
            headers,
            b"GET /oauth/callback?state=s&code=c HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        );

        let mut pipelined = FragmentedReader {
            fragments: [
                b"GET /oauth/callback HTTP/1.1\r\n\r\nGET /again HTTP/1.1\r\n\r\n".to_vec(),
            ]
            .into(),
        };
        let error = read_callback_headers(&mut pipelined).expect_err("trailing request must fail");
        assert!(matches!(error, GcpError::OAuthValidation(_)));
    }

    #[test]
    fn userinfo_rejects_missing_and_empty_subject() {
        for raw in [r"{}", r#"{"sub":""}"#] {
            let user: UserInfo = serde_json::from_str(raw).expect("userinfo shape");
            let error = validate_user_info(user).expect_err("subject is required");
            assert!(matches!(error, GcpError::Authentication(_)));
        }
    }

    #[test]
    fn oauth_principal_is_the_opaque_stable_subject() {
        let principal = validate_user_info(user("stable-subject-123")).expect("valid identity");

        assert_eq!(principal, "stable-subject-123");
    }

    #[test]
    fn login_validates_identity_before_committing_refresh_credential() {
        let secrets = Arc::new(RecordingSecrets::with_value("old-account-refresh"));
        let app = app_with_secrets(secrets.clone());

        let error = app
            .complete_token(
                token(Some("new-account-refresh")),
                user(""),
                TokenFlow::Login,
            )
            .expect_err("invalid subject must fail");

        assert_eq!(secrets.value().as_deref(), Some("old-account-refresh"));
        assert_eq!(secrets.set_calls.load(Ordering::SeqCst), 0);
        let debug = format!("{error:?}");
        assert!(!debug.contains("access-token-secret"));
        assert!(!debug.contains("new-account-refresh"));
    }

    #[test]
    fn login_requires_a_new_offline_refresh_credential() {
        let secrets = Arc::new(RecordingSecrets::with_value("old-account-refresh"));
        let app = app_with_secrets(secrets.clone());

        let error = app
            .complete_token(token(None), user("new-subject"), TokenFlow::Login)
            .expect_err("login without refresh token must fail");

        assert_eq!(secrets.value().as_deref(), Some("old-account-refresh"));
        assert_eq!(secrets.set_calls.load(Ordering::SeqCst), 0);
        assert!(!format!("{error:?}").contains("access-token-secret"));
    }

    #[test]
    fn refresh_may_retain_existing_credential_after_subject_validation() {
        let secrets = Arc::new(RecordingSecrets::with_value("existing-refresh"));
        let app = app_with_secrets(secrets.clone());

        let refreshed = app
            .complete_token(token(None), user("stable-subject"), TokenFlow::Refresh)
            .expect("refresh without token rotation");

        assert_eq!(refreshed.principal, "stable-subject");
        assert_eq!(secrets.value().as_deref(), Some("existing-refresh"));
        assert_eq!(secrets.set_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn oauth_token_debug_redacts_access_token() {
        let token = OAuthToken {
            access_token: SecretString::from("access-token-secret"),
            principal: "stable-subject".into(),
            expires_at: None,
        };

        let debug = format!("{token:?}");
        assert!(!debug.contains("access-token-secret"));
        assert!(!debug.contains("stable-subject"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn cached_access_token_requires_conservative_remaining_lifetime() {
        let now = Instant::now();
        let token = |expires_at| OAuthToken {
            access_token: SecretString::from("access-token-secret"),
            principal: "stable-subject".into(),
            expires_at,
        };

        assert!(token_is_usable(
            &token(Some(now + Duration::from_secs(61))),
            now
        ));
        assert!(!token_is_usable(
            &token(Some(now + Duration::from_mins(1))),
            now
        ));
        assert!(!token_is_usable(&token(None), now));
    }
}
