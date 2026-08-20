use std::sync::Arc;

use async_trait::async_trait;
use http::Method;
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

use crate::{GcpError, Result};

#[derive(Debug, Clone)]
pub struct RestResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn request(
        &self,
        method: Method,
        url: Url,
        bearer_token: &SecretString,
        body: Option<Value>,
    ) -> Result<RestResponse>;
}

#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    #[must_use]
    pub fn new() -> Self {
        crate::ensure_tls_provider();
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn request(
        &self,
        method: Method,
        url: Url,
        bearer_token: &SecretString,
        body: Option<Value>,
    ) -> Result<RestResponse> {
        if url.scheme() != "https" || url.host_str().is_none_or(|host| !is_google_api_host(host)) {
            return Err(GcpError::Contract(format!(
                "refusing credential-bearing request to untrusted endpoint {url}"
            )));
        }
        let method = reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|error| GcpError::Contract(format!("invalid HTTP method: {error}")))?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(bearer_token.expose_secret());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|error| {
            GcpError::Infrastructure(format!("Google API request failed: {error}"))
        })?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| {
                GcpError::Infrastructure(format!("Google API response failed: {error}"))
            })?
            .to_vec();
        Ok(RestResponse { status, body })
    }
}

fn is_google_api_host(host: &str) -> bool {
    host == "googleapis.com" || host.ends_with(".googleapis.com")
}

#[derive(Clone)]
pub struct GoogleRestClient {
    pub(crate) project_id: String,
    pub(crate) project_number: String,
    pub(crate) access_token: SecretString,
    pub(crate) transport: Arc<dyn HttpTransport>,
}

impl std::fmt::Debug for GoogleRestClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GoogleRestClient")
            .field("project_id", &self.project_id)
            .field("project_number", &self.project_number)
            .field("access_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl GoogleRestClient {
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        project_number: impl Into<String>,
        access_token: SecretString,
    ) -> Self {
        Self::with_transport(
            project_id,
            project_number,
            access_token,
            Arc::new(ReqwestTransport::new()),
        )
    }

    #[must_use]
    pub fn with_transport(
        project_id: impl Into<String>,
        project_number: impl Into<String>,
        access_token: SecretString,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            project_number: project_number.into(),
            access_token,
            transport,
        }
    }

    pub(crate) async fn get<T: DeserializeOwned>(&self, url: Url) -> Result<T> {
        self.request_json(Method::GET, url, None).await
    }

    pub(crate) async fn mutate<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<T> {
        self.request_json(method, url, body).await
    }

    pub(crate) async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<T> {
        let response = self
            .transport
            .request(method, url, &self.access_token, body)
            .await?;
        match response.status {
            200..=299 => serde_json::from_slice(&response.body).map_err(|_| {
                GcpError::Infrastructure("Google API returned an invalid JSON response".into())
            }),
            404 => Err(GcpError::NotFound("requested Google resource".into())),
            status => Err(GcpError::safe_api(status, &response.body)),
        }
    }

    pub(crate) async fn revalidate_project(&self, expected_project_number: &str) -> Result<()> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Project {
            project_number: String,
            lifecycle_state: String,
        }
        if expected_project_number != self.project_number {
            return Err(GcpError::Contract(format!(
                "expected project number {expected_project_number}, client is bound to {}",
                self.project_number
            )));
        }
        let url = Url::parse(&format!(
            "https://cloudresourcemanager.googleapis.com/v1/projects/{}",
            self.project_id
        ))?;
        let project: Project = self.get(url).await?;
        if project.project_number != expected_project_number || project.lifecycle_state != "ACTIVE"
        {
            return Err(GcpError::Contract(format!(
                "project identity changed or project is not active (observed number {}, state {})",
                project.project_number, project.lifecycle_state
            )));
        }
        Ok(())
    }
}
