use async_trait::async_trait;
use http::Method;
use serde::Deserialize;
use url::Url;

use crate::{GcpDiscovery, GcpError, GoogleCloudClient, GoogleRestClient, Result, ServiceStatus};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceUsageOperation {
    pub name: String,
    pub state: ServiceUsageOperationState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceUsageOperationState {
    Pending,
    Succeeded,
    Failed { code: i32, message: String },
}

#[async_trait]
pub trait GcpServiceUsage: Send + Sync {
    async fn service_status(&self, project_number: &str, service: &str) -> Result<ServiceStatus>;

    async fn enable_service(
        &self,
        project_number: &str,
        service: &str,
    ) -> Result<ServiceUsageOperation>;

    async fn service_operation(
        &self,
        project_number: &str,
        operation_name: &str,
    ) -> Result<ServiceUsageOperation>;
}

#[async_trait]
pub trait GcpProjectIdentity: Send + Sync {
    async fn revalidate_project_identity(
        &self,
        project_id: &str,
        project_number: &str,
    ) -> Result<()>;
}

#[async_trait]
impl GcpServiceUsage for GoogleRestClient {
    async fn service_status(&self, project_number: &str, service: &str) -> Result<ServiceStatus> {
        require_bound_project(self, project_number)?;
        validate_service_name(service)?;
        <Self as GcpDiscovery>::service(self, project_number, service).await
    }

    async fn enable_service(
        &self,
        project_number: &str,
        service: &str,
    ) -> Result<ServiceUsageOperation> {
        require_bound_project(self, project_number)?;
        validate_service_name(service)?;
        let url = Url::parse(&format!(
            "https://serviceusage.googleapis.com/v1/projects/{project_number}/services/{service}:enable"
        ))?;
        let operation: OperationWire = self
            .mutate(Method::POST, url, Some(serde_json::json!({})))
            .await?;
        operation.try_into()
    }

    async fn service_operation(
        &self,
        project_number: &str,
        operation_name: &str,
    ) -> Result<ServiceUsageOperation> {
        require_bound_project(self, project_number)?;
        validate_operation_name(operation_name)?;
        let url = Url::parse(&format!(
            "https://serviceusage.googleapis.com/v1/{operation_name}"
        ))?;
        self.get::<OperationWire>(url).await?.try_into()
    }
}

#[async_trait]
impl GcpServiceUsage for GoogleCloudClient {
    async fn service_status(&self, project_number: &str, service: &str) -> Result<ServiceStatus> {
        self.service_usage
            .service_status(project_number, service)
            .await
    }

    async fn enable_service(
        &self,
        project_number: &str,
        service: &str,
    ) -> Result<ServiceUsageOperation> {
        self.service_usage
            .enable_service(project_number, service)
            .await
    }

    async fn service_operation(
        &self,
        project_number: &str,
        operation_name: &str,
    ) -> Result<ServiceUsageOperation> {
        self.service_usage
            .service_operation(project_number, operation_name)
            .await
    }
}

#[async_trait]
impl GcpProjectIdentity for GoogleCloudClient {
    async fn revalidate_project_identity(
        &self,
        project_id: &str,
        project_number: &str,
    ) -> Result<()> {
        if project_id != self.project_id || project_number != self.project_number {
            return Err(GcpError::Contract(
                "project identity differs from the bound Google client".into(),
            ));
        }
        let observed = <Self as GcpDiscovery>::project(self, project_id).await?;
        if observed.project_id != project_id
            || observed.project_number != project_number
            || !observed.is_active()
        {
            return Err(GcpError::Contract(
                "GCP project immutable identity changed".into(),
            ));
        }
        Ok(())
    }
}

fn require_bound_project(client: &GoogleRestClient, project_number: &str) -> Result<()> {
    if project_number != client.project_number
        || project_number.is_empty()
        || !project_number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(GcpError::Contract(
            "Service Usage request is not bound to the authenticated project number".into(),
        ));
    }
    Ok(())
}

fn validate_service_name(service: &str) -> Result<()> {
    if service.is_empty()
        || service.len() > 253
        || !service.ends_with(".googleapis.com")
        || !service
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
    {
        return Err(GcpError::Contract("invalid Google service name".into()));
    }
    Ok(())
}

fn validate_operation_name(name: &str) -> Result<()> {
    if name.len() < "operations/".len() + 1
        || name.len() > 1024
        || !name.starts_with("operations/")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(GcpError::Contract(
            "invalid Service Usage operation name".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct OperationWire {
    name: String,
    #[serde(default)]
    done: bool,
    error: Option<OperationErrorWire>,
}

#[derive(Deserialize)]
struct OperationErrorWire {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    message: String,
}

impl TryFrom<OperationWire> for ServiceUsageOperation {
    type Error = GcpError;

    fn try_from(operation: OperationWire) -> Result<Self> {
        validate_operation_name(&operation.name)?;
        let state = match (operation.done, operation.error) {
            (false, None) => ServiceUsageOperationState::Pending,
            (true, None) => ServiceUsageOperationState::Succeeded,
            (true, Some(error)) => ServiceUsageOperationState::Failed {
                code: error.code,
                message: error.message,
            },
            (false, Some(_)) => {
                return Err(GcpError::Infrastructure(
                    "Service Usage operation returned an error before completion".into(),
                ));
            }
        };
        Ok(Self {
            name: operation.name,
            state,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use secrecy::SecretString;
    use serde_json::Value;

    use super::*;
    use crate::{HttpTransport, RestResponse};

    #[derive(Default)]
    struct FakeTransport {
        responses: Mutex<VecDeque<RestResponse>>,
        requests: Mutex<Vec<(Method, String, Option<Value>)>>,
    }

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = RestResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl HttpTransport for FakeTransport {
        async fn request(
            &self,
            method: Method,
            url: Url,
            _bearer_token: &SecretString,
            body: Option<Value>,
        ) -> Result<RestResponse> {
            self.requests
                .lock()
                .expect("requests")
                .push((method, url.to_string(), body));
            self.responses
                .lock()
                .expect("responses")
                .pop_front()
                .ok_or_else(|| GcpError::Infrastructure("missing fake response".into()))
        }
    }

    fn response(body: &str) -> RestResponse {
        RestResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn enable_and_poll_are_project_bound_fixed_requests() {
        let transport = Arc::new(FakeTransport::new([
            response(r#"{"name":"operations/enable-compute","done":false}"#),
            response(r#"{"name":"operations/enable-compute","done":true}"#),
        ]));
        let client = GoogleRestClient::with_transport(
            "project-id",
            "12345",
            SecretString::from("token"),
            transport.clone(),
        );

        let started = client
            .enable_service("12345", "compute.googleapis.com")
            .await
            .expect("start");
        assert_eq!(started.state, ServiceUsageOperationState::Pending);
        let completed = client
            .service_operation("12345", &started.name)
            .await
            .expect("poll");
        assert_eq!(completed.state, ServiceUsageOperationState::Succeeded);

        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests[0].0, Method::POST);
        assert_eq!(
            requests[0].1,
            "https://serviceusage.googleapis.com/v1/projects/12345/services/compute.googleapis.com:enable"
        );
        assert_eq!(requests[0].2, Some(serde_json::json!({})));
        assert_eq!(requests[1].0, Method::GET);
        assert_eq!(
            requests[1].1,
            "https://serviceusage.googleapis.com/v1/operations/enable-compute"
        );
    }

    #[tokio::test]
    async fn rejects_cross_project_and_untrusted_names_before_transport() {
        let transport = Arc::new(FakeTransport::default());
        let client = GoogleRestClient::with_transport(
            "project-id",
            "12345",
            SecretString::from("token"),
            transport.clone(),
        );

        assert!(
            client
                .service_status("67890", "compute.googleapis.com")
                .await
                .is_err()
        );
        assert!(
            client
                .service_status("12345", "compute.googleapis.com@example.com")
                .await
                .is_err()
        );
        assert!(
            client
                .enable_service("67890", "compute.googleapis.com")
                .await
                .is_err()
        );
        assert!(
            client
                .enable_service("12345", "compute.googleapis.com@example.com")
                .await
                .is_err()
        );
        assert!(
            client
                .service_operation("12345", "https://example.com/steal")
                .await
                .is_err()
        );
        assert!(transport.requests.lock().expect("requests").is_empty());
    }
}
