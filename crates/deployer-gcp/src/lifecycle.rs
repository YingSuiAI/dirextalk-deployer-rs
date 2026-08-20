use std::collections::BTreeMap;

use async_trait::async_trait;
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::{GcpError, GoogleRestClient, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Network,
    Subnetwork,
    Firewall,
    Address,
    Disk,
    Instance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", content = "name", rename_all = "snake_case")]
pub enum OperationScope {
    Global,
    Region(String),
    Zone(String),
    DnsZone(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub name: String,
    pub self_link: String,
    pub project_number: String,
    pub scope: OperationScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationFailure {
    pub code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", content = "failure", rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    Succeeded,
    Failed(OperationFailure),
}

impl OperationState {
    fn from_wire(status: &str, error: Option<OperationErrorWire>) -> Result<Self> {
        match status {
            "PENDING" | "RUNNING" => Ok(Self::Pending),
            "DONE" if error.as_ref().is_none_or(|error| error.errors.is_empty()) => {
                Ok(Self::Succeeded)
            }
            "DONE" => {
                let error = error
                    .and_then(|error| error.errors.into_iter().next())
                    .expect("DONE error was checked as non-empty");
                Ok(Self::Failed(OperationFailure {
                    code: error.code,
                    message: error
                        .message
                        .unwrap_or_else(|| "Google operation failed".into()),
                }))
            }
            other => Err(GcpError::Infrastructure(format!(
                "Google operation returned unknown status {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceIdentity {
    pub kind: ResourceKind,
    pub name: String,
    pub project_number: String,
    pub location: Option<String>,
    pub numeric_id: String,
    pub self_link: String,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceReceipt {
    pub identity: ResourceIdentity,
    pub observed_attributes: BTreeMap<String, Value>,
}

pub fn validate_resource_identity(
    expected: &ResourceIdentity,
    observed: &ResourceReceipt,
) -> Result<()> {
    let actual = &observed.identity;
    if actual.kind != expected.kind
        || actual.name != expected.name
        || actual.project_number != expected.project_number
        || actual.location != expected.location
        || actual.numeric_id != expected.numeric_id
        || actual.self_link != expected.self_link
        || actual.deployment_uuid != expected.deployment_uuid
    {
        return Err(GcpError::Contract(format!(
            "immutable identity mismatch for {:?} {}: expected numeric id {}, observed {}",
            expected.kind, expected.name, expected.numeric_id, actual.numeric_id
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    pub name: String,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubnetworkSpec {
    pub name: String,
    pub region: String,
    pub network_self_link: String,
    pub cidr: String,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirewallSpec {
    pub name: String,
    pub network_self_link: String,
    pub source_ranges: Vec<String>,
    pub target_tag: String,
    pub allowed: Vec<FirewallAllowance>,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirewallAllowance {
    pub protocol: String,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddressSpec {
    pub name: String,
    pub region: String,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiskSpec {
    pub name: String,
    pub zone: String,
    pub size_gib: u32,
    pub disk_type: String,
    pub source_image: String,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstanceSpec {
    pub name: String,
    pub zone: String,
    pub machine_type: String,
    pub subnetwork_self_link: String,
    pub address: String,
    pub boot_disk_self_link: String,
    pub network_tags: Vec<String>,
    pub ssh_username: String,
    pub ssh_public_key: String,
    pub deployment_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsRecordSet {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub rrdatas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsChange {
    pub managed_zone: String,
    pub additions: Vec<DnsRecordSet>,
    pub deletions: Vec<DnsRecordSet>,
}

#[async_trait]
pub trait GcpLifecycle: Send + Sync {
    async fn start_network(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &NetworkSpec,
    ) -> Result<Operation>;
    async fn start_subnetwork(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &SubnetworkSpec,
    ) -> Result<Operation>;
    async fn start_firewall(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &FirewallSpec,
    ) -> Result<Operation>;
    async fn start_address(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &AddressSpec,
    ) -> Result<Operation>;
    async fn start_disk(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &DiskSpec,
    ) -> Result<Operation>;
    async fn start_instance(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &InstanceSpec,
    ) -> Result<Operation>;
    async fn start_dns_change(
        &self,
        project_number: &str,
        request_id: Uuid,
        change: &DnsChange,
    ) -> Result<Operation>;
    async fn poll_operation(
        &self,
        project_number: &str,
        operation: &Operation,
    ) -> Result<OperationState>;
    async fn get_resource(
        &self,
        project_number: &str,
        kind: ResourceKind,
        name: &str,
        location: Option<&str>,
    ) -> Result<ResourceReceipt>;
    async fn start_delete(
        &self,
        project_number: &str,
        request_id: Uuid,
        identity: &ResourceIdentity,
    ) -> Result<Operation>;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationWire {
    name: String,
    self_link: Option<String>,
    status: String,
    error: Option<OperationErrorWire>,
}

#[derive(Deserialize)]
struct OperationErrorWire {
    #[serde(default)]
    errors: Vec<OperationErrorItemWire>,
}

#[derive(Deserialize)]
struct OperationErrorItemWire {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct DnsChangeWire {
    id: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceWire {
    id: String,
    name: String,
    self_link: String,
    description: Option<String>,
    region: Option<String>,
    zone: Option<String>,
    #[serde(flatten)]
    attributes: BTreeMap<String, Value>,
}

#[async_trait]
impl GcpLifecycle for GoogleRestClient {
    async fn start_network(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &NetworkSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        self.start_compute(
            project_number,
            request_id,
            OperationScope::Global,
            format!("{}/global/networks", compute_project_url(&self.project_id)),
            json!({
                "name": spec.name,
                "description": deployment_marker(spec.deployment_uuid),
                "autoCreateSubnetworks": false,
                "routingConfig": { "routingMode": "GLOBAL" }
            }),
        )
        .await
    }

    async fn start_subnetwork(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &SubnetworkSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        validate_name(&spec.region)?;
        require_self_link(
            &spec.network_self_link,
            &self.project_id,
            "/global/networks/",
        )?;
        self.start_compute(
            project_number,
            request_id,
            OperationScope::Region(spec.region.clone()),
            format!(
                "{}/regions/{}/subnetworks",
                compute_project_url(&self.project_id),
                spec.region
            ),
            json!({
                "name": spec.name,
                "description": deployment_marker(spec.deployment_uuid),
                "network": spec.network_self_link,
                "ipCidrRange": spec.cidr,
                "stackType": "IPV4_ONLY"
            }),
        )
        .await
    }

    async fn start_firewall(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &FirewallSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        require_self_link(
            &spec.network_self_link,
            &self.project_id,
            "/global/networks/",
        )?;
        if spec.source_ranges.is_empty() || spec.allowed.is_empty() || spec.target_tag.is_empty() {
            return Err(GcpError::Contract(
                "firewall scope and allowances must be explicit".into(),
            ));
        }
        self.start_compute(
            project_number,
            request_id,
            OperationScope::Global,
            format!("{}/global/firewalls", compute_project_url(&self.project_id)),
            json!({
                "name": spec.name,
                "description": deployment_marker(spec.deployment_uuid),
                "network": spec.network_self_link,
                "direction": "INGRESS",
                "sourceRanges": spec.source_ranges,
                "targetTags": [spec.target_tag],
                "allowed": spec.allowed,
            }),
        )
        .await
    }

    async fn start_address(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &AddressSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        validate_name(&spec.region)?;
        self.start_compute(
            project_number,
            request_id,
            OperationScope::Region(spec.region.clone()),
            format!(
                "{}/regions/{}/addresses",
                compute_project_url(&self.project_id),
                spec.region
            ),
            json!({
                "name": spec.name,
                "description": deployment_marker(spec.deployment_uuid),
                "addressType": "EXTERNAL",
                "ipVersion": "IPV4",
                "networkTier": "PREMIUM"
            }),
        )
        .await
    }

    async fn start_disk(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &DiskSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        validate_name(&spec.zone)?;
        if spec.size_gib < 10 {
            return Err(GcpError::Contract(
                "boot disk must be at least 10 GiB".into(),
            ));
        }
        self.start_compute(
            project_number,
            request_id,
            OperationScope::Zone(spec.zone.clone()),
            format!("{}/zones/{}/disks", compute_project_url(&self.project_id), spec.zone),
            json!({
                "name": spec.name,
                "description": deployment_marker(spec.deployment_uuid),
                "sizeGb": spec.size_gib.to_string(),
                "type": format!("{}/zones/{}/diskTypes/{}", compute_project_url(&self.project_id), spec.zone, spec.disk_type),
                "sourceImage": spec.source_image,
                "labels": { "dirextalk-deployment": spec.deployment_uuid.to_string() }
            }),
        ).await
    }

    async fn start_instance(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &InstanceSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        validate_name(&spec.zone)?;
        require_self_link(
            &spec.subnetwork_self_link,
            &self.project_id,
            "/subnetworks/",
        )?;
        require_self_link(&spec.boot_disk_self_link, &self.project_id, "/disks/")?;
        if spec.address.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(GcpError::Contract(
                "instance address must be a reserved IPv4 address".into(),
            ));
        }
        validate_ssh(&spec.ssh_username, &spec.ssh_public_key)?;
        self.start_compute(
            project_number,
            request_id,
            OperationScope::Zone(spec.zone.clone()),
            format!("{}/zones/{}/instances", compute_project_url(&self.project_id), spec.zone),
            json!({
                "name": spec.name,
                "description": deployment_marker(spec.deployment_uuid),
                "machineType": format!("{}/zones/{}/machineTypes/{}", compute_project_url(&self.project_id), spec.zone, spec.machine_type),
                "canIpForward": false,
                "deletionProtection": false,
                "disks": [{
                    "boot": true,
                    "autoDelete": false,
                    "source": spec.boot_disk_self_link
                }],
                "networkInterfaces": [{
                    "subnetwork": spec.subnetwork_self_link,
                    "stackType": "IPV4_ONLY",
                    "accessConfigs": [{
                        "name": "External NAT",
                        "type": "ONE_TO_ONE_NAT",
                        "natIP": spec.address,
                        "networkTier": "PREMIUM"
                    }]
                }],
                "tags": { "items": spec.network_tags },
                "labels": { "dirextalk-deployment": spec.deployment_uuid.to_string() },
                "metadata": { "items": [{ "key": "ssh-keys", "value": format!("{}:{}", spec.ssh_username, spec.ssh_public_key) }] }
            }),
        ).await
    }

    async fn start_dns_change(
        &self,
        project_number: &str,
        request_id: Uuid,
        change: &DnsChange,
    ) -> Result<Operation> {
        validate_name(&change.managed_zone)?;
        if change.additions.is_empty() && change.deletions.is_empty() {
            return Err(GcpError::Contract(
                "DNS change has no additions or deletions".into(),
            ));
        }
        self.revalidate_project(project_number).await?;
        let base_url = Url::parse(&format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes",
            self.project_id, change.managed_zone
        ))?;
        let mut url = base_url.clone();
        url.query_pairs_mut()
            .append_pair("clientOperationId", &request_id.to_string());
        let response: DnsChangeWire = self
            .mutate(
                Method::POST,
                url.clone(),
                Some(json!({
                    "additions": change.additions,
                    "deletions": change.deletions,
                })),
            )
            .await?;
        let self_link = format!(
            "{}/{}",
            base_url.as_str().trim_end_matches('/'),
            response.id
        );
        let operation = Operation {
            name: response.id,
            self_link,
            project_number: project_number.into(),
            scope: OperationScope::DnsZone(change.managed_zone.clone()),
        };
        match response.status.as_str() {
            "pending" | "done" => Ok(operation),
            other => Err(GcpError::Infrastructure(format!(
                "Cloud DNS change returned unknown status {other}"
            ))),
        }
    }

    async fn poll_operation(
        &self,
        project_number: &str,
        operation: &Operation,
    ) -> Result<OperationState> {
        self.assert_operation_identity(project_number, operation)?;
        self.revalidate_project(project_number).await?;
        if matches!(operation.scope, OperationScope::DnsZone(_)) {
            require_self_link(&operation.self_link, &self.project_id, "/changes/")?;
            let url = Url::parse(&operation.self_link)?;
            let change: DnsChangeWire = self.get(url).await?;
            if change.id != operation.name {
                return Err(GcpError::Contract(
                    "Cloud DNS change identity mismatch".into(),
                ));
            }
            return match change.status.as_str() {
                "pending" => Ok(OperationState::Pending),
                "done" => Ok(OperationState::Succeeded),
                other => Err(GcpError::Infrastructure(format!(
                    "Cloud DNS change returned unknown status {other}"
                ))),
            };
        }
        let url = trusted_operation_url(&operation.self_link, &self.project_id)?;
        let response: OperationWire = self.get(url).await?;
        if response.name != operation.name
            || response.self_link.as_deref() != Some(operation.self_link.as_str())
        {
            return Err(GcpError::Contract(
                "compute operation identity mismatch".into(),
            ));
        }
        OperationState::from_wire(&response.status, response.error)
    }

    async fn get_resource(
        &self,
        project_number: &str,
        kind: ResourceKind,
        name: &str,
        location: Option<&str>,
    ) -> Result<ResourceReceipt> {
        validate_name(name)?;
        self.revalidate_project(project_number).await?;
        let (url, expected_location) = resource_url(&self.project_id, kind, name, location)?;
        let resource: ResourceWire = self.get(url).await?;
        let deployment_uuid = deployment_uuid(&resource)?;
        let observed_location = resource
            .zone
            .as_deref()
            .or(resource.region.as_deref())
            .and_then(last_path_segment)
            .map(str::to_owned);
        if resource.name != name || observed_location != expected_location {
            return Err(GcpError::Contract(
                "resource name or location changed".into(),
            ));
        }
        Ok(ResourceReceipt {
            identity: ResourceIdentity {
                kind,
                name: resource.name,
                project_number: project_number.into(),
                location: expected_location,
                numeric_id: resource.id,
                self_link: resource.self_link,
                deployment_uuid,
            },
            observed_attributes: resource.attributes,
        })
    }

    async fn start_delete(
        &self,
        project_number: &str,
        request_id: Uuid,
        identity: &ResourceIdentity,
    ) -> Result<Operation> {
        if identity.project_number != project_number {
            return Err(GcpError::Contract(
                "delete project identity mismatch".into(),
            ));
        }
        let observed = self
            .get_resource(
                project_number,
                identity.kind,
                &identity.name,
                identity.location.as_deref(),
            )
            .await?;
        validate_resource_identity(identity, &observed)?;
        let mut url = Url::parse(&identity.self_link)?;
        require_self_link(
            identity.self_link.as_str(),
            &self.project_id,
            resource_collection(identity.kind),
        )?;
        self.revalidate_project(project_number).await?;
        url.query_pairs_mut()
            .append_pair("requestId", &request_id.to_string());
        let response: OperationWire = self.mutate(Method::DELETE, url, None).await?;
        operation_from_wire(response, project_number, scope_for_resource(identity)?)
    }
}

impl GoogleRestClient {
    async fn start_compute(
        &self,
        project_number: &str,
        request_id: Uuid,
        scope: OperationScope,
        url: String,
        body: Value,
    ) -> Result<Operation> {
        self.revalidate_project(project_number).await?;
        let mut url = Url::parse(&url)?;
        url.query_pairs_mut()
            .append_pair("requestId", &request_id.to_string());
        let response: OperationWire = self.mutate(Method::POST, url, Some(body)).await?;
        operation_from_wire(response, project_number, scope)
    }

    fn assert_operation_identity(&self, project_number: &str, operation: &Operation) -> Result<()> {
        if operation.project_number != project_number || project_number != self.project_number {
            return Err(GcpError::Contract(
                "operation project identity mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn operation_from_wire(
    response: OperationWire,
    project_number: &str,
    scope: OperationScope,
) -> Result<Operation> {
    let self_link = response
        .self_link
        .ok_or_else(|| GcpError::Infrastructure("compute operation omitted selfLink".into()))?;
    if response.name.is_empty() {
        return Err(GcpError::Infrastructure(
            "compute operation omitted name".into(),
        ));
    }
    Ok(Operation {
        name: response.name,
        self_link,
        project_number: project_number.into(),
        scope,
    })
}

fn resource_url(
    project_id: &str,
    kind: ResourceKind,
    name: &str,
    location: Option<&str>,
) -> Result<(Url, Option<String>)> {
    let root = compute_project_url(project_id);
    let (path, observed_location) = match kind {
        ResourceKind::Network => (format!("global/networks/{name}"), None),
        ResourceKind::Firewall => (format!("global/firewalls/{name}"), None),
        ResourceKind::Subnetwork => {
            let region = required_location(kind, location)?;
            (
                format!("regions/{region}/subnetworks/{name}"),
                Some(region.into()),
            )
        }
        ResourceKind::Address => {
            let region = required_location(kind, location)?;
            (
                format!("regions/{region}/addresses/{name}"),
                Some(region.into()),
            )
        }
        ResourceKind::Disk => {
            let zone = required_location(kind, location)?;
            (format!("zones/{zone}/disks/{name}"), Some(zone.into()))
        }
        ResourceKind::Instance => {
            let zone = required_location(kind, location)?;
            (format!("zones/{zone}/instances/{name}"), Some(zone.into()))
        }
    };
    Ok((Url::parse(&format!("{root}/{path}"))?, observed_location))
}

fn required_location(kind: ResourceKind, location: Option<&str>) -> Result<&str> {
    let location =
        location.ok_or_else(|| GcpError::Contract(format!("{kind:?} requires a location")))?;
    validate_name(location)?;
    Ok(location)
}

fn scope_for_resource(identity: &ResourceIdentity) -> Result<OperationScope> {
    match identity.kind {
        ResourceKind::Network | ResourceKind::Firewall => Ok(OperationScope::Global),
        ResourceKind::Subnetwork | ResourceKind::Address => Ok(OperationScope::Region(
            required_location(identity.kind, identity.location.as_deref())?.into(),
        )),
        ResourceKind::Disk | ResourceKind::Instance => Ok(OperationScope::Zone(
            required_location(identity.kind, identity.location.as_deref())?.into(),
        )),
    }
}

fn resource_collection(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Network => "/global/networks/",
        ResourceKind::Firewall => "/global/firewalls/",
        ResourceKind::Subnetwork => "/subnetworks/",
        ResourceKind::Address => "/addresses/",
        ResourceKind::Disk => "/disks/",
        ResourceKind::Instance => "/instances/",
    }
}

fn deployment_uuid(resource: &ResourceWire) -> Result<Uuid> {
    let marker = resource
        .description
        .as_deref()
        .and_then(|description| description.strip_prefix("dirextalk-deployment:"));
    let label = resource
        .attributes
        .get("labels")
        .and_then(|labels| labels.get("dirextalk-deployment"))
        .and_then(Value::as_str);
    let value = marker.or(label).ok_or_else(|| {
        GcpError::Contract("resource has no Dirextalk deployment identity".into())
    })?;
    Uuid::parse_str(value)
        .map_err(|_| GcpError::Contract("resource deployment identity is invalid".into()))
}

fn deployment_marker(uuid: Uuid) -> String {
    format!("dirextalk-deployment:{uuid}")
}

fn compute_project_url(project_id: &str) -> String {
    format!("https://compute.googleapis.com/compute/v1/projects/{project_id}")
}

fn trusted_operation_url(value: &str, project_id: &str) -> Result<Url> {
    require_self_link(value, project_id, "/operations/")?;
    Url::parse(value).map_err(Into::into)
}

fn require_self_link(value: &str, project_id: &str, collection: &str) -> Result<()> {
    let url = Url::parse(value)?;
    if url.scheme() != "https"
        || url
            .host_str()
            .is_none_or(|host| host != "compute.googleapis.com" && host != "dns.googleapis.com")
        || !url.path().contains(&format!("/projects/{project_id}/"))
        || !url.path().contains(collection)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GcpError::Contract(format!(
            "untrusted or mismatched GCP self-link {url}"
        )));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(GcpError::Contract(format!(
            "invalid GCP resource name {value:?}"
        )))
    }
}

fn validate_ssh(username: &str, public_key: &str) -> Result<()> {
    let valid_user = !username.is_empty()
        && username.len() <= 32
        && username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
        && username
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase);
    let valid_key = !public_key.contains(['\r', '\n', ':'])
        && (public_key.starts_with("ssh-ed25519 ")
            || public_key.starts_with("ecdsa-sha2-nistp256 "))
        && public_key.len() <= 2048;
    if valid_user && valid_key {
        Ok(())
    } else {
        Err(GcpError::Contract("invalid instance SSH identity".into()))
    }
}

fn last_path_segment(value: &str) -> Option<&str> {
    value
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_wire(status: &str, error: Option<OperationErrorWire>) -> OperationState {
        OperationState::from_wire(status, error).expect("known status")
    }

    #[test]
    fn operation_has_pending_success_and_failed_states() {
        assert_eq!(operation_wire("RUNNING", None), OperationState::Pending);
        assert_eq!(operation_wire("DONE", None), OperationState::Succeeded);
        let failed = operation_wire(
            "DONE",
            Some(OperationErrorWire {
                errors: vec![OperationErrorItemWire {
                    code: Some("QUOTA_EXCEEDED".into()),
                    message: Some("quota exhausted".into()),
                }],
            }),
        );
        assert_eq!(
            failed,
            OperationState::Failed(OperationFailure {
                code: Some("QUOTA_EXCEEDED".into()),
                message: "quota exhausted".into()
            })
        );
        assert!(OperationState::from_wire("MYSTERY", None).is_err());
    }

    #[test]
    fn immutable_numeric_identity_mismatch_is_rejected() {
        let deployment_uuid = Uuid::new_v4();
        let expected = ResourceIdentity { kind: ResourceKind::Instance, name: "dirextalk-node".into(), project_number: "123".into(), location: Some("us-central1-a".into()), numeric_id: "100".into(), self_link: "https://compute.googleapis.com/compute/v1/projects/p/zones/us-central1-a/instances/dirextalk-node".into(), deployment_uuid };
        let observed = ResourceReceipt {
            identity: ResourceIdentity {
                numeric_id: "101".into(),
                ..expected.clone()
            },
            observed_attributes: BTreeMap::new(),
        };
        let error =
            validate_resource_identity(&expected, &observed).expect_err("replacement must fail");
        assert!(
            matches!(error, GcpError::Contract(message) if message.contains("identity mismatch"))
        );
    }
}
