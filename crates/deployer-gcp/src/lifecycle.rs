use std::collections::BTreeMap;

use async_trait::async_trait;
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::{GcpError, GoogleCloudClient, GoogleRestClient, Result};

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
    DnsZone(DnsZoneIdentity),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub name: String,
    pub numeric_id: String,
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

pub fn require_resource_absent(
    expected: &ResourceIdentity,
    observed: Option<&ResourceReceipt>,
) -> Result<()> {
    let Some(observed) = observed else {
        return Ok(());
    };
    validate_resource_identity(expected, observed)?;
    Err(GcpError::Infrastructure(format!(
        "GCP {:?} delete completed but the exact resource still exists",
        expected.kind
    )))
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
    pub source_image_id: String,
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

#[derive(Debug, Clone, Copy)]
pub enum ResourceSpecRef<'a> {
    Network(&'a NetworkSpec),
    Subnetwork(&'a SubnetworkSpec),
    Firewall(&'a FirewallSpec),
    Address(&'a AddressSpec),
    Disk(&'a DiskSpec),
    Instance(&'a InstanceSpec),
}

pub fn validate_resource_properties(
    spec: ResourceSpecRef<'_>,
    receipt: &ResourceReceipt,
) -> Result<()> {
    let (kind, name, location, deployment_uuid, expected) = expected_resource_properties(spec);
    if receipt.identity.kind != kind
        || receipt.identity.name != name
        || receipt.identity.location.as_deref() != location
        || receipt.identity.deployment_uuid != deployment_uuid
    {
        return Err(GcpError::Contract(
            "observed resource does not match the planned resource identity".into(),
        ));
    }
    if kind == ResourceKind::Address {
        let valid_address = receipt
            .observed_attributes
            .get("address")
            .and_then(Value::as_str)
            .is_some_and(|address| address.parse::<std::net::Ipv4Addr>().is_ok());
        if !valid_address {
            return Err(GcpError::Contract(
                "observed Address property address does not satisfy the plan".into(),
            ));
        }
    }
    for (key, expected_value) in expected {
        if receipt.observed_attributes.get(&key) != Some(&expected_value) {
            return Err(GcpError::Contract(format!(
                "observed {kind:?} property {key} does not satisfy the plan"
            )));
        }
    }
    Ok(())
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
pub struct DnsZoneIdentity {
    pub project_id: String,
    pub name: String,
    pub numeric_id: String,
}

pub fn validate_dns_zone_identity(
    expected: &DnsZoneIdentity,
    observed: &DnsZoneIdentity,
) -> Result<()> {
    validate_dns_zone_reference(expected, &expected.project_id)?;
    if expected != observed {
        return Err(GcpError::Contract(format!(
            "Cloud DNS managed zone identity changed: expected {}/{}, numeric id {}; observed {}/{}, numeric id {}",
            expected.project_id,
            expected.name,
            expected.numeric_id,
            observed.project_id,
            observed.name,
            observed.numeric_id
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsChange {
    pub managed_zone: DnsZoneIdentity,
    pub expected_current: Option<DnsRecordSet>,
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
    async fn get_dns_record_set(
        &self,
        project_number: &str,
        zone: &DnsZoneIdentity,
        name: &str,
        record_type: &str,
    ) -> Result<Option<DnsRecordSet>>;
    async fn start_dns_change(
        &self,
        project_number: &str,
        request_id: Uuid,
        change: &DnsChange,
    ) -> Result<Option<Operation>>;
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
    ) -> Result<Option<ResourceReceipt>>;
    async fn start_delete(
        &self,
        project_number: &str,
        request_id: Uuid,
        identity: &ResourceIdentity,
    ) -> Result<Option<Operation>>;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationWire {
    id: String,
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
    ) -> Result<Option<Operation>> {
        validate_dns_zone_reference(&change.managed_zone, &self.project_id)?;
        validate_dns_change(change)?;
        let record = change
            .additions
            .first()
            .or_else(|| change.deletions.first())
            .expect("validated DNS change has one record");
        let current = GcpLifecycle::get_dns_record_set(
            self,
            project_number,
            &change.managed_zone,
            &record.name,
            "A",
        )
        .await?;
        if dns_change_already_satisfied(change, current.as_ref())? {
            return Ok(None);
        }
        self.revalidate_project(project_number).await?;
        self.revalidate_dns_zone(&change.managed_zone).await?;
        let base_url = Url::parse(&format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes",
            self.project_id, change.managed_zone.name
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
            name: response.id.clone(),
            numeric_id: response.id,
            self_link,
            project_number: project_number.into(),
            scope: OperationScope::DnsZone(change.managed_zone.clone()),
        };
        match response.status.as_str() {
            "pending" | "done" => Ok(Some(operation)),
            other => Err(GcpError::Infrastructure(format!(
                "Cloud DNS change returned unknown status {other}"
            ))),
        }
    }

    async fn get_dns_record_set(
        &self,
        project_number: &str,
        zone: &DnsZoneIdentity,
        name: &str,
        record_type: &str,
    ) -> Result<Option<DnsRecordSet>> {
        validate_dns_zone_reference(zone, &self.project_id)?;
        self.revalidate_project(project_number).await?;
        self.revalidate_dns_zone(zone).await?;
        crate::GcpDiscovery::dns_record_set(self, &zone.project_id, &zone.name, name, record_type)
            .await
    }

    async fn poll_operation(
        &self,
        project_number: &str,
        operation: &Operation,
    ) -> Result<OperationState> {
        self.assert_operation_identity(project_number, operation)?;
        let operation_url = validate_operation_self_link(operation, &self.project_id)?;
        self.revalidate_project(project_number).await?;
        if let OperationScope::DnsZone(zone) = &operation.scope {
            self.revalidate_dns_zone(zone).await?;
            let change: DnsChangeWire = self.get(operation_url).await?;
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
        let response: OperationWire = self.get(operation_url).await?;
        validate_wire_operation_identity(&response, operation)?;
        OperationState::from_wire(&response.status, response.error)
    }

    async fn get_resource(
        &self,
        project_number: &str,
        kind: ResourceKind,
        name: &str,
        location: Option<&str>,
    ) -> Result<Option<ResourceReceipt>> {
        validate_name(name)?;
        self.revalidate_project(project_number).await?;
        let (url, expected_location) = resource_url(&self.project_id, kind, name, location)?;
        let resource: ResourceWire = match self.get(url).await {
            Ok(resource) => resource,
            Err(GcpError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
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
        validate_resource_self_link(
            &resource.self_link,
            &self.project_id,
            kind,
            name,
            expected_location.as_deref(),
        )?;
        Ok(Some(ResourceReceipt {
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
        }))
    }

    async fn start_delete(
        &self,
        project_number: &str,
        request_id: Uuid,
        identity: &ResourceIdentity,
    ) -> Result<Option<Operation>> {
        if identity.project_number != project_number {
            return Err(GcpError::Contract(
                "delete project identity mismatch".into(),
            ));
        }
        let Some(observed) = self
            .get_resource(
                project_number,
                identity.kind,
                &identity.name,
                identity.location.as_deref(),
            )
            .await?
        else {
            return Ok(None);
        };
        validate_resource_identity(identity, &observed)?;
        let mut url = Url::parse(&identity.self_link)?;
        validate_resource_self_link(
            &identity.self_link,
            &self.project_id,
            identity.kind,
            &identity.name,
            identity.location.as_deref(),
        )?;
        self.revalidate_project(project_number).await?;
        url.query_pairs_mut()
            .append_pair("requestId", &request_id.to_string());
        let response: OperationWire = self.mutate(Method::DELETE, url, None).await?;
        operation_from_wire(response, project_number, scope_for_resource(identity)?).map(Some)
    }
}

impl GoogleRestClient {
    async fn revalidate_dns_zone(&self, expected: &DnsZoneIdentity) -> Result<()> {
        #[derive(Deserialize)]
        struct ManagedZone {
            name: String,
            id: String,
        }

        validate_dns_zone_reference(expected, &self.project_id)?;
        let url = Url::parse(&format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}",
            expected.project_id, expected.name
        ))?;
        let zone: ManagedZone = self.get(url).await?;
        validate_dns_zone_identity(
            expected,
            &DnsZoneIdentity {
                project_id: expected.project_id.clone(),
                name: zone.name,
                numeric_id: zone.id,
            },
        )
    }

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
        validate_operation_numeric_id(operation)?;
        Ok(())
    }
}

#[async_trait]
impl GcpLifecycle for GoogleCloudClient {
    async fn start_network(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &NetworkSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        self.revalidate_project(project_number).await?;
        let body = google_cloud_compute_v1::model::Network::new()
            .set_name(&spec.name)
            .set_description(deployment_marker(spec.deployment_uuid))
            .set_auto_create_subnetworks(false)
            .set_routing_config(
                google_cloud_compute_v1::model::NetworkRoutingConfig::new().set_routing_mode(
                    google_cloud_compute_v1::model::network_routing_config::RoutingMode::Global,
                ),
            );
        let response = self
            .networks
            .insert()
            .set_project(&self.project_id)
            .set_request_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        operation_from_sdk(response, project_number, OperationScope::Global)
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
        self.revalidate_project(project_number).await?;
        let body = google_cloud_compute_v1::model::Subnetwork::new()
            .set_name(&spec.name)
            .set_description(deployment_marker(spec.deployment_uuid))
            .set_network(&spec.network_self_link)
            .set_ip_cidr_range(&spec.cidr)
            .set_stack_type(google_cloud_compute_v1::model::subnetwork::StackType::Ipv4Only);
        let response = self
            .subnetworks
            .insert()
            .set_project(&self.project_id)
            .set_region(&spec.region)
            .set_request_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        operation_from_sdk(
            response,
            project_number,
            OperationScope::Region(spec.region.clone()),
        )
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
        self.revalidate_project(project_number).await?;
        let allowed = spec.allowed.iter().map(|item| {
            google_cloud_compute_v1::model::firewall::Allowed::new()
                .set_ip_protocol(&item.protocol)
                .set_ports(item.ports.clone())
        });
        let body = google_cloud_compute_v1::model::Firewall::new()
            .set_name(&spec.name)
            .set_description(deployment_marker(spec.deployment_uuid))
            .set_network(&spec.network_self_link)
            .set_direction(google_cloud_compute_v1::model::firewall::Direction::Ingress)
            .set_source_ranges(spec.source_ranges.clone())
            .set_target_tags([spec.target_tag.clone()])
            .set_allowed(allowed);
        let response = self
            .firewalls
            .insert()
            .set_project(&self.project_id)
            .set_request_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        operation_from_sdk(response, project_number, OperationScope::Global)
    }

    async fn start_address(
        &self,
        project_number: &str,
        request_id: Uuid,
        spec: &AddressSpec,
    ) -> Result<Operation> {
        validate_name(&spec.name)?;
        validate_name(&spec.region)?;
        self.revalidate_project(project_number).await?;
        let body = google_cloud_compute_v1::model::Address::new()
            .set_name(&spec.name)
            .set_description(deployment_marker(spec.deployment_uuid))
            .set_address_type(google_cloud_compute_v1::model::address::AddressType::External)
            .set_ip_version(google_cloud_compute_v1::model::address::IpVersion::Ipv4)
            .set_network_tier(google_cloud_compute_v1::model::address::NetworkTier::Premium);
        let response = self
            .addresses
            .insert()
            .set_project(&self.project_id)
            .set_region(&spec.region)
            .set_request_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        operation_from_sdk(
            response,
            project_number,
            OperationScope::Region(spec.region.clone()),
        )
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
        self.revalidate_project(project_number).await?;
        let body = google_cloud_compute_v1::model::Disk::new()
            .set_name(&spec.name)
            .set_description(deployment_marker(spec.deployment_uuid))
            .set_size_gb(i64::from(spec.size_gib))
            .set_type(format!(
                "{}/zones/{}/diskTypes/{}",
                compute_project_url(&self.project_id),
                spec.zone,
                spec.disk_type
            ))
            .set_source_image(&spec.source_image)
            .set_labels([("dirextalk-deployment", spec.deployment_uuid.to_string())]);
        let response = self
            .disks
            .insert()
            .set_project(&self.project_id)
            .set_zone(&spec.zone)
            .set_request_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        operation_from_sdk(
            response,
            project_number,
            OperationScope::Zone(spec.zone.clone()),
        )
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
        self.revalidate_project(project_number).await?;
        let disk = google_cloud_compute_v1::model::AttachedDisk::new()
            .set_boot(true)
            .set_auto_delete(false)
            .set_source(&spec.boot_disk_self_link);
        let access = google_cloud_compute_v1::model::AccessConfig::new()
            .set_name("External NAT")
            .set_type(google_cloud_compute_v1::model::access_config::Type::OneToOneNat)
            .set_nat_ip(&spec.address)
            .set_network_tier(google_cloud_compute_v1::model::access_config::NetworkTier::Premium);
        let interface = google_cloud_compute_v1::model::NetworkInterface::new()
            .set_subnetwork(&spec.subnetwork_self_link)
            .set_stack_type(google_cloud_compute_v1::model::network_interface::StackType::Ipv4Only)
            .set_access_configs([access]);
        let metadata = google_cloud_compute_v1::model::Metadata::new().set_items([
            google_cloud_compute_v1::model::metadata::Items::new()
                .set_key("ssh-keys")
                .set_value(format!("{}:{}", spec.ssh_username, spec.ssh_public_key)),
        ]);
        let body = google_cloud_compute_v1::model::Instance::new()
            .set_name(&spec.name)
            .set_description(deployment_marker(spec.deployment_uuid))
            .set_machine_type(format!(
                "{}/zones/{}/machineTypes/{}",
                compute_project_url(&self.project_id),
                spec.zone,
                spec.machine_type
            ))
            .set_can_ip_forward(false)
            .set_deletion_protection(false)
            .set_disks([disk])
            .set_network_interfaces([interface])
            .set_tags(
                google_cloud_compute_v1::model::Tags::new().set_items(spec.network_tags.clone()),
            )
            .set_labels([("dirextalk-deployment", spec.deployment_uuid.to_string())])
            .set_metadata(metadata);
        if !body.service_accounts.is_empty() {
            return Err(GcpError::Contract(
                "VM service account must be absent".into(),
            ));
        }
        let response = self
            .instances
            .insert()
            .set_project(&self.project_id)
            .set_zone(&spec.zone)
            .set_request_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        operation_from_sdk(
            response,
            project_number,
            OperationScope::Zone(spec.zone.clone()),
        )
    }

    async fn start_dns_change(
        &self,
        project_number: &str,
        request_id: Uuid,
        change: &DnsChange,
    ) -> Result<Option<Operation>> {
        validate_dns_zone_reference(&change.managed_zone, &self.project_id)?;
        validate_dns_change(change)?;
        let record = change
            .additions
            .first()
            .or_else(|| change.deletions.first())
            .expect("validated DNS record");
        let current = GcpLifecycle::get_dns_record_set(
            self,
            project_number,
            &change.managed_zone,
            &record.name,
            "A",
        )
        .await?;
        if dns_change_already_satisfied(change, current.as_ref())? {
            return Ok(None);
        }
        self.revalidate_project(project_number).await?;
        self.revalidate_dns_zone(&change.managed_zone).await?;
        let convert = |record: &DnsRecordSet| {
            let mut value = google_cloud_dns_v1::model::ResourceRecordSet::new()
                .set_name(&record.name)
                .set_ttl(i32::try_from(record.ttl).expect("validated TTL"))
                .set_rrdatas(record.rrdatas.clone());
            value.r#type = Some(record.record_type.clone());
            value
        };
        let body = google_cloud_dns_v1::model::Change::new()
            .set_additions(change.additions.iter().map(convert))
            .set_deletions(change.deletions.iter().map(convert));
        let response = self
            .dns_changes
            .create()
            .set_project(&self.project_id)
            .set_managed_zone(&change.managed_zone.name)
            .set_client_operation_id(request_id.to_string())
            .set_body(body)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        let id = response
            .id
            .ok_or_else(|| GcpError::Infrastructure("Cloud DNS operation omitted id".into()))?;
        Ok(Some(Operation {
            name: id.clone(),
            numeric_id: id.clone(),
            self_link: format!(
                "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes/{id}",
                self.project_id, change.managed_zone.name
            ),
            project_number: project_number.into(),
            scope: OperationScope::DnsZone(change.managed_zone.clone()),
        }))
    }

    async fn get_dns_record_set(
        &self,
        project_number: &str,
        zone: &DnsZoneIdentity,
        name: &str,
        record_type: &str,
    ) -> Result<Option<DnsRecordSet>> {
        validate_dns_zone_reference(zone, &self.project_id)?;
        self.revalidate_project(project_number).await?;
        self.revalidate_dns_zone(zone).await?;
        crate::GcpDiscovery::dns_record_set(self, &zone.project_id, &zone.name, name, record_type)
            .await
    }

    async fn poll_operation(
        &self,
        project_number: &str,
        operation: &Operation,
    ) -> Result<OperationState> {
        self.assert_operation_identity(project_number, operation)?;
        validate_operation_self_link(operation, &self.project_id)?;
        self.revalidate_project(project_number).await?;
        if let OperationScope::DnsZone(zone) = &operation.scope {
            self.revalidate_dns_zone(zone).await?;
            let response = self
                .dns_changes
                .get()
                .set_project(&self.project_id)
                .set_managed_zone(&zone.name)
                .set_change_id(&operation.name)
                .send()
                .await
                .map_err(crate::official::official_error)?;
            if response.id.as_deref() != Some(&operation.name) {
                return Err(GcpError::Contract(
                    "Cloud DNS change identity mismatch".into(),
                ));
            }
            return match response
                .status
                .and_then(|status| status.name().map(str::to_owned))
                .as_deref()
            {
                Some("PENDING") => Ok(OperationState::Pending),
                Some("DONE") => Ok(OperationState::Succeeded),
                _ => Err(GcpError::Infrastructure(
                    "Cloud DNS returned unknown operation state".into(),
                )),
            };
        }
        let response = match &operation.scope {
            OperationScope::Global => {
                self.global_operations
                    .get()
                    .set_project(&self.project_id)
                    .set_operation(&operation.name)
                    .send()
                    .await
            }
            OperationScope::Region(region) => {
                self.region_operations
                    .get()
                    .set_project(&self.project_id)
                    .set_region(region)
                    .set_operation(&operation.name)
                    .send()
                    .await
            }
            OperationScope::Zone(zone) => {
                self.zone_operations
                    .get()
                    .set_project(&self.project_id)
                    .set_zone(zone)
                    .set_operation(&operation.name)
                    .send()
                    .await
            }
            OperationScope::DnsZone(_) => unreachable!(),
        }
        .map_err(crate::official::official_error)?;
        validate_sdk_operation_identity(&response, operation)?;
        operation_state_from_sdk(response)
    }

    async fn get_resource(
        &self,
        project_number: &str,
        kind: ResourceKind,
        name: &str,
        location: Option<&str>,
    ) -> Result<Option<ResourceReceipt>> {
        self.get_resource_sdk(project_number, kind, name, location)
            .await
    }

    async fn start_delete(
        &self,
        project_number: &str,
        request_id: Uuid,
        identity: &ResourceIdentity,
    ) -> Result<Option<Operation>> {
        if identity.project_number != project_number {
            return Err(GcpError::Contract(
                "delete project identity mismatch".into(),
            ));
        }
        let Some(observed) = self
            .get_resource_sdk(
                project_number,
                identity.kind,
                &identity.name,
                identity.location.as_deref(),
            )
            .await?
        else {
            return Ok(None);
        };
        validate_resource_identity(identity, &observed)?;
        self.revalidate_project(project_number).await?;
        let response = match identity.kind {
            ResourceKind::Network => {
                self.networks
                    .delete()
                    .set_project(&self.project_id)
                    .set_network(&identity.name)
                    .set_request_id(request_id.to_string())
                    .send()
                    .await
            }
            ResourceKind::Firewall => {
                self.firewalls
                    .delete()
                    .set_project(&self.project_id)
                    .set_firewall(&identity.name)
                    .set_request_id(request_id.to_string())
                    .send()
                    .await
            }
            ResourceKind::Subnetwork => {
                self.subnetworks
                    .delete()
                    .set_project(&self.project_id)
                    .set_region(required_location(
                        identity.kind,
                        identity.location.as_deref(),
                    )?)
                    .set_subnetwork(&identity.name)
                    .set_request_id(request_id.to_string())
                    .send()
                    .await
            }
            ResourceKind::Address => {
                self.addresses
                    .delete()
                    .set_project(&self.project_id)
                    .set_region(required_location(
                        identity.kind,
                        identity.location.as_deref(),
                    )?)
                    .set_address(&identity.name)
                    .set_request_id(request_id.to_string())
                    .send()
                    .await
            }
            ResourceKind::Disk => {
                self.disks
                    .delete()
                    .set_project(&self.project_id)
                    .set_zone(required_location(
                        identity.kind,
                        identity.location.as_deref(),
                    )?)
                    .set_disk(&identity.name)
                    .set_request_id(request_id.to_string())
                    .send()
                    .await
            }
            ResourceKind::Instance => {
                self.instances
                    .delete()
                    .set_project(&self.project_id)
                    .set_zone(required_location(
                        identity.kind,
                        identity.location.as_deref(),
                    )?)
                    .set_instance(&identity.name)
                    .set_request_id(request_id.to_string())
                    .send()
                    .await
            }
        }
        .map_err(crate::official::official_error)?;
        operation_from_sdk(response, project_number, scope_for_resource(identity)?).map(Some)
    }
}

impl GoogleCloudClient {
    async fn revalidate_dns_zone(&self, expected: &DnsZoneIdentity) -> Result<()> {
        validate_dns_zone_reference(expected, &self.project_id)?;
        let zone = self
            .dns_zones
            .get()
            .set_project(&expected.project_id)
            .set_managed_zone(&expected.name)
            .send()
            .await
            .map_err(crate::official::official_error)?;
        let observed = DnsZoneIdentity {
            project_id: expected.project_id.clone(),
            name: zone.name.ok_or_else(|| {
                GcpError::Infrastructure("Cloud DNS managed zone omitted name".into())
            })?,
            numeric_id: zone
                .id
                .ok_or_else(|| {
                    GcpError::Infrastructure("Cloud DNS managed zone omitted numeric id".into())
                })?
                .to_string(),
        };
        validate_dns_zone_identity(expected, &observed)
    }

    async fn revalidate_project(&self, expected_project_number: &str) -> Result<()> {
        if expected_project_number != self.project_number {
            return Err(GcpError::Contract(
                "official client project identity mismatch".into(),
            ));
        }
        let project = self
            .projects
            .get_project()
            .set_name(format!("projects/{}", self.project_id))
            .send()
            .await
            .map_err(crate::official::official_error)?;
        let observed_number = project
            .name
            .strip_prefix("projects/")
            .unwrap_or(&project.name);
        if observed_number != expected_project_number || project.state.name() != Some("ACTIVE") {
            return Err(GcpError::Contract(
                "project identity changed or project is not active".into(),
            ));
        }
        Ok(())
    }

    fn assert_operation_identity(&self, project_number: &str, operation: &Operation) -> Result<()> {
        if project_number != self.project_number || operation.project_number != project_number {
            return Err(GcpError::Contract(
                "operation project identity mismatch".into(),
            ));
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "each GCE resource has a distinct official SDK client and receipt shape"
    )]
    async fn get_resource_sdk(
        &self,
        project_number: &str,
        kind: ResourceKind,
        name: &str,
        location: Option<&str>,
    ) -> Result<Option<ResourceReceipt>> {
        validate_name(name)?;
        self.revalidate_project(project_number).await?;
        match kind {
            ResourceKind::Network => {
                let Some(value) = optional_sdk_response(
                    self.networks
                        .get()
                        .set_project(&self.project_id)
                        .set_network(name)
                        .send()
                        .await,
                )?
                else {
                    return Ok(None);
                };
                let routing_mode = value
                    .routing_config
                    .as_ref()
                    .and_then(|config| config.routing_mode.as_ref())
                    .and_then(|mode| mode.name());
                let attributes = BTreeMap::from([
                    (
                        "auto_create_subnetworks".into(),
                        json!(value.auto_create_subnetworks),
                    ),
                    ("routing_mode".into(), json!(routing_mode)),
                ]);
                sdk_receipt(
                    kind,
                    name,
                    &self.project_id,
                    project_number,
                    None,
                    value.id,
                    value.self_link,
                    value.description,
                    None,
                    attributes,
                )
                .map(Some)
            }
            ResourceKind::Firewall => {
                let Some(value) = optional_sdk_response(
                    self.firewalls
                        .get()
                        .set_project(&self.project_id)
                        .set_firewall(name)
                        .send()
                        .await,
                )?
                else {
                    return Ok(None);
                };
                let allowed: Vec<_> = value
                    .allowed
                    .iter()
                    .map(|allowed| FirewallAllowance {
                        protocol: allowed.ip_protocol.clone().unwrap_or_default(),
                        ports: allowed.ports.clone(),
                    })
                    .collect();
                let attributes = BTreeMap::from([
                    ("allowed".into(), normalized_firewall_allowances(&allowed)),
                    (
                        "network".into(),
                        json!(value.network.as_deref().map(normalized_resource_reference)),
                    ),
                    (
                        "source_ranges".into(),
                        json!(sorted_strings(value.source_ranges.clone())),
                    ),
                    (
                        "target_tags".into(),
                        json!(sorted_strings(value.target_tags.clone())),
                    ),
                ]);
                sdk_receipt(
                    kind,
                    name,
                    &self.project_id,
                    project_number,
                    None,
                    value.id,
                    value.self_link,
                    value.description,
                    None,
                    attributes,
                )
                .map(Some)
            }
            ResourceKind::Subnetwork => {
                let region = required_location(kind, location)?;
                let Some(value) = optional_sdk_response(
                    self.subnetworks
                        .get()
                        .set_project(&self.project_id)
                        .set_region(region)
                        .set_subnetwork(name)
                        .send()
                        .await,
                )?
                else {
                    return Ok(None);
                };
                let attributes = BTreeMap::from([
                    ("ip_cidr_range".into(), json!(value.ip_cidr_range)),
                    (
                        "network".into(),
                        json!(value.network.as_deref().map(normalized_resource_reference)),
                    ),
                ]);
                sdk_receipt(
                    kind,
                    name,
                    &self.project_id,
                    project_number,
                    Some(region),
                    value.id,
                    value.self_link,
                    value.description,
                    None,
                    attributes,
                )
                .map(Some)
            }
            ResourceKind::Address => {
                let region = required_location(kind, location)?;
                let Some(value) = optional_sdk_response(
                    self.addresses
                        .get()
                        .set_project(&self.project_id)
                        .set_region(region)
                        .set_address(name)
                        .send()
                        .await,
                )?
                else {
                    return Ok(None);
                };
                sdk_receipt(
                    kind,
                    name,
                    &self.project_id,
                    project_number,
                    Some(region),
                    value.id,
                    value.self_link,
                    value.description,
                    Some(&value.labels),
                    BTreeMap::from([("address".into(), json!(value.address))]),
                )
                .map(Some)
            }
            ResourceKind::Disk => {
                let zone = required_location(kind, location)?;
                let Some(value) = optional_sdk_response(
                    self.disks
                        .get()
                        .set_project(&self.project_id)
                        .set_zone(zone)
                        .set_disk(name)
                        .send()
                        .await,
                )?
                else {
                    return Ok(None);
                };
                let attributes = BTreeMap::from([
                    ("size_gb".into(), json!(value.size_gb)),
                    (
                        "source_image".into(),
                        json!(value.source_image.as_deref().and_then(last_path_segment)),
                    ),
                    ("source_image_id".into(), json!(value.source_image_id)),
                    (
                        "type".into(),
                        json!(value.r#type.as_deref().and_then(last_path_segment)),
                    ),
                ]);
                sdk_receipt(
                    kind,
                    name,
                    &self.project_id,
                    project_number,
                    Some(zone),
                    value.id,
                    value.self_link,
                    value.description,
                    Some(&value.labels),
                    attributes,
                )
                .map(Some)
            }
            ResourceKind::Instance => {
                let zone = required_location(kind, location)?;
                let Some(value) = optional_sdk_response(
                    self.instances
                        .get()
                        .set_project(&self.project_id)
                        .set_zone(zone)
                        .set_instance(name)
                        .send()
                        .await,
                )?
                else {
                    return Ok(None);
                };
                if !value.service_accounts.is_empty() {
                    return Err(GcpError::Contract(
                        "observed VM unexpectedly has a project service account".into(),
                    ));
                }
                let boot_disk = value.disks.iter().find(|disk| disk.boot == Some(true));
                let interface = value.network_interfaces.first();
                let access_config =
                    interface.and_then(|interface| interface.access_configs.first());
                let metadata_items = value
                    .metadata
                    .as_ref()
                    .map_or(&[][..], |metadata| metadata.items.as_slice());
                let ssh_keys_hash = metadata_items
                    .iter()
                    .find(|item| item.key.as_deref() == Some("ssh-keys"))
                    .and_then(|item| item.value.as_ref())
                    .map(|value| sha256_hex(value));
                let attributes = BTreeMap::from([
                    (
                        "access_config_count".into(),
                        json!(interface.map_or(0, |interface| interface.access_configs.len())),
                    ),
                    (
                        "boot_disk".into(),
                        json!(
                            boot_disk
                                .and_then(|disk| disk.source.as_deref())
                                .map(normalized_resource_reference)
                        ),
                    ),
                    (
                        "boot_disk_auto_delete".into(),
                        json!(boot_disk.and_then(|disk| disk.auto_delete)),
                    ),
                    ("can_ip_forward".into(), json!(value.can_ip_forward)),
                    (
                        "deletion_protection".into(),
                        json!(value.deletion_protection),
                    ),
                    ("disk_count".into(), json!(value.disks.len())),
                    (
                        "machine_type".into(),
                        json!(value.machine_type.as_deref().and_then(last_path_segment)),
                    ),
                    ("metadata_key_count".into(), json!(metadata_items.len())),
                    (
                        "nat_ip".into(),
                        json!(access_config.and_then(|access| access.nat_ip.as_deref())),
                    ),
                    (
                        "network_interface_count".into(),
                        json!(value.network_interfaces.len()),
                    ),
                    (
                        "network_tags".into(),
                        json!(sorted_strings(
                            value
                                .tags
                                .as_ref()
                                .map_or_else(Vec::new, |tags| tags.items.clone())
                        )),
                    ),
                    (
                        "service_account_count".into(),
                        json!(value.service_accounts.len()),
                    ),
                    ("ssh_keys_sha256".into(), json!(ssh_keys_hash)),
                    (
                        "subnetwork".into(),
                        json!(
                            interface
                                .and_then(|interface| interface.subnetwork.as_deref())
                                .map(normalized_resource_reference)
                        ),
                    ),
                ]);
                sdk_receipt(
                    kind,
                    name,
                    &self.project_id,
                    project_number,
                    Some(zone),
                    value.id,
                    value.self_link,
                    value.description,
                    Some(&value.labels),
                    attributes,
                )
                .map(Some)
            }
        }
    }
}

fn optional_sdk_response<T>(
    response: std::result::Result<T, google_cloud_gax::error::Error>,
) -> Result<Option<T>> {
    match response {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.http_status_code() == Some(404) => Ok(None),
        Err(error) => Err(crate::official::official_error(error)),
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    reason = "the helper normalizes identity fields shared by six generated GCE model types"
)]
fn sdk_receipt(
    kind: ResourceKind,
    expected_name: &str,
    project_id: &str,
    project_number: &str,
    location: Option<&str>,
    id: Option<u64>,
    self_link: Option<String>,
    description: Option<String>,
    labels: Option<&std::collections::HashMap<String, String>>,
    observed_attributes: BTreeMap<String, Value>,
) -> Result<ResourceReceipt> {
    let numeric_id = id
        .ok_or_else(|| GcpError::Infrastructure("GCP resource omitted numeric id".into()))?
        .to_string();
    let self_link = self_link
        .ok_or_else(|| GcpError::Infrastructure("GCP resource omitted self-link".into()))?;
    validate_resource_self_link(&self_link, project_id, kind, expected_name, location)?;
    let deployment = description
        .as_deref()
        .and_then(|value| value.strip_prefix("dirextalk-deployment:"))
        .or_else(|| {
            labels.and_then(|labels| labels.get("dirextalk-deployment").map(String::as_str))
        })
        .ok_or_else(|| {
            GcpError::Contract("resource has no Dirextalk deployment identity".into())
        })?;
    let deployment_uuid = Uuid::parse_str(deployment)
        .map_err(|_| GcpError::Contract("resource deployment identity is invalid".into()))?;
    if last_path_segment(&self_link) != Some(expected_name) {
        return Err(GcpError::Contract(
            "resource self-link name mismatch".into(),
        ));
    }
    Ok(ResourceReceipt {
        identity: ResourceIdentity {
            kind,
            name: expected_name.into(),
            project_number: project_number.into(),
            location: location.map(str::to_owned),
            numeric_id,
            self_link,
            deployment_uuid,
        },
        observed_attributes,
    })
}

fn operation_from_sdk(
    response: google_cloud_compute_v1::model::Operation,
    project_number: &str,
    scope: OperationScope,
) -> Result<Operation> {
    let name = response
        .name
        .ok_or_else(|| GcpError::Infrastructure("compute operation omitted name".into()))?;
    let numeric_id = response
        .id
        .ok_or_else(|| GcpError::Infrastructure("compute operation omitted numeric id".into()))?
        .to_string();
    let self_link = response
        .self_link
        .ok_or_else(|| GcpError::Infrastructure("compute operation omitted selfLink".into()))?;
    let operation = Operation {
        name,
        numeric_id,
        self_link,
        project_number: project_number.into(),
        scope,
    };
    validate_operation_numeric_id(&operation)?;
    Ok(operation)
}

fn validate_sdk_operation_identity(
    response: &google_cloud_compute_v1::model::Operation,
    expected: &Operation,
) -> Result<()> {
    if response.name.as_deref() != Some(&expected.name)
        || response.id.map(|id| id.to_string()).as_deref() != Some(&expected.numeric_id)
        || response.self_link.as_deref() != Some(&expected.self_link)
    {
        return Err(GcpError::Contract(
            "compute operation identity mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_wire_operation_identity(response: &OperationWire, expected: &Operation) -> Result<()> {
    if response.name != expected.name
        || response.id != expected.numeric_id
        || response.self_link.as_deref() != Some(expected.self_link.as_str())
    {
        return Err(GcpError::Contract(
            "compute operation identity mismatch".into(),
        ));
    }
    Ok(())
}

fn operation_state_from_sdk(
    response: google_cloud_compute_v1::model::Operation,
) -> Result<OperationState> {
    let status = response
        .status
        .and_then(|value| value.name().map(str::to_owned))
        .ok_or_else(|| GcpError::Infrastructure("compute operation omitted status".into()))?;
    match status.as_str() {
        "PENDING" | "RUNNING" => Ok(OperationState::Pending),
        "DONE"
            if response
                .error
                .as_ref()
                .is_none_or(|error| error.errors.is_empty()) =>
        {
            Ok(OperationState::Succeeded)
        }
        "DONE" => {
            let error = response
                .error
                .and_then(|error| error.errors.into_iter().next())
                .expect("DONE error checked non-empty");
            Ok(OperationState::Failed(OperationFailure {
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
    let operation = Operation {
        name: response.name,
        numeric_id: response.id,
        self_link,
        project_number: project_number.into(),
        scope,
    };
    validate_operation_numeric_id(&operation)?;
    Ok(operation)
}

fn validate_operation_numeric_id(operation: &Operation) -> Result<()> {
    if operation.numeric_id == "0"
        || operation.numeric_id.is_empty()
        || !operation
            .numeric_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(GcpError::Infrastructure(
            "Google operation omitted valid numeric id".into(),
        ));
    }
    Ok(())
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

fn validate_operation_self_link(operation: &Operation, project_id: &str) -> Result<Url> {
    let url = Url::parse(&operation.self_link)?;
    let expected = match &operation.scope {
        OperationScope::Global => {
            format!(
                "/projects/{project_id}/global/operations/{}",
                operation.name
            )
        }
        OperationScope::Region(region) => format!(
            "/projects/{project_id}/regions/{region}/operations/{}",
            operation.name
        ),
        OperationScope::Zone(zone) => format!(
            "/projects/{project_id}/zones/{zone}/operations/{}",
            operation.name
        ),
        OperationScope::DnsZone(zone) => format!(
            "/projects/{project_id}/managedZones/{}/changes/{}",
            zone.name, operation.name
        ),
    };
    let observed = match &operation.scope {
        OperationScope::DnsZone(_) => canonical_dns_path(&url),
        OperationScope::Global | OperationScope::Region(_) | OperationScope::Zone(_) => {
            canonical_compute_path(&url)
        }
    };
    if url.scheme() != "https"
        || observed != Some(expected.as_str())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GcpError::Contract(
            "operation self-link does not match its exact project, scope, and name".into(),
        ));
    }
    Ok(url)
}

fn validate_resource_self_link(
    value: &str,
    project_id: &str,
    kind: ResourceKind,
    name: &str,
    location: Option<&str>,
) -> Result<()> {
    let url = Url::parse(value)?;
    let expected = match kind {
        ResourceKind::Network => format!("/projects/{project_id}/global/networks/{name}"),
        ResourceKind::Firewall => format!("/projects/{project_id}/global/firewalls/{name}"),
        ResourceKind::Subnetwork => format!(
            "/projects/{project_id}/regions/{}/subnetworks/{name}",
            required_location(kind, location)?
        ),
        ResourceKind::Address => format!(
            "/projects/{project_id}/regions/{}/addresses/{name}",
            required_location(kind, location)?
        ),
        ResourceKind::Disk => format!(
            "/projects/{project_id}/zones/{}/disks/{name}",
            required_location(kind, location)?
        ),
        ResourceKind::Instance => format!(
            "/projects/{project_id}/zones/{}/instances/{name}",
            required_location(kind, location)?
        ),
    };
    if url.scheme() != "https"
        || canonical_compute_path(&url) != Some(expected.as_str())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GcpError::Contract(
            "resource self-link does not match its exact project, scope, kind, and name".into(),
        ));
    }
    Ok(())
}

fn canonical_compute_path(url: &Url) -> Option<&str> {
    match url.host_str()? {
        "compute.googleapis.com" | "www.googleapis.com" => url.path().strip_prefix("/compute/v1"),
        _ => None,
    }
}

fn canonical_dns_path(url: &Url) -> Option<&str> {
    match url.host_str()? {
        "dns.googleapis.com" => url.path().strip_prefix("/dns/v1"),
        _ => None,
    }
}

fn require_self_link(value: &str, project_id: &str, collection: &str) -> Result<()> {
    let url = Url::parse(value)?;
    let path = canonical_compute_path(&url).or_else(|| canonical_dns_path(&url));
    let expected_prefix = format!("/projects/{project_id}/");
    if url.scheme() != "https"
        || path.is_none_or(|path| {
            !path.starts_with(&expected_prefix)
                || !path
                    .rsplit_once(collection)
                    .is_some_and(|(_, leaf)| !leaf.is_empty() && !leaf.contains('/'))
        })
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

fn validate_dns_zone_reference(zone: &DnsZoneIdentity, project_id: &str) -> Result<()> {
    validate_name(&zone.name)?;
    if zone.project_id != project_id
        || zone
            .numeric_id
            .parse::<u64>()
            .ok()
            .is_none_or(|numeric_id| numeric_id == 0)
    {
        return Err(GcpError::Contract(
            "Cloud DNS managed zone must bind the exact project, name, and nonzero numeric id"
                .into(),
        ));
    }
    Ok(())
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

fn validate_dns_change(change: &DnsChange) -> Result<()> {
    if change.additions.len() > 1
        || change.deletions.len() > 1
        || (change.additions.is_empty() && change.deletions.is_empty())
    {
        return Err(GcpError::Contract(
            "v0.1 DNS change must affect exactly one A record".into(),
        ));
    }
    let addition = change.additions.first();
    let deletion = change.deletions.first();
    for record in addition.into_iter().chain(deletion) {
        if record.record_type != "A"
            || !record.name.ends_with('.')
            || record.rrdatas.len() != 1
            || record.rrdatas[0].parse::<std::net::Ipv4Addr>().is_err()
            || record.ttl == 0
            || record.ttl > i32::MAX.cast_unsigned()
        {
            return Err(GcpError::Contract(
                "v0.1 DNS changes require one absolute IPv4 A record".into(),
            ));
        }
    }
    if let (Some(addition), Some(deletion)) = (addition, deletion)
        && (addition.name != deletion.name || addition.record_type != deletion.record_type)
    {
        return Err(GcpError::Contract(
            "DNS replacement must preserve record name and type".into(),
        ));
    }
    if deletion != change.expected_current.as_ref() {
        return Err(GcpError::Contract(
            "DNS deletion must exactly match the plan-bound current record".into(),
        ));
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the six public resource specs are normalized into one validation contract"
)]
fn expected_resource_properties(
    spec: ResourceSpecRef<'_>,
) -> (
    ResourceKind,
    &str,
    Option<&str>,
    Uuid,
    BTreeMap<String, Value>,
) {
    match spec {
        ResourceSpecRef::Network(spec) => (
            ResourceKind::Network,
            &spec.name,
            None,
            spec.deployment_uuid,
            BTreeMap::from([
                ("auto_create_subnetworks".into(), json!(false)),
                ("routing_mode".into(), json!("GLOBAL")),
            ]),
        ),
        ResourceSpecRef::Subnetwork(spec) => (
            ResourceKind::Subnetwork,
            &spec.name,
            Some(&spec.region),
            spec.deployment_uuid,
            BTreeMap::from([
                ("ip_cidr_range".into(), json!(spec.cidr)),
                (
                    "network".into(),
                    json!(normalized_resource_reference(&spec.network_self_link)),
                ),
            ]),
        ),
        ResourceSpecRef::Firewall(spec) => (
            ResourceKind::Firewall,
            &spec.name,
            None,
            spec.deployment_uuid,
            BTreeMap::from([
                (
                    "allowed".into(),
                    normalized_firewall_allowances(&spec.allowed),
                ),
                (
                    "network".into(),
                    json!(normalized_resource_reference(&spec.network_self_link)),
                ),
                (
                    "source_ranges".into(),
                    json!(sorted_strings(spec.source_ranges.clone())),
                ),
                (
                    "target_tags".into(),
                    json!(sorted_strings(vec![spec.target_tag.clone()])),
                ),
            ]),
        ),
        ResourceSpecRef::Address(spec) => (
            ResourceKind::Address,
            &spec.name,
            Some(&spec.region),
            spec.deployment_uuid,
            BTreeMap::new(),
        ),
        ResourceSpecRef::Disk(spec) => (
            ResourceKind::Disk,
            &spec.name,
            Some(&spec.zone),
            spec.deployment_uuid,
            BTreeMap::from([
                ("size_gb".into(), json!(spec.size_gib)),
                (
                    "source_image".into(),
                    json!(last_path_segment(&spec.source_image).unwrap_or(&spec.source_image)),
                ),
                ("source_image_id".into(), json!(spec.source_image_id)),
                ("type".into(), json!(spec.disk_type)),
            ]),
        ),
        ResourceSpecRef::Instance(spec) => (
            ResourceKind::Instance,
            &spec.name,
            Some(&spec.zone),
            spec.deployment_uuid,
            BTreeMap::from([
                ("access_config_count".into(), json!(1)),
                ("boot_disk_auto_delete".into(), json!(false)),
                (
                    "boot_disk".into(),
                    json!(normalized_resource_reference(&spec.boot_disk_self_link)),
                ),
                ("can_ip_forward".into(), json!(false)),
                ("deletion_protection".into(), json!(false)),
                ("disk_count".into(), json!(1)),
                ("machine_type".into(), json!(spec.machine_type)),
                ("metadata_key_count".into(), json!(1)),
                ("nat_ip".into(), json!(spec.address)),
                ("network_interface_count".into(), json!(1)),
                (
                    "network_tags".into(),
                    json!(sorted_strings(spec.network_tags.clone())),
                ),
                ("service_account_count".into(), json!(0)),
                (
                    "ssh_keys_sha256".into(),
                    json!(sha256_hex(&format!(
                        "{}:{}",
                        spec.ssh_username, spec.ssh_public_key
                    ))),
                ),
                (
                    "subnetwork".into(),
                    json!(normalized_resource_reference(&spec.subnetwork_self_link)),
                ),
            ]),
        ),
    }
}

fn normalized_resource_reference(value: &str) -> String {
    value
        .find("projects/")
        .map_or_else(|| value.to_owned(), |position| value[position..].to_owned())
}

fn normalized_firewall_allowances(allowed: &[FirewallAllowance]) -> Value {
    let mut allowed: Vec<_> = allowed
        .iter()
        .map(|allowance| {
            (
                allowance.protocol.clone(),
                sorted_strings(allowance.ports.clone()),
            )
        })
        .collect();
    allowed.sort();
    json!(
        allowed
            .into_iter()
            .map(|(protocol, ports)| json!({ "protocol": protocol, "ports": ports }))
            .collect::<Vec<_>>()
    )
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn sha256_hex(value: &str) -> String {
    use sha2::{Digest as _, Sha256};

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(value.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn dns_change_already_satisfied(
    change: &DnsChange,
    current: Option<&DnsRecordSet>,
) -> Result<bool> {
    validate_dns_change(change)?;
    if current == change.additions.first() {
        return Ok(true);
    }
    if current == change.expected_current.as_ref() {
        return Ok(false);
    }
    Err(GcpError::Contract(
        "Cloud DNS A record changed after planning; a new explicit plan is required".into(),
    ))
}

pub fn require_dns_change_applied(
    change: &DnsChange,
    current: Option<&DnsRecordSet>,
) -> Result<()> {
    if dns_change_already_satisfied(change, current)? {
        return Ok(());
    }
    Err(GcpError::Infrastructure(
        "Cloud DNS change completed but the exact planned value is not present".into(),
    ))
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use http::Method;
    use secrecy::SecretString;

    use super::*;
    use crate::{HttpTransport, RestResponse};

    #[derive(Default)]
    struct RecordingTransport {
        calls: Mutex<Vec<(Method, Url, Option<Value>)>>,
    }

    #[derive(Clone, Copy)]
    enum ResourceResponse {
        Absent,
        Present(&'static str),
        InfrastructureFailure,
    }

    struct DeleteTransport {
        response: Mutex<ResourceResponse>,
        deployment_uuid: Uuid,
        delete_calls: Mutex<usize>,
    }

    struct DnsReplacementTransport {
        zone_id: Mutex<u64>,
        replace_after_record_read: bool,
        record_calls: Mutex<usize>,
        change_calls: Mutex<usize>,
        poll_calls: Mutex<usize>,
    }

    impl DnsReplacementTransport {
        fn new(zone_id: u64, replace_after_record_read: bool) -> Self {
            Self {
                zone_id: Mutex::new(zone_id),
                replace_after_record_read,
                record_calls: Mutex::new(0),
                change_calls: Mutex::new(0),
                poll_calls: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl HttpTransport for DeleteTransport {
        async fn request(
            &self,
            method: Method,
            url: Url,
            _bearer_token: &SecretString,
            _body: Option<Value>,
        ) -> Result<RestResponse> {
            if url.host_str() == Some("cloudresourcemanager.googleapis.com") {
                return Ok(RestResponse {
                    status: 200,
                    body: serde_json::to_vec(
                        &json!({ "projectNumber": "123", "lifecycleState": "ACTIVE" }),
                    )
                    .expect("project JSON"),
                });
            }
            if method == Method::GET {
                return match *self.response.lock().expect("response lock") {
                    ResourceResponse::Absent => Ok(RestResponse {
                        status: 404,
                        body: Vec::new(),
                    }),
                    ResourceResponse::Present(numeric_id) => Ok(RestResponse {
                        status: 200,
                        body: serde_json::to_vec(&json!({
                            "id": numeric_id,
                            "name": "dirextalk-node",
                            "selfLink": "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/dirextalk-node",
                            "description": deployment_marker(self.deployment_uuid),
                            "zone": "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a"
                        }))
                        .expect("resource JSON"),
                    }),
                    ResourceResponse::InfrastructureFailure => Err(GcpError::Infrastructure(
                        "simulated transport failure".into(),
                    )),
                };
            }
            *self.delete_calls.lock().expect("delete calls lock") += 1;
            Ok(RestResponse {
                status: 200,
                body: serde_json::to_vec(&json!({
                    "id": "991",
                    "name": "operation-1",
                    "selfLink": "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/operations/operation-1",
                    "status": "PENDING"
                }))
                .expect("operation JSON"),
            })
        }
    }

    #[async_trait]
    impl HttpTransport for DnsReplacementTransport {
        async fn request(
            &self,
            method: Method,
            url: Url,
            _bearer_token: &SecretString,
            _body: Option<Value>,
        ) -> Result<RestResponse> {
            if url.host_str() == Some("cloudresourcemanager.googleapis.com") {
                return Ok(RestResponse {
                    status: 200,
                    body: serde_json::to_vec(
                        &json!({ "projectNumber": "123", "lifecycleState": "ACTIVE" }),
                    )
                    .expect("project JSON"),
                });
            }
            if url.path().ends_with("/managedZones/example") {
                let id = *self.zone_id.lock().expect("zone id lock");
                return Ok(RestResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({ "name": "example", "id": id.to_string() }))
                        .expect("zone JSON"),
                });
            }
            if method == Method::GET && url.path().ends_with("/rrsets") {
                *self.record_calls.lock().expect("record calls lock") += 1;
                if self.replace_after_record_read {
                    *self.zone_id.lock().expect("zone id lock") = 101;
                }
                return Ok(RestResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({
                        "rrsets": [{
                            "name": "node.example.com.",
                            "type": "A",
                            "ttl": 300,
                            "rrdatas": ["203.0.113.10"]
                        }]
                    }))
                    .expect("record JSON"),
                });
            }
            if method == Method::POST && url.path().ends_with("/changes") {
                *self.change_calls.lock().expect("change calls lock") += 1;
                return Ok(RestResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({ "id": "7", "status": "pending" }))
                        .expect("change JSON"),
                });
            }
            if method == Method::GET && url.path().contains("/changes/") {
                *self.poll_calls.lock().expect("poll calls lock") += 1;
                return Ok(RestResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({ "id": "7", "status": "done" }))
                        .expect("poll JSON"),
                });
            }
            Err(GcpError::Infrastructure(format!(
                "unexpected fake DNS request {method} {url}"
            )))
        }
    }

    fn instance_identity(deployment_uuid: Uuid) -> ResourceIdentity {
        ResourceIdentity {
            kind: ResourceKind::Instance,
            name: "dirextalk-node".into(),
            project_number: "123".into(),
            location: Some("us-central1-a".into()),
            numeric_id: "100".into(),
            self_link: "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/dirextalk-node".into(),
            deployment_uuid,
        }
    }

    fn delete_client(
        response: ResourceResponse,
    ) -> (GoogleRestClient, Arc<DeleteTransport>, ResourceIdentity) {
        let deployment_uuid = Uuid::new_v4();
        let transport = Arc::new(DeleteTransport {
            response: Mutex::new(response),
            deployment_uuid,
            delete_calls: Mutex::new(0),
        });
        let client = GoogleRestClient::with_transport(
            "test-project",
            "123",
            SecretString::from("access-token"),
            transport.clone(),
        );
        (client, transport, instance_identity(deployment_uuid))
    }

    fn dns_client(
        zone_id: u64,
        replace_after_record_read: bool,
    ) -> (GoogleRestClient, Arc<DnsReplacementTransport>) {
        let transport = Arc::new(DnsReplacementTransport::new(
            zone_id,
            replace_after_record_read,
        ));
        let client = GoogleRestClient::with_transport(
            "test-project",
            "123",
            SecretString::from("access-token"),
            transport.clone(),
        );
        (client, transport)
    }

    #[async_trait]
    impl HttpTransport for RecordingTransport {
        async fn request(
            &self,
            method: Method,
            url: Url,
            _bearer_token: &SecretString,
            body: Option<Value>,
        ) -> Result<RestResponse> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((method.clone(), url, body));
            let response = if method == Method::GET {
                json!({ "projectNumber": "123", "lifecycleState": "ACTIVE" })
            } else {
                json!({
                    "id": "991",
                    "name": "operation-1",
                    "selfLink": "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/operations/operation-1",
                    "status": "PENDING"
                })
            };
            Ok(RestResponse {
                status: 200,
                body: serde_json::to_vec(&response).expect("response JSON"),
            })
        }
    }

    fn operation_wire(status: &str, error: Option<OperationErrorWire>) -> OperationState {
        OperationState::from_wire(status, error).expect("known status")
    }

    fn dns_zone_identity(numeric_id: &str) -> DnsZoneIdentity {
        DnsZoneIdentity {
            project_id: "test-project".into(),
            name: "example".into(),
            numeric_id: numeric_id.into(),
        }
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

    #[test]
    fn official_compute_self_links_accept_only_the_canonical_api_path() {
        require_self_link(
            "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/dirextalk-network",
            "test-project",
            "/global/networks/",
        )
        .expect("official SDK self-link");
        assert!(
            require_self_link(
                "https://www.googleapis.com/storage/v1/projects/test-project/global/networks/dirextalk-network",
                "test-project",
                "/global/networks/",
            )
            .is_err()
        );
    }

    #[test]
    fn operation_self_link_requires_exact_scope_and_name_path() {
        let valid = Operation {
            name: "operation-1".into(),
            numeric_id: "17".into(),
            self_link: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/operations/operation-1".into(),
            project_number: "123".into(),
            scope: OperationScope::Zone("us-central1-a".into()),
        };
        validate_operation_self_link(&valid, "test-project").expect("exact operation path");

        let cross_scope = Operation {
            scope: OperationScope::Region("us-central1-a".into()),
            ..valid.clone()
        };
        assert!(validate_operation_self_link(&cross_scope, "test-project").is_err());
        let confused = Operation {
            self_link: format!("{}/extra", valid.self_link),
            ..valid
        };
        assert!(validate_operation_self_link(&confused, "test-project").is_err());
    }

    #[test]
    fn compute_operation_keeps_opaque_name_and_numeric_id_as_distinct_identity() {
        let self_link = "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/operations/operation-opaque";
        let sdk = google_cloud_compute_v1::model::Operation::new()
            .set_id(991_u64)
            .set_name("operation-opaque")
            .set_self_link(self_link);
        let operation = operation_from_sdk(
            sdk.clone(),
            "123",
            OperationScope::Zone("us-central1-a".into()),
        )
        .expect("SDK operation");
        assert_eq!(operation.name, "operation-opaque");
        assert_eq!(operation.numeric_id, "991");
        validate_sdk_operation_identity(&sdk, &operation).expect("exact SDK identity");

        let replacement = sdk.set_id(992_u64);
        assert!(validate_sdk_operation_identity(&replacement, &operation).is_err());

        let wire = OperationWire {
            id: "991".into(),
            name: "operation-opaque".into(),
            self_link: Some(self_link.into()),
            status: "RUNNING".into(),
            error: None,
        };
        validate_wire_operation_identity(&wire, &operation).expect("exact REST identity");
        let replacement = OperationWire {
            id: "992".into(),
            ..wire
        };
        assert!(validate_wire_operation_identity(&replacement, &operation).is_err());
    }

    #[test]
    fn resource_self_link_rejects_cross_zone_and_collection_confusion() {
        let exact = "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/dirextalk-node";
        validate_resource_self_link(
            exact,
            "test-project",
            ResourceKind::Instance,
            "dirextalk-node",
            Some("us-central1-a"),
        )
        .expect("exact resource path");
        assert!(
            validate_resource_self_link(
                exact,
                "test-project",
                ResourceKind::Instance,
                "dirextalk-node",
                Some("us-central1-b"),
            )
            .is_err()
        );
        assert!(
            validate_resource_self_link(
                "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/disks/instances/dirextalk-node",
                "test-project",
                ResourceKind::Instance,
                "dirextalk-node",
                Some("us-central1-a"),
            )
            .is_err()
        );
    }

    #[test]
    fn dns_change_requires_exact_owned_value() {
        let owned = DnsRecordSet {
            name: "node.example.com.".into(),
            record_type: "A".into(),
            ttl: 300,
            rrdatas: vec!["203.0.113.10".into()],
        };
        let change = DnsChange {
            managed_zone: dns_zone_identity("100"),
            expected_current: Some(owned.clone()),
            additions: vec![],
            deletions: vec![owned.clone()],
        };
        validate_dns_change(&change).expect("exact deletion");
        let stale = DnsChange {
            expected_current: Some(DnsRecordSet {
                rrdatas: vec!["203.0.113.11".into()],
                ..owned
            }),
            ..change.clone()
        };
        assert!(validate_dns_change(&stale).is_err());
        assert!(
            !dns_change_already_satisfied(&change, change.expected_current.as_ref())
                .expect("owned old value may be changed")
        );
        assert!(dns_change_already_satisfied(&change, None).expect("absence is desired"));
    }

    #[tokio::test]
    async fn dns_record_read_rejects_same_name_zone_replacement() {
        let (client, transport) = dns_client(101, false);

        let error = GcpLifecycle::get_dns_record_set(
            &client,
            "123",
            &dns_zone_identity("100"),
            "node.example.com.",
            "A",
        )
        .await
        .expect_err("replacement must fail before the record read");

        assert!(matches!(error, GcpError::Contract(_)));
        assert_eq!(*transport.record_calls.lock().expect("record calls"), 0);
    }

    #[tokio::test]
    async fn dns_change_revalidates_zone_again_immediately_before_create() {
        let (client, transport) = dns_client(100, true);
        let old = DnsRecordSet {
            name: "node.example.com.".into(),
            record_type: "A".into(),
            ttl: 300,
            rrdatas: vec!["203.0.113.10".into()],
        };
        let change = DnsChange {
            managed_zone: dns_zone_identity("100"),
            expected_current: Some(old.clone()),
            additions: vec![DnsRecordSet {
                rrdatas: vec!["203.0.113.11".into()],
                ..old.clone()
            }],
            deletions: vec![old],
        };

        let error = client
            .start_dns_change("123", Uuid::new_v4(), &change)
            .await
            .expect_err("replacement must fail before change creation");

        assert!(matches!(error, GcpError::Contract(_)));
        assert_eq!(*transport.record_calls.lock().expect("record calls"), 1);
        assert_eq!(*transport.change_calls.lock().expect("change calls"), 0);
    }

    #[tokio::test]
    async fn dns_poll_rejects_same_name_zone_replacement() {
        let (client, transport) = dns_client(101, false);
        let operation = Operation {
            name: "7".into(),
            numeric_id: "7".into(),
            self_link: "https://dns.googleapis.com/dns/v1/projects/test-project/managedZones/example/changes/7".into(),
            project_number: "123".into(),
            scope: OperationScope::DnsZone(dns_zone_identity("100")),
        };

        let error = client
            .poll_operation("123", &operation)
            .await
            .expect_err("replacement must fail before operation polling");

        assert!(matches!(error, GcpError::Contract(_)));
        assert_eq!(*transport.poll_calls.lock().expect("poll calls"), 0);
    }

    #[tokio::test]
    async fn instance_insert_has_request_id_and_no_service_account() {
        let transport = Arc::new(RecordingTransport::default());
        let client = GoogleRestClient::with_transport(
            "test-project",
            "123",
            SecretString::from("access-token"),
            transport.clone(),
        );
        let request_id = Uuid::new_v4();
        let spec = InstanceSpec {
            name: "dirextalk-node".into(),
            zone: "us-central1-a".into(),
            machine_type: "e2-custom-2-4096".into(),
            subnetwork_self_link: "https://compute.googleapis.com/compute/v1/projects/test-project/regions/us-central1/subnetworks/dirextalk-subnet".into(),
            address: "203.0.113.10".into(),
            boot_disk_self_link: "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/disks/dirextalk-disk".into(),
            network_tags: vec!["dirextalk-node".into()],
            ssh_username: "dirextalk".into(),
            ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".into(),
            deployment_uuid: Uuid::new_v4(),
        };
        client
            .start_instance("123", request_id, &spec)
            .await
            .expect("insert");
        let calls = transport.calls.lock().expect("calls lock");
        let (_, url, body) = calls.last().expect("insert call");
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "requestId")
                .map(|(_, value)| value.into_owned()),
            Some(request_id.to_string())
        );
        let body = body.as_ref().expect("insert body");
        assert!(body.get("serviceAccounts").is_none());
        assert_eq!(body["metadata"]["items"][0]["key"], "ssh-keys");
    }

    #[tokio::test]
    async fn delete_recovery_treats_absent_target_as_already_satisfied() {
        let (client, transport, identity) = delete_client(ResourceResponse::Absent);

        let operation = client
            .start_delete("123", Uuid::new_v4(), &identity)
            .await
            .expect("absence is expected");

        assert!(operation.is_none());
        assert_eq!(*transport.delete_calls.lock().expect("delete calls"), 0);
        let observed = client
            .get_resource(
                "123",
                identity.kind,
                &identity.name,
                identity.location.as_deref(),
            )
            .await
            .expect("optional read");
        require_resource_absent(&identity, observed.as_ref()).expect("delete postcondition");
    }

    #[tokio::test]
    async fn delete_recovery_rejects_same_name_replacement() {
        let (client, transport, identity) = delete_client(ResourceResponse::Present("101"));

        let error = client
            .start_delete("123", Uuid::new_v4(), &identity)
            .await
            .expect_err("replacement must not be deleted");

        assert!(matches!(error, GcpError::Contract(_)));
        assert_eq!(*transport.delete_calls.lock().expect("delete calls"), 0);
    }

    #[tokio::test]
    async fn optional_resource_read_preserves_infrastructure_failure() {
        let (client, _transport, identity) = delete_client(ResourceResponse::InfrastructureFailure);

        let error = client
            .get_resource(
                "123",
                identity.kind,
                &identity.name,
                identity.location.as_deref(),
            )
            .await
            .expect_err("transport failure is not absence");

        assert!(matches!(error, GcpError::Infrastructure(_)));
    }

    #[tokio::test]
    async fn delete_starts_only_for_the_exact_owned_resource() {
        let (client, transport, identity) = delete_client(ResourceResponse::Present("100"));

        let operation = client
            .start_delete("123", Uuid::new_v4(), &identity)
            .await
            .expect("delete start")
            .expect("operation started");

        assert_eq!(operation.project_number, "123");
        assert_eq!(*transport.delete_calls.lock().expect("delete calls"), 1);
        *transport.response.lock().expect("response lock") = ResourceResponse::Absent;
        let observed = client
            .get_resource(
                "123",
                identity.kind,
                &identity.name,
                identity.location.as_deref(),
            )
            .await
            .expect("post-delete read");
        require_resource_absent(&identity, observed.as_ref()).expect("target is absent");
    }

    #[test]
    fn deletion_postcondition_rejects_exact_survivor_and_replacement() {
        let identity = instance_identity(Uuid::new_v4());
        let exact = ResourceReceipt {
            identity: identity.clone(),
            observed_attributes: BTreeMap::new(),
        };
        let replacement = ResourceReceipt {
            identity: ResourceIdentity {
                numeric_id: "101".into(),
                ..identity.clone()
            },
            observed_attributes: BTreeMap::new(),
        };

        assert!(matches!(
            require_resource_absent(&identity, Some(&exact)),
            Err(GcpError::Infrastructure(_))
        ));
        assert!(matches!(
            require_resource_absent(&identity, Some(&replacement)),
            Err(GcpError::Contract(_))
        ));
    }

    #[test]
    fn dns_recovery_accepts_only_exact_old_or_new_value() {
        let old = DnsRecordSet {
            name: "node.example.com.".into(),
            record_type: "A".into(),
            ttl: 300,
            rrdatas: vec!["203.0.113.10".into()],
        };
        let new = DnsRecordSet {
            rrdatas: vec!["203.0.113.11".into()],
            ..old.clone()
        };
        let replacement = DnsRecordSet {
            rrdatas: vec!["203.0.113.12".into()],
            ..old.clone()
        };
        let change = DnsChange {
            managed_zone: dns_zone_identity("100"),
            expected_current: Some(old.clone()),
            additions: vec![new.clone()],
            deletions: vec![old.clone()],
        };

        assert!(!dns_change_already_satisfied(&change, Some(&old)).expect("old value"));
        assert!(dns_change_already_satisfied(&change, Some(&new)).expect("new value"));
        assert!(matches!(
            dns_change_already_satisfied(&change, Some(&replacement)),
            Err(GcpError::Contract(_))
        ));
        assert!(matches!(
            require_dns_change_applied(&change, Some(&old)),
            Err(GcpError::Infrastructure(_))
        ));
    }

    #[test]
    fn observed_property_drift_fails_with_unchanged_numeric_identity() {
        let spec = NetworkSpec {
            name: "dirextalk-network".into(),
            deployment_uuid: Uuid::new_v4(),
        };
        let (_, _, _, _, attributes) =
            expected_resource_properties(ResourceSpecRef::Network(&spec));
        let mut receipt = ResourceReceipt {
            identity: ResourceIdentity {
                kind: ResourceKind::Network,
                name: spec.name.clone(),
                project_number: "123".into(),
                location: None,
                numeric_id: "100".into(),
                self_link: "https://compute.googleapis.com/compute/v1/projects/test-project/global/networks/dirextalk-network".into(),
                deployment_uuid: spec.deployment_uuid,
            },
            observed_attributes: attributes,
        };
        validate_resource_properties(ResourceSpecRef::Network(&spec), &receipt)
            .expect("matching properties");

        receipt
            .observed_attributes
            .insert("routing_mode".into(), json!("REGIONAL"));
        let error = validate_resource_properties(ResourceSpecRef::Network(&spec), &receipt)
            .expect_err("property drift must fail");
        assert!(matches!(error, GcpError::Contract(_)));
        assert_eq!(receipt.identity.numeric_id, "100");
    }

    #[test]
    fn instance_observations_hash_ssh_metadata() {
        let spec = InstanceSpec {
            name: "dirextalk-node".into(),
            zone: "us-central1-a".into(),
            machine_type: "e2-custom-2-4096".into(),
            subnetwork_self_link:
                "projects/test-project/regions/us-central1/subnetworks/dirextalk-subnet".into(),
            address: "203.0.113.10".into(),
            boot_disk_self_link: "projects/test-project/zones/us-central1-a/disks/dirextalk-disk"
                .into(),
            network_tags: vec!["dirextalk-node".into()],
            ssh_username: "dirextalk".into(),
            ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".into(),
            deployment_uuid: Uuid::new_v4(),
        };
        let (_, _, _, _, attributes) =
            expected_resource_properties(ResourceSpecRef::Instance(&spec));
        let serialized = serde_json::to_string(&attributes).expect("attributes JSON");

        assert!(!serialized.contains(&spec.ssh_public_key));
        assert!(attributes.contains_key("ssh_keys_sha256"));
    }
}
