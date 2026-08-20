use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CoreError, ExactReleaseIdentity, PlanDigest, ReleaseTag, Result, SCHEMA_VERSION, Sha256Digest,
    validate_service_id,
};

/// Immutable authenticated GCP project and OAuth-principal binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub project_id: String,
    pub project_number: u64,
    pub oauth_principal: String,
}

/// The lifecycle phase durably reached by a deployment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    Planned,
    Applying,
    WaitingUser,
    Installed,
    Complete,
    Destroying,
    Destroyed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectAction {
    Create,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Network,
    Subnet,
    Firewall,
    Address,
    Instance,
    Disk,
    DnsRecord,
}

/// Original GCP operation identity recorded before polling or retrying.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRef {
    /// The original idempotency request id, equal to `PendingEffect.effect_id`.
    pub request_id: Uuid,
    pub project_number: u64,
    pub location: String,
    pub numeric_id: u64,
    pub self_link: String,
}

/// A cloud effect journaled before the first mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEffect {
    /// Persisted before mutation and reused as the provider request id.
    pub effect_id: Uuid,
    pub deployment_uuid: Uuid,
    pub project_number: u64,
    pub action: EffectAction,
    pub resource_kind: ResourceKind,
    pub resource_name: String,
    pub location: String,
    pub expected_attributes: BTreeMap<String, String>,
    /// Exact pre-mutation target. Required for update/delete and forbidden for
    /// create, so a retry can never cross into a same-name replacement.
    pub target: Option<ResourceRef>,
    pub operation: Option<OperationRef>,
}

/// Immutable identity and observed receipt for a single GCP resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub resource_kind: ResourceKind,
    pub name: String,
    pub project_number: u64,
    pub location: String,
    pub numeric_id: u64,
    pub self_link: String,
    pub deployment_uuid: Uuid,
    pub observed_attributes: BTreeMap<String, String>,
}

/// All resources owned by a single v0.1 deployment.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GcpResources {
    pub network: Option<ResourceRef>,
    pub subnet: Option<ResourceRef>,
    pub web_firewall: Option<ResourceRef>,
    pub turn_firewall: Option<ResourceRef>,
    pub ssh_firewall: Option<ResourceRef>,
    pub address: Option<ResourceRef>,
    pub instance: Option<ResourceRef>,
    pub boot_disk: Option<ResourceRef>,
    pub dns_record: Option<ResourceRef>,
}

impl GcpResources {
    fn iter(&self) -> impl Iterator<Item = (ResourceKind, &ResourceRef)> {
        [
            (ResourceKind::Network, self.network.as_ref()),
            (ResourceKind::Subnet, self.subnet.as_ref()),
            (ResourceKind::Firewall, self.web_firewall.as_ref()),
            (ResourceKind::Firewall, self.turn_firewall.as_ref()),
            (ResourceKind::Firewall, self.ssh_firewall.as_ref()),
            (ResourceKind::Address, self.address.as_ref()),
            (ResourceKind::Instance, self.instance.as_ref()),
            (ResourceKind::Disk, self.boot_disk.as_ref()),
            (ResourceKind::DnsRecord, self.dns_record.as_ref()),
        ]
        .into_iter()
        .filter_map(|(kind, resource)| resource.map(|resource| (kind, resource)))
    }
}

/// Pinned SSH server identity; the fingerprint is public verification data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshHostIdentity {
    pub address: String,
    pub algorithm: String,
    pub fingerprint_sha256: String,
}

/// Signed, digest-bound result emitted by the fixed one-shot host installer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostReceipt {
    pub deployment_uuid: Uuid,
    pub release_tag: ReleaseTag,
    pub host_installer_sha256: Sha256Digest,
    pub runtime_bundle_sha256: Sha256Digest,
    pub installed_at_unix_ms: u64,
    pub receipt_signature: String,
}

/// Redacted local agent wiring state. No Matrix or agent token is stored here.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWiringStatus {
    pub requested: bool,
    pub installed: bool,
    pub service_active: bool,
    pub last_checked_unix_ms: Option<u64>,
}

/// Complete schema-v1 state payload. The integrity digest covers every other
/// field using canonical JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentState {
    pub schema_version: u32,
    pub deployment_uuid: Uuid,
    pub service_id: String,
    pub project_identity: ProjectIdentity,
    pub phase: DeploymentPhase,
    /// Exact approved deployment plan used by apply/resume. Destroy uses a
    /// separate digest derived from the identity-bound resource receipts.
    pub approved_plan_digest: Option<PlanDigest>,
    pub pending_effect: Option<PendingEffect>,
    pub release_identity: Option<ExactReleaseIdentity>,
    pub gcp_resources: GcpResources,
    pub ssh_host_identity: Option<SshHostIdentity>,
    pub host_receipt: Option<HostReceipt>,
    pub local_wiring: LocalWiringStatus,
    #[serde(default)]
    pub integrity_digest: String,
}

impl DeploymentState {
    /// Checks identity bindings that must hold before state can be persisted.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::UnsupportedStateSchema`] for a non-v1 payload, or
    /// [`CoreError::InvalidState`] when an identity or lifecycle invariant is
    /// broken.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoreError::UnsupportedStateSchema);
        }
        validate_service_id(&self.service_id)?;
        if self.deployment_uuid.is_nil() {
            return Err(CoreError::InvalidState("deployment UUID must be non-zero"));
        }
        if self.project_identity.project_number == 0 {
            return Err(CoreError::InvalidState("project number must be non-zero"));
        }
        if self.project_identity.project_id.is_empty()
            || self.project_identity.oauth_principal.is_empty()
        {
            return Err(CoreError::InvalidState("project identity is incomplete"));
        }
        if matches!(
            self.phase,
            DeploymentPhase::Applying
                | DeploymentPhase::Installed
                | DeploymentPhase::Complete
                | DeploymentPhase::WaitingUser
        ) && self.approved_plan_digest.is_none()
        {
            return Err(CoreError::InvalidState(
                "active deployment requires an approved plan digest",
            ));
        }
        if matches!(
            self.phase,
            DeploymentPhase::Applying
                | DeploymentPhase::WaitingUser
                | DeploymentPhase::Installed
                | DeploymentPhase::Complete
                | DeploymentPhase::Destroying
        ) && self.release_identity.is_none()
        {
            return Err(CoreError::InvalidState(
                "active deployment requires exact release identity",
            ));
        }
        for (expected_kind, resource) in self.gcp_resources.iter() {
            validate_resource(
                resource,
                self.project_identity.project_number,
                self.deployment_uuid,
            )?;
            if resource.resource_kind != expected_kind {
                return Err(CoreError::InvalidState(
                    "resource kind does not match its state slot",
                ));
            }
        }
        if let Some(effect) = &self.pending_effect {
            validate_effect(
                effect,
                self.phase,
                self.project_identity.project_number,
                self.deployment_uuid,
            )?;
        }
        if let Some(identity) = &self.ssh_host_identity
            && (identity.address.is_empty()
                || identity.algorithm.is_empty()
                || !identity.fingerprint_sha256.starts_with("SHA256:")
                || identity.fingerprint_sha256.len() <= "SHA256:".len())
        {
            return Err(CoreError::InvalidState("SSH host identity is incomplete"));
        }
        validate_host(self)?;
        if self.local_wiring.installed && !self.local_wiring.requested {
            return Err(CoreError::InvalidState("local wiring was not requested"));
        }
        if self.local_wiring.service_active && !self.local_wiring.installed {
            return Err(CoreError::InvalidState("local wiring is not installed"));
        }
        Ok(())
    }
}

pub(crate) fn validate_resource(
    resource: &ResourceRef,
    project_number: u64,
    deployment_uuid: Uuid,
) -> Result<()> {
    if resource.name.is_empty() {
        return Err(CoreError::InvalidState("resource name is incomplete"));
    }
    if resource.project_number != project_number {
        return Err(CoreError::InvalidState(
            "resource project identity mismatch",
        ));
    }
    if resource.deployment_uuid != deployment_uuid {
        return Err(CoreError::InvalidState(
            "resource deployment identity mismatch",
        ));
    }
    if resource.numeric_id == 0
        || !safe_public_name(&resource.name)
        || !safe_location(&resource.location)
        || !trusted_google_self_link(&resource.self_link)
    {
        return Err(CoreError::InvalidState("resource identity is incomplete"));
    }
    validate_attributes(&resource.observed_attributes)
}

fn validate_effect(
    effect: &PendingEffect,
    phase: DeploymentPhase,
    project_number: u64,
    deployment_uuid: Uuid,
) -> Result<()> {
    if matches!(
        phase,
        DeploymentPhase::Planned | DeploymentPhase::Complete | DeploymentPhase::Destroyed
    ) {
        return Err(CoreError::InvalidState(
            "deployment phase cannot carry a pending effect",
        ));
    }
    if effect.effect_id.is_nil() {
        return Err(CoreError::InvalidState(
            "pending effect UUID must be non-zero",
        ));
    }
    if effect.project_number != project_number || effect.deployment_uuid != deployment_uuid {
        return Err(CoreError::InvalidState("pending effect identity mismatch"));
    }
    match (effect.action, &effect.target) {
        (EffectAction::Create, None) => {}
        (EffectAction::Update | EffectAction::Delete, Some(target)) => {
            validate_resource(target, project_number, deployment_uuid)?;
            if target.resource_kind != effect.resource_kind
                || target.name != effect.resource_name
                || target.location != effect.location
            {
                return Err(CoreError::InvalidState(
                    "pending effect target identity mismatch",
                ));
            }
        }
        _ => {
            return Err(CoreError::InvalidState(
                "pending effect target identity is missing or unexpected",
            ));
        }
    }
    if effect.resource_name.is_empty() || effect.location.is_empty() {
        return Err(CoreError::InvalidState(
            "pending effect identity is incomplete",
        ));
    }
    validate_attributes(&effect.expected_attributes)?;
    if let Some(operation) = &effect.operation
        && (operation.request_id != effect.effect_id
            || operation.project_number != effect.project_number
            || operation.numeric_id == 0
            || !trusted_google_self_link(&operation.self_link)
            || !safe_location(&operation.location))
    {
        return Err(CoreError::InvalidState("operation identity mismatch"));
    }
    Ok(())
}

fn validate_host(state: &DeploymentState) -> Result<()> {
    if state.host_receipt.is_some() && state.ssh_host_identity.is_none() {
        return Err(CoreError::InvalidState(
            "host receipt requires pinned SSH identity",
        ));
    }
    let Some(receipt) = &state.host_receipt else {
        return Ok(());
    };
    let Some(release) = &state.release_identity else {
        return Err(CoreError::InvalidState(
            "host receipt requires exact release identity",
        ));
    };
    if receipt.deployment_uuid != state.deployment_uuid
        || receipt.release_tag != release.release_tag
        || receipt.host_installer_sha256 != release.host_installer_linux_amd64_sha256
        || receipt.runtime_bundle_sha256 != release.runtime_bundle_linux_amd64_sha256
    {
        return Err(CoreError::InvalidState("host receipt identity mismatch"));
    }
    if !valid_sha256(&receipt.receipt_signature) {
        return Err(CoreError::InvalidState("host receipt is incomplete"));
    }
    Ok(())
}

pub(crate) fn validate_attributes(attributes: &BTreeMap<String, String>) -> Result<()> {
    for (key, value) in attributes {
        let normalized = key.to_ascii_lowercase();
        if key.is_empty()
            || key.len() > 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || [
                "token",
                "secret",
                "password",
                "credential",
                "authorization",
                "cookie",
                "bearer",
                "private_key",
                "initialization_code",
                "conversation",
            ]
            .iter()
            .any(|forbidden| normalized.contains(forbidden))
        {
            return Err(CoreError::InvalidState(
                "resource attributes contain an unsafe key",
            ));
        }
        if !safe_attribute_value(key, value) {
            return Err(CoreError::InvalidState(
                "resource attributes contain an unsafe value",
            ));
        }
    }
    Ok(())
}

fn safe_attribute_value(key: &str, value: &str) -> bool {
    if value.is_empty() || value.len() > 2_048 {
        return false;
    }
    match key {
        "name" | "type" | "machine_type" | "status" | "zone_name" => safe_public_name(value),
        "service_account" => value == "none",
        "cidr" => valid_ipv4_cidr(value, false),
        "source" => valid_ipv4_cidr(value, true),
        "ports" => value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":,-".contains(&byte)
        }),
        "size_gib" | "zone_numeric_id" | "ttl" => {
            value.parse::<u64>().is_ok_and(|number| number > 0)
        }
        "address" | "value" => value.parse::<std::net::Ipv4Addr>().is_ok(),
        "current_values" => serde_json::from_str::<Vec<std::net::Ipv4Addr>>(value).is_ok(),
        "tags" => serde_json::from_str::<Vec<String>>(value)
            .is_ok_and(|tags| !tags.is_empty() && tags.iter().all(|tag| safe_public_name(tag))),
        "network_self_link" | "subnet_self_link" => trusted_google_self_link(value),
        _ => false,
    }
}

fn safe_public_name(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn safe_location(value: &str) -> bool {
    value == "global" || safe_public_name(value)
}

fn trusted_google_self_link(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url
            .host_str()
            .is_some_and(|host| host == "googleapis.com" || host.ends_with(".googleapis.com"))
}

fn valid_ipv4_cidr(value: &str, require_host: bool) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(prefix)) = (address.parse::<std::net::Ipv4Addr>(), prefix.parse::<u32>())
    else {
        return false;
    };
    if prefix > 32 || (require_host && prefix != 32) {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask == u32::from(address)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressStatus {
    Started,
    Succeeded,
    WaitingUser,
    Failed,
}

/// Fixed operation labels prevent credentials or conversation content from
/// entering JSON/JSONL through free-form progress fields.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressOperation {
    Plan,
    Apply,
    Resume,
    Destroy,
    Verify,
    CloudEffect,
    HostInstall,
    ConnectInstall,
}

/// Secret-free structured progress suitable for human, JSON, or JSONL output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressEvent {
    pub timestamp_unix_ms: u64,
    pub operation: ProgressOperation,
    pub status: ProgressStatus,
    pub resource_kind: Option<ResourceKind>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::test_release_identity;

    fn state() -> DeploymentState {
        DeploymentState {
            schema_version: 1,
            deployment_uuid: Uuid::new_v4(),
            service_id: "production-0123456789ab".to_owned(),
            project_identity: ProjectIdentity {
                project_id: "dirextalk-prod".to_owned(),
                project_number: 42,
                oauth_principal: "operator@example.com".to_owned(),
            },
            phase: DeploymentPhase::Applying,
            approved_plan_digest: Some(
                "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
                    .parse()
                    .unwrap(),
            ),
            pending_effect: None,
            release_identity: Some(test_release_identity()),
            gcp_resources: GcpResources::default(),
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus::default(),
            integrity_digest: String::new(),
        }
    }

    #[test]
    fn resource_identity_must_match_state() {
        let mut state = state();
        state.gcp_resources.network = Some(ResourceRef {
            project_number: 99,
            location: "global".to_owned(),
            numeric_id: 1,
            self_link: "https://compute.googleapis.com/network/1".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::new(),
            resource_kind: ResourceKind::Network,
            name: "network".to_owned(),
        });
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState(
                "resource project identity mismatch"
            ))
        ));
    }

    #[test]
    fn pending_operation_must_match_effect_project() {
        let mut state = state();
        let effect_id = Uuid::new_v4();
        state.pending_effect = Some(PendingEffect {
            effect_id,
            deployment_uuid: state.deployment_uuid,
            project_number: 42,
            action: EffectAction::Create,
            resource_kind: ResourceKind::Network,
            resource_name: "network".to_owned(),
            location: "global".to_owned(),
            expected_attributes: BTreeMap::new(),
            target: None,
            operation: Some(OperationRef {
                request_id: effect_id,
                project_number: 43,
                location: "global".to_owned(),
                numeric_id: 7,
                self_link: "https://compute.googleapis.com/operation/7".to_owned(),
            }),
        });
        assert!(state.validate().is_err());
    }

    #[test]
    fn delete_requires_full_target_and_operation_request_binding() {
        let mut state = state();
        state.phase = DeploymentPhase::Destroying;
        let target = ResourceRef {
            resource_kind: ResourceKind::Network,
            name: "network".to_owned(),
            project_number: 42,
            location: "global".to_owned(),
            numeric_id: 8,
            self_link: "https://compute.googleapis.com/network/8".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::from([("name".to_owned(), "network".to_owned())]),
        };
        let effect_id = Uuid::new_v4();
        let mut effect = PendingEffect {
            effect_id,
            deployment_uuid: state.deployment_uuid,
            project_number: 42,
            action: EffectAction::Delete,
            resource_kind: ResourceKind::Network,
            resource_name: "network".to_owned(),
            location: "global".to_owned(),
            expected_attributes: BTreeMap::new(),
            target: None,
            operation: None,
        };
        state.pending_effect = Some(effect.clone());
        assert!(state.validate().is_err());

        effect.target = Some(target);
        effect.operation = Some(OperationRef {
            request_id: Uuid::new_v4(),
            project_number: 42,
            location: "global".to_owned(),
            numeric_id: 9,
            self_link: "https://compute.googleapis.com/operation/9".to_owned(),
        });
        state.pending_effect = Some(effect.clone());
        assert!(state.validate().is_err());
        effect.operation.as_mut().unwrap().request_id = effect_id;
        state.pending_effect = Some(effect);
        assert!(state.validate().is_ok());
    }

    #[test]
    fn host_receipt_requires_exact_release_artifacts_and_pinned_host() {
        let mut state = state();
        let release = state.release_identity.as_ref().unwrap();
        let receipt = HostReceipt {
            deployment_uuid: state.deployment_uuid,
            release_tag: release.release_tag.clone(),
            host_installer_sha256: release.host_installer_linux_amd64_sha256.clone(),
            runtime_bundle_sha256: release.runtime_bundle_linux_amd64_sha256.clone(),
            installed_at_unix_ms: 1,
            receipt_signature: "d".repeat(64),
        };
        state.host_receipt = Some(receipt.clone());
        assert!(state.validate().is_err());

        state.ssh_host_identity = Some(SshHostIdentity {
            address: "203.0.113.42".to_owned(),
            algorithm: "ssh-ed25519".to_owned(),
            fingerprint_sha256: "SHA256:host-key".to_owned(),
        });
        assert!(state.validate().is_ok());

        let mut wrong_installer = receipt.clone();
        wrong_installer.host_installer_sha256 = Sha256Digest::parse("e".repeat(64)).unwrap();
        state.host_receipt = Some(wrong_installer);
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState("host receipt identity mismatch"))
        ));

        let mut wrong_bundle = receipt;
        wrong_bundle.runtime_bundle_sha256 = Sha256Digest::parse("f".repeat(64)).unwrap();
        state.host_receipt = Some(wrong_bundle);
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState("host receipt identity mismatch"))
        ));
    }

    #[test]
    fn state_rejects_secret_bearing_attribute_keys() {
        let mut state = state();
        state.gcp_resources.network = Some(ResourceRef {
            project_number: 42,
            location: "global".to_owned(),
            numeric_id: 1,
            self_link: "https://compute.googleapis.com/network/1".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::from([(
                "oauth_refresh_token".to_owned(),
                "never-persist-this".to_owned(),
            )]),
            resource_kind: ResourceKind::Network,
            name: "network".to_owned(),
        });
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState(
                "resource attributes contain an unsafe key"
            ))
        ));
    }

    #[test]
    fn state_rejects_untyped_or_secret_capable_attribute_values() {
        let mut state = state();
        state.gcp_resources.address = Some(ResourceRef {
            project_number: 42,
            location: "us-central1".to_owned(),
            numeric_id: 1,
            self_link: "https://compute.googleapis.com/address/1".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::from([(
                "address".to_owned(),
                "not-an-ip-or-token".to_owned(),
            )]),
            resource_kind: ResourceKind::Address,
            name: "static-ip".to_owned(),
        });
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState(
                "resource attributes contain an unsafe value"
            ))
        ));
    }
}
