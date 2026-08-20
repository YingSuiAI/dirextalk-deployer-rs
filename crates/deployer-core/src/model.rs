use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, PlanDigest, Result, SCHEMA_VERSION, validate_service_id};

/// Immutable authenticated GCP project and OAuth-principal binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub project_id: String,
    pub project_number: u64,
    pub oauth_principal: String,
}

/// The lifecycle phase durably reached by a deployment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectAction {
    Create,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    pub project_number: u64,
    pub location: String,
    pub numeric_id: u64,
    pub self_link: String,
}

/// A cloud effect journaled before the first mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEffect {
    pub effect_id: Uuid,
    pub deployment_uuid: Uuid,
    pub project_number: u64,
    pub action: EffectAction,
    pub resource_kind: ResourceKind,
    pub resource_name: String,
    pub location: String,
    pub expected_attributes: BTreeMap<String, String>,
    pub operation: Option<OperationRef>,
}

/// Immutable identity and observed receipt for a single GCP resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
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
    fn iter(&self) -> impl Iterator<Item = &ResourceRef> {
        [
            self.network.as_ref(),
            self.subnet.as_ref(),
            self.web_firewall.as_ref(),
            self.turn_firewall.as_ref(),
            self.ssh_firewall.as_ref(),
            self.address.as_ref(),
            self.instance.as_ref(),
            self.boot_disk.as_ref(),
            self.dns_record.as_ref(),
        ]
        .into_iter()
        .flatten()
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
    pub exact_release: String,
    pub installer_sha256: String,
    pub bundle_sha256: String,
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
    pub exact_release: Option<String>,
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
        for resource in self.gcp_resources.iter() {
            validate_resource(
                resource,
                self.project_identity.project_number,
                self.deployment_uuid,
            )?;
        }
        if let Some(effect) = &self.pending_effect {
            validate_effect(
                effect,
                self.phase,
                self.project_identity.project_number,
                self.deployment_uuid,
            )?;
        }
        if let Some(exact_release) = &self.exact_release
            && !valid_identifier(exact_release)
        {
            return Err(CoreError::InvalidState("exact release is invalid"));
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

fn validate_resource(
    resource: &ResourceRef,
    project_number: u64,
    deployment_uuid: Uuid,
) -> Result<()> {
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
    if resource.numeric_id == 0 || resource.self_link.is_empty() || resource.location.is_empty() {
        return Err(CoreError::InvalidState("resource identity is incomplete"));
    }
    validate_attribute_keys(&resource.observed_attributes)
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
    if effect.resource_name.is_empty() || effect.location.is_empty() {
        return Err(CoreError::InvalidState(
            "pending effect identity is incomplete",
        ));
    }
    validate_attribute_keys(&effect.expected_attributes)?;
    if let Some(operation) = &effect.operation
        && (operation.project_number != effect.project_number
            || operation.numeric_id == 0
            || operation.self_link.is_empty()
            || operation.location.is_empty())
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
    if receipt.deployment_uuid != state.deployment_uuid
        || state.exact_release.as_deref() != Some(receipt.exact_release.as_str())
    {
        return Err(CoreError::InvalidState("host receipt identity mismatch"));
    }
    if !valid_sha256(&receipt.installer_sha256)
        || !valid_sha256(&receipt.bundle_sha256)
        || receipt.receipt_signature.is_empty()
    {
        return Err(CoreError::InvalidState("host receipt is incomplete"));
    }
    Ok(())
}

fn validate_attribute_keys(attributes: &BTreeMap<String, String>) -> Result<()> {
    for key in attributes.keys() {
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
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
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

/// Secret-free structured progress suitable for human, JSON, or JSONL output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressEvent {
    pub timestamp_unix_ms: u64,
    pub operation: String,
    pub status: ProgressStatus,
    pub message: String,
    pub resource_kind: Option<ResourceKind>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            exact_release: None,
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
        state.pending_effect = Some(PendingEffect {
            effect_id: Uuid::new_v4(),
            deployment_uuid: state.deployment_uuid,
            project_number: 42,
            action: EffectAction::Create,
            resource_kind: ResourceKind::Network,
            resource_name: "network".to_owned(),
            location: "global".to_owned(),
            expected_attributes: BTreeMap::new(),
            operation: Some(OperationRef {
                project_number: 43,
                location: "global".to_owned(),
                numeric_id: 7,
                self_link: "https://compute.googleapis.com/operation/7".to_owned(),
            }),
        });
        assert!(state.validate().is_err());
    }

    #[test]
    fn host_receipt_requires_release_and_pinned_host() {
        let mut state = state();
        state.host_receipt = Some(HostReceipt {
            deployment_uuid: state.deployment_uuid,
            exact_release: "v0.1.0".to_owned(),
            installer_sha256: "a".repeat(64),
            bundle_sha256: "b".repeat(64),
            installed_at_unix_ms: 1,
            receipt_signature: "signature".to_owned(),
        });
        assert!(state.validate().is_err());
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
        });
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState(
                "resource attributes contain an unsafe key"
            ))
        ));
    }
}
