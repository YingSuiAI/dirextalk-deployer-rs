use std::{collections::BTreeMap, fmt, net::Ipv4Addr, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::{
    CoreError, DestroyPlan, DestroyTarget, ExactReleaseIdentity, PlanDigest, ReleaseTag, Result,
    SCHEMA_VERSION, Sha256Digest, validate_service_id,
};

/// Stable Google OIDC `sub`, used as the immutable OAuth owner identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GoogleSubject(String);

impl GoogleSubject {
    /// Parses a bounded, persistence-safe Google subject.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidState`] for empty, oversized, whitespace,
    /// control-character, separator, or otherwise unsafe values.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !(1..=255).contains(&value.len())
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(CoreError::InvalidState("Google OAuth subject is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GoogleSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for GoogleSubject {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for GoogleSubject {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GoogleSubject {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Strict HTTPS Google API operation URI with no credentials, query, or
/// fragment. Cross-field project, scope, and operation-id checks happen when
/// the containing [`PendingEffect`] is validated.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationUri(String);

impl OperationUri {
    /// Parses a bounded Google Compute or Cloud DNS operation URI.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidState`] for non-Google or secret-capable
    /// URI shapes.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let url = url::Url::parse(&value)
            .map_err(|_| CoreError::InvalidState("operation URI is invalid"))?;
        if value.len() > 2_048
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(
                url.host_str(),
                Some("compute.googleapis.com" | "www.googleapis.com" | "dns.googleapis.com")
            )
        {
            return Err(CoreError::InvalidState("operation URI is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OperationUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for OperationUri {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for OperationUri {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OperationUri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Supported SSH host-key algorithms that may be persisted as a pin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshHostKeyAlgorithm {
    Rsa,
    Ecdsa256,
    Ecdsa384,
    Ecdsa521,
    Ed25519,
}

/// Transport-canonical `SHA256:<lowercase-hex>` host-key fingerprint.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SshSha256Fingerprint(String);

impl SshSha256Fingerprint {
    /// Parses a canonical SHA-256 host-key fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidState`] unless the suffix is exactly 64
    /// lowercase hexadecimal characters.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some(encoded) = value.strip_prefix("SHA256:") else {
            return Err(CoreError::InvalidState("SSH host fingerprint is invalid"));
        };
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CoreError::InvalidState("SSH host fingerprint is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SshSha256Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for SshSha256Fingerprint {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for SshSha256Fingerprint {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SshSha256Fingerprint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Immutable authenticated GCP project and OAuth-principal binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub project_id: String,
    pub project_number: u64,
    pub oauth_principal: GoogleSubject,
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
    /// Provider operation name used in the scoped polling endpoint. Compute
    /// names are opaque and are not the numeric operation id.
    pub name: String,
    pub numeric_id: u64,
    pub self_link: OperationUri,
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
    pub address: Ipv4Addr,
    pub algorithm: SshHostKeyAlgorithm,
    pub fingerprint_sha256: SshSha256Fingerprint,
}

/// Sealed destroy/purge approval and durable progress cursor. The current
/// target is `plan.targets[next_target_index]`; the cursor advances atomically
/// with the resource receipt after each deletion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDestroyPlan {
    pub plan: DestroyPlan,
    pub plan_digest: PlanDigest,
    pub next_target_index: u32,
}

impl ActiveDestroyPlan {
    /// Creates a durable destroy cursor only for the exact approved digest.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] if the approval differs from the
    /// complete destroy/purge plan.
    pub fn new(plan: DestroyPlan, approved: PlanDigest) -> Result<Self> {
        if plan.digest()? != approved {
            return Err(CoreError::InvalidPlan("destroy approval digest mismatch"));
        }
        Ok(Self {
            plan,
            plan_digest: approved,
            next_target_index: 0,
        })
    }

    #[must_use]
    pub fn current_target(&self) -> Option<&DestroyTarget> {
        usize::try_from(self.next_target_index)
            .ok()
            .and_then(|index| self.plan.targets.get(index))
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        usize::try_from(self.next_target_index).is_ok_and(|index| index == self.plan.targets.len())
    }

    /// Advances the durable cursor after the exact current target receipt has
    /// been applied to state.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidState`] for an out-of-order receipt or cursor
    /// overflow.
    pub fn advance(&mut self, deleted: &ResourceRef) -> Result<()> {
        if self.current_target().map(|target| &target.resource) != Some(deleted) {
            return Err(CoreError::InvalidState(
                "destroy receipt does not match current target",
            ));
        }
        self.next_target_index = self
            .next_target_index
            .checked_add(1)
            .ok_or(CoreError::InvalidState("destroy target cursor overflow"))?;
        Ok(())
    }
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
    pub active_destroy: Option<ActiveDestroyPlan>,
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
        if !valid_project_id(&self.project_identity.project_id) {
            return Err(CoreError::InvalidState("project identity is incomplete"));
        }
        if matches!(
            self.phase,
            DeploymentPhase::Applying
                | DeploymentPhase::Installed
                | DeploymentPhase::Complete
                | DeploymentPhase::WaitingUser
                | DeploymentPhase::Destroying
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
                &self.project_identity,
                self.deployment_uuid,
            )?;
        }
        validate_phase_receipts_and_resources(self)?;
        validate_active_destroy(self)?;
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
        || !valid_resource_location(resource.resource_kind, &resource.location)
        || !trusted_google_self_link(&resource.self_link)
    {
        return Err(CoreError::InvalidState("resource identity is incomplete"));
    }
    validate_resource_attributes(resource.resource_kind, &resource.observed_attributes)
}

pub(crate) fn validate_resource_name_and_location(
    kind: ResourceKind,
    name: &str,
    location: &str,
) -> Result<()> {
    if !safe_public_name(name) || !valid_resource_location(kind, location) {
        return Err(CoreError::InvalidState("resource identity is incomplete"));
    }
    Ok(())
}

fn validate_effect(
    effect: &PendingEffect,
    phase: DeploymentPhase,
    identity: &ProjectIdentity,
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
    if effect.project_number != identity.project_number || effect.deployment_uuid != deployment_uuid
    {
        return Err(CoreError::InvalidState("pending effect identity mismatch"));
    }
    match (effect.action, &effect.target) {
        (EffectAction::Create, None) => {}
        (EffectAction::Update | EffectAction::Delete, Some(target)) => {
            validate_resource(target, identity.project_number, deployment_uuid)?;
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
    if !safe_public_name(&effect.resource_name)
        || !valid_resource_location(effect.resource_kind, &effect.location)
    {
        return Err(CoreError::InvalidState(
            "pending effect identity is incomplete",
        ));
    }
    if effect.action == EffectAction::Delete {
        validate_resource_attributes(effect.resource_kind, &effect.expected_attributes)?;
    } else {
        validate_attributes(&effect.expected_attributes)?;
    }
    if let Some(operation) = &effect.operation {
        validate_operation(operation, effect, identity)?;
    }
    Ok(())
}

fn validate_operation(
    operation: &OperationRef,
    effect: &PendingEffect,
    identity: &ProjectIdentity,
) -> Result<()> {
    if operation.request_id != effect.effect_id
        || operation.project_number != effect.project_number
        || operation.location != effect.location
        || !safe_public_name(&operation.name)
        || operation.numeric_id == 0
    {
        return Err(CoreError::InvalidState("operation identity mismatch"));
    }
    let url = url::Url::parse(operation.self_link.as_str())
        .map_err(|_| CoreError::InvalidState("operation identity mismatch"))?;
    let segments: Vec<_> = url
        .path_segments()
        .ok_or(CoreError::InvalidState("operation identity mismatch"))?
        .collect();
    let expected_compute_scope = match effect.resource_kind {
        ResourceKind::Network | ResourceKind::Firewall => Some(("global", "operations")),
        ResourceKind::Subnet | ResourceKind::Address => Some(("regions", effect.location.as_str())),
        ResourceKind::Disk | ResourceKind::Instance => Some(("zones", effect.location.as_str())),
        ResourceKind::DnsRecord => None,
    };
    let valid = if let Some((scope_kind, scope_name)) = expected_compute_scope {
        let expected = if scope_kind == "global" {
            vec![
                "compute",
                "v1",
                "projects",
                identity.project_id.as_str(),
                "global",
                "operations",
                operation.name.as_str(),
            ]
        } else {
            vec![
                "compute",
                "v1",
                "projects",
                identity.project_id.as_str(),
                scope_kind,
                scope_name,
                "operations",
                operation.name.as_str(),
            ]
        };
        matches!(
            url.host_str(),
            Some("compute.googleapis.com" | "www.googleapis.com")
        ) && segments == expected
    } else {
        let zone = effect
            .expected_attributes
            .get("zone_name")
            .ok_or(CoreError::InvalidState("operation identity mismatch"))?;
        segments
            == [
                "dns",
                "v1",
                "projects",
                identity.project_id.as_str(),
                "managedZones",
                zone,
                "changes",
                operation.name.as_str(),
            ]
            && operation.name == operation.numeric_id.to_string()
            && url.host_str() == Some("dns.googleapis.com")
    };
    if !valid {
        return Err(CoreError::InvalidState("operation identity mismatch"));
    }
    Ok(())
}

fn validate_phase_receipts_and_resources(state: &DeploymentState) -> Result<()> {
    let infrastructure_complete = state.gcp_resources.network.is_some()
        && state.gcp_resources.subnet.is_some()
        && state.gcp_resources.web_firewall.is_some()
        && state.gcp_resources.turn_firewall.is_some()
        && state.gcp_resources.ssh_firewall.is_some()
        && state.gcp_resources.address.is_some()
        && state.gcp_resources.instance.is_some()
        && state.gcp_resources.boot_disk.is_some();
    match state.phase {
        DeploymentPhase::Planned => {
            if state.pending_effect.is_some()
                || state.active_destroy.is_some()
                || state.gcp_resources.iter().next().is_some()
                || state.ssh_host_identity.is_some()
                || state.host_receipt.is_some()
            {
                return Err(CoreError::InvalidState(
                    "planned deployment contains active receipts",
                ));
            }
        }
        DeploymentPhase::WaitingUser => {
            if !infrastructure_complete
                || state.pending_effect.is_some()
                || state.ssh_host_identity.is_some()
                || state.host_receipt.is_some()
            {
                return Err(CoreError::InvalidState(
                    "waiting deployment infrastructure is incomplete",
                ));
            }
        }
        DeploymentPhase::Installed | DeploymentPhase::Complete => {
            if !infrastructure_complete
                || state.ssh_host_identity.is_none()
                || state.host_receipt.is_none()
                || state.pending_effect.is_some()
            {
                return Err(CoreError::InvalidState(
                    "installed deployment receipts are incomplete",
                ));
            }
            if state.phase == DeploymentPhase::Complete
                && state.local_wiring.requested
                && (!state.local_wiring.installed || !state.local_wiring.service_active)
            {
                return Err(CoreError::InvalidState(
                    "complete deployment local wiring is incomplete",
                ));
            }
        }
        DeploymentPhase::Destroyed => {
            if state.pending_effect.is_some()
                || state.active_destroy.is_some()
                || state.gcp_resources.network.is_some()
                || state.gcp_resources.subnet.is_some()
                || state.gcp_resources.web_firewall.is_some()
                || state.gcp_resources.turn_firewall.is_some()
                || state.gcp_resources.ssh_firewall.is_some()
                || state.gcp_resources.address.is_some()
                || state.gcp_resources.instance.is_some()
                || state.gcp_resources.dns_record.is_some()
            {
                return Err(CoreError::InvalidState(
                    "destroyed deployment retains managed resources",
                ));
            }
        }
        DeploymentPhase::Applying | DeploymentPhase::Destroying | DeploymentPhase::Failed => {}
    }
    Ok(())
}

fn validate_active_destroy(state: &DeploymentState) -> Result<()> {
    let Some(active) = &state.active_destroy else {
        if state.phase == DeploymentPhase::Destroying {
            return Err(CoreError::InvalidState(
                "destroying deployment lacks approved destroy plan",
            ));
        }
        return Ok(());
    };
    if state.phase != DeploymentPhase::Destroying
        || active.plan.digest()? != active.plan_digest
        || active.plan.deployment_uuid != state.deployment_uuid
        || active.plan.service_id != state.service_id
        || active.plan.project_identity != state.project_identity
    {
        return Err(CoreError::InvalidState(
            "active destroy plan identity mismatch",
        ));
    }
    let index = usize::try_from(active.next_target_index)
        .map_err(|_| CoreError::InvalidState("destroy target cursor is invalid"))?;
    if index > active.plan.targets.len() {
        return Err(CoreError::InvalidState("destroy target cursor is invalid"));
    }
    for (target_index, target) in active.plan.targets.iter().enumerate() {
        let recorded = find_resource(&state.gcp_resources, &target.resource);
        if target_index < index {
            if recorded.is_some() {
                return Err(CoreError::InvalidState(
                    "completed destroy target remains recorded",
                ));
            }
        } else if recorded != Some(&target.resource) {
            return Err(CoreError::InvalidState(
                "remaining destroy target identity mismatch",
            ));
        }
    }
    for (_, resource) in state.gcp_resources.iter() {
        let remaining = active.plan.targets[index..]
            .iter()
            .any(|target| target.resource == *resource);
        let retained_disk = matches!(
            &active.plan.boot_disk,
            crate::BootDiskDisposition::Retain { disk: Some(disk) } if disk == resource
        );
        if !remaining && !retained_disk {
            return Err(CoreError::InvalidState(
                "active destroy state contains an unapproved resource",
            ));
        }
    }
    match (&state.pending_effect, active.current_target()) {
        (Some(effect), Some(target)) if pending_matches_destroy_target(effect, target) => {}
        (None, _) => {}
        _ => {
            return Err(CoreError::InvalidState(
                "pending delete differs from active destroy target",
            ));
        }
    }
    if active.is_complete() && state.pending_effect.is_some() {
        return Err(CoreError::InvalidState(
            "completed destroy cursor has a pending effect",
        ));
    }
    Ok(())
}

fn find_resource<'a>(
    resources: &'a GcpResources,
    expected: &ResourceRef,
) -> Option<&'a ResourceRef> {
    resources
        .iter()
        .map(|(_, resource)| resource)
        .find(|resource| {
            resource.resource_kind == expected.resource_kind && resource.name == expected.name
        })
}

fn pending_matches_destroy_target(effect: &PendingEffect, target: &DestroyTarget) -> bool {
    let mut expected_attributes = target.resource.observed_attributes.clone();
    if let Some(value) = target.expected_dns_ipv4 {
        expected_attributes.insert("value".to_owned(), value.to_string());
    }
    effect.action == EffectAction::Delete
        && effect.resource_kind == target.resource.resource_kind
        && effect.resource_name == target.resource.name
        && effect.location == target.resource.location
        && effect.expected_attributes == expected_attributes
        && effect.target.as_ref() == Some(&target.resource)
}

fn validate_host(state: &DeploymentState) -> Result<()> {
    if state
        .ssh_host_identity
        .as_ref()
        .is_some_and(|identity| !is_public_ipv4(identity.address))
    {
        return Err(CoreError::InvalidState("SSH host address is not public"));
    }
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
    let recorded_address = state
        .gcp_resources
        .address
        .as_ref()
        .and_then(|address| address.observed_attributes.get("address"))
        .or_else(|| {
            state.active_destroy.as_ref().and_then(|active| {
                active
                    .plan
                    .targets
                    .iter()
                    .find(|target| target.resource.resource_kind == ResourceKind::Address)
                    .and_then(|target| target.resource.observed_attributes.get("address"))
            })
        })
        .and_then(|address| address.parse::<Ipv4Addr>().ok());
    let address_matches = recorded_address
        == state
            .ssh_host_identity
            .as_ref()
            .map(|identity| identity.address);
    if receipt.deployment_uuid != state.deployment_uuid
        || receipt.release_tag != release.release_tag
        || receipt.host_installer_sha256 != release.host_installer_linux_amd64_sha256
        || receipt.runtime_bundle_sha256 != release.runtime_bundle_linux_amd64_sha256
        || receipt.installed_at_unix_ms == 0
        || !address_matches
    {
        return Err(CoreError::InvalidState("host receipt identity mismatch"));
    }
    if !valid_sha256(&receipt.receipt_signature) {
        return Err(CoreError::InvalidState("host receipt is incomplete"));
    }
    Ok(())
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_documentation()
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        && octets[0] < 224
}

pub(crate) fn validate_attributes(attributes: &BTreeMap<String, String>) -> Result<()> {
    validate_attribute_keys(attributes)?;
    for (key, value) in attributes {
        if !safe_attribute_value(key, value) {
            return Err(CoreError::InvalidState(
                "resource attributes contain an unsafe value",
            ));
        }
    }
    Ok(())
}

fn validate_resource_attributes(
    kind: ResourceKind,
    attributes: &BTreeMap<String, String>,
) -> Result<()> {
    validate_attribute_keys(attributes)?;
    if attributes
        .iter()
        .all(|(key, value)| safe_resource_attribute_value(kind, key, value))
    {
        Ok(())
    } else {
        Err(CoreError::InvalidState(
            "resource attributes contain an unsafe value",
        ))
    }
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
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedFirewallAllowance {
    protocol: String,
    ports: Vec<String>,
}

fn safe_resource_attribute_value(kind: ResourceKind, key: &str, value: &str) -> bool {
    if value.is_empty() || value.len() > 2_048 {
        return false;
    }
    match (kind, key) {
        (ResourceKind::Network, "auto_create_subnetworks")
        | (
            ResourceKind::Instance,
            "boot_disk_auto_delete" | "can_ip_forward" | "deletion_protection",
        ) => value == "false",
        (ResourceKind::Network, "routing_mode") => value == "GLOBAL",
        (ResourceKind::Subnet, "ip_cidr_range") => valid_ipv4_cidr(value, false),
        (ResourceKind::Subnet | ResourceKind::Firewall, "network") => {
            valid_normalized_resource_reference(value, "global", "networks")
        }
        (ResourceKind::Firewall, "allowed") => valid_firewall_allowances(value),
        (ResourceKind::Firewall, "source_ranges") => valid_cidr_list(value),
        (ResourceKind::Firewall, "target_tags") | (ResourceKind::Instance, "network_tags") => {
            valid_name_list(value)
        }
        (ResourceKind::Address, "address") | (ResourceKind::Instance, "nat_ip") => {
            value.parse::<Ipv4Addr>().is_ok_and(is_public_ipv4)
        }
        (ResourceKind::Disk, "size_gb" | "source_image_id")
        | (ResourceKind::DnsRecord, "zone_numeric_id" | "ttl") => positive_integer(value),
        (ResourceKind::Disk, "source_image")
        | (ResourceKind::Instance, "machine_type")
        | (ResourceKind::DnsRecord, "zone_name") => safe_public_name(value),
        (ResourceKind::Disk, "type") => value == "pd-balanced",
        (
            ResourceKind::Instance,
            "access_config_count" | "disk_count" | "metadata_key_count" | "network_interface_count",
        ) => value == "1",
        (ResourceKind::Instance, "service_account_count") => value == "0",
        (ResourceKind::Instance, "boot_disk") => {
            valid_normalized_resource_reference(value, "zones", "disks")
        }
        (ResourceKind::Instance, "ssh_keys_sha256") => valid_sha256(value),
        (ResourceKind::Instance, "subnetwork") => {
            valid_normalized_resource_reference(value, "regions", "subnetworks")
        }
        (ResourceKind::DnsRecord, "value") => value.parse::<Ipv4Addr>().is_ok(),
        (ResourceKind::DnsRecord, "current_values") => {
            serde_json::from_str::<Vec<Ipv4Addr>>(value).is_ok()
        }
        _ => false,
    }
}

fn positive_integer(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|number| number > 0)
}

fn valid_normalized_resource_reference(value: &str, scope: &str, collection: &str) -> bool {
    let segments: Vec<_> = value.split('/').collect();
    match segments.as_slice() {
        ["projects", project, "global", observed_collection, name] => {
            scope == "global"
                && *observed_collection == collection
                && valid_project_id(project)
                && safe_public_name(name)
        }
        [
            "projects",
            project,
            observed_scope,
            location,
            observed_collection,
            name,
        ] => {
            *observed_scope == scope
                && *observed_collection == collection
                && valid_project_id(project)
                && match scope {
                    "regions" => valid_region(location),
                    "zones" => valid_zone(location),
                    _ => false,
                }
                && safe_public_name(name)
        }
        _ => false,
    }
}

fn valid_firewall_allowances(value: &str) -> bool {
    serde_json::from_str::<Vec<ObservedFirewallAllowance>>(value).is_ok_and(|allowances| {
        !allowances.is_empty()
            && allowances.iter().all(|allowance| {
                matches!(allowance.protocol.as_str(), "tcp" | "udp")
                    && !allowance.ports.is_empty()
                    && allowance.ports.iter().all(|port| valid_port(port))
            })
    })
}

fn valid_port(value: &str) -> bool {
    let parse = |value: &str| value.parse::<u16>().ok().filter(|port| *port > 0);
    match value.split_once('-') {
        Some((start, end)) => match (parse(start), parse(end)) {
            (Some(start), Some(end)) => start <= end,
            _ => false,
        },
        None => parse(value).is_some(),
    }
}

fn valid_cidr_list(value: &str) -> bool {
    serde_json::from_str::<Vec<String>>(value).is_ok_and(|ranges| {
        !ranges.is_empty() && ranges.iter().all(|range| valid_ipv4_cidr(range, false))
    })
}

fn valid_name_list(value: &str) -> bool {
    serde_json::from_str::<Vec<String>>(value)
        .is_ok_and(|names| !names.is_empty() && names.iter().all(|name| safe_public_name(name)))
}

fn safe_attribute_value(key: &str, value: &str) -> bool {
    if value.is_empty() || value.len() > 2_048 {
        return false;
    }
    match key {
        "name" | "type" | "machine_type" | "status" | "zone_name" => safe_public_name(value),
        "service_account" => value == "none",
        "cidr" | "source" => valid_ipv4_cidr(value, false),
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

fn valid_resource_location(kind: ResourceKind, value: &str) -> bool {
    match kind {
        ResourceKind::Network | ResourceKind::Firewall | ResourceKind::DnsRecord => {
            value == "global"
        }
        ResourceKind::Subnet | ResourceKind::Address => valid_region(value),
        ResourceKind::Instance | ResourceKind::Disk => valid_zone(value),
    }
}

fn valid_region(value: &str) -> bool {
    (3..=63).contains(&value.len()) && safe_public_name(value) && value.contains('-')
}

fn valid_zone(value: &str) -> bool {
    valid_region(value)
        && value
            .rsplit_once('-')
            .is_some_and(|(region, suffix)| valid_region(region) && suffix.len() == 1)
}

fn valid_project_id(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
                oauth_principal: GoogleSubject::parse("operator.example").unwrap(),
            },
            phase: DeploymentPhase::Applying,
            approved_plan_digest: Some(
                "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
                    .parse()
                    .unwrap(),
            ),
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(test_release_identity()),
            gcp_resources: GcpResources::default(),
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus::default(),
            integrity_digest: String::new(),
        }
    }

    fn resource(
        state: &DeploymentState,
        kind: ResourceKind,
        name: &str,
        location: &str,
        numeric_id: u64,
    ) -> ResourceRef {
        ResourceRef {
            resource_kind: kind,
            name: name.to_owned(),
            project_number: state.project_identity.project_number,
            location: location.to_owned(),
            numeric_id,
            self_link: format!("https://compute.googleapis.com/{name}/{numeric_id}"),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::new(),
        }
    }

    fn active_destroy_state(purge_disk: bool) -> DeploymentState {
        let mut state = state();
        state.gcp_resources.network = Some(resource(
            &state,
            ResourceKind::Network,
            "network",
            "global",
            11,
        ));
        state.gcp_resources.boot_disk = Some(resource(
            &state,
            ResourceKind::Disk,
            "boot",
            "us-central1-a",
            12,
        ));
        let purge_id = purge_disk.then_some(12);
        let plan = DestroyPlan::from_state(&state, purge_id).unwrap();
        let digest = plan.digest().unwrap();
        state.phase = DeploymentPhase::Destroying;
        state.active_destroy = Some(ActiveDestroyPlan::new(plan, digest).unwrap());
        state
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
                name: "operation-7".to_owned(),
                numeric_id: 7,
                self_link: OperationUri::parse(
                    "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/global/operations/operation-7",
                )
                .unwrap(),
            }),
        });
        assert!(state.validate().is_err());
    }

    #[test]
    fn delete_requires_full_target_and_operation_request_binding() {
        let mut state = state();
        let target = ResourceRef {
            resource_kind: ResourceKind::Network,
            name: "network".to_owned(),
            project_number: 42,
            location: "global".to_owned(),
            numeric_id: 8,
            self_link: "https://compute.googleapis.com/network/8".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::new(),
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
            name: "operation-9".to_owned(),
            numeric_id: 9,
            self_link: OperationUri::parse(
                "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/global/operations/operation-9",
            )
            .unwrap(),
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

        state.gcp_resources.address = Some(ResourceRef {
            resource_kind: ResourceKind::Address,
            name: "static-ip".to_owned(),
            project_number: 42,
            location: "us-central1".to_owned(),
            numeric_id: 10,
            self_link: "https://compute.googleapis.com/address/10".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::from([("address".to_owned(), "8.8.8.8".to_owned())]),
        });
        state.ssh_host_identity = Some(SshHostIdentity {
            address: "8.8.8.8".parse().unwrap(),
            algorithm: SshHostKeyAlgorithm::Ed25519,
            fingerprint_sha256: SshSha256Fingerprint::parse(format!("SHA256:{}", "a".repeat(64)))
                .unwrap(),
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
    fn host_receipt_remains_bound_while_its_address_is_deleted() {
        let mut state = state();
        let release = state.release_identity.as_ref().unwrap();
        state.host_receipt = Some(HostReceipt {
            deployment_uuid: state.deployment_uuid,
            release_tag: release.release_tag.clone(),
            host_installer_sha256: release.host_installer_linux_amd64_sha256.clone(),
            runtime_bundle_sha256: release.runtime_bundle_linux_amd64_sha256.clone(),
            installed_at_unix_ms: 1,
            receipt_signature: "d".repeat(64),
        });
        state.gcp_resources.address = Some(ResourceRef {
            resource_kind: ResourceKind::Address,
            name: "static-ip".to_owned(),
            project_number: 42,
            location: "us-central1".to_owned(),
            numeric_id: 10,
            self_link: "https://compute.googleapis.com/address/10".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::from([("address".to_owned(), "8.8.8.8".to_owned())]),
        });
        state.ssh_host_identity = Some(SshHostIdentity {
            address: "8.8.8.8".parse().unwrap(),
            algorithm: SshHostKeyAlgorithm::Ed25519,
            fingerprint_sha256: SshSha256Fingerprint::parse(format!("SHA256:{}", "a".repeat(64)))
                .unwrap(),
        });
        let plan = DestroyPlan::from_state(&state, None).unwrap();
        let digest = plan.digest().unwrap();
        let deleted = state.gcp_resources.address.take().unwrap();
        state.phase = DeploymentPhase::Destroying;
        state.active_destroy = Some(ActiveDestroyPlan::new(plan, digest).unwrap());
        state
            .active_destroy
            .as_mut()
            .unwrap()
            .advance(&deleted)
            .unwrap();
        assert!(state.validate().is_ok());
    }

    #[test]
    fn typed_public_identity_fields_reject_noncanonical_values() {
        assert!(GoogleSubject::parse("").is_err());
        assert!(GoogleSubject::parse("subject with spaces").is_err());
        assert!(OperationUri::parse("http://compute.googleapis.com/operation/1").is_err());
        assert!(OperationUri::parse("https://evil.example/operation/1").is_err());
        assert!(SshSha256Fingerprint::parse(format!("SHA256:{}", "A".repeat(64))).is_err());
        assert!(SshSha256Fingerprint::parse(format!("SHA256:{}", "a".repeat(63))).is_err());

        let mut state = state();
        state.ssh_host_identity = Some(SshHostIdentity {
            address: "10.0.0.1".parse().unwrap(),
            algorithm: SshHostKeyAlgorithm::Ed25519,
            fingerprint_sha256: SshSha256Fingerprint::parse(format!("SHA256:{}", "a".repeat(64)))
                .unwrap(),
        });
        assert!(matches!(
            state.validate(),
            Err(CoreError::InvalidState("SSH host address is not public"))
        ));

        let unknown_algorithm = r#"{"address":"8.8.8.8","algorithm":"dss","fingerprint_sha256":"SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(serde_json::from_str::<SshHostIdentity>(unknown_algorithm).is_err());
    }

    #[test]
    fn destroy_cursor_seals_order_and_crash_boundaries() {
        let mut state = active_destroy_state(false);
        assert!(state.validate().is_ok());
        let target = state
            .active_destroy
            .as_ref()
            .unwrap()
            .current_target()
            .unwrap()
            .resource
            .clone();
        state.pending_effect = Some(PendingEffect {
            effect_id: Uuid::new_v4(),
            deployment_uuid: state.deployment_uuid,
            project_number: state.project_identity.project_number,
            action: EffectAction::Delete,
            resource_kind: target.resource_kind,
            resource_name: target.name.clone(),
            location: target.location.clone(),
            expected_attributes: target.observed_attributes.clone(),
            target: Some(target.clone()),
            operation: None,
        });
        assert!(state.validate().is_ok());

        let mut out_of_order = state.clone();
        let disk = out_of_order
            .gcp_resources
            .boot_disk
            .as_ref()
            .unwrap()
            .clone();
        assert!(
            out_of_order
                .active_destroy
                .as_mut()
                .unwrap()
                .advance(&disk)
                .is_err()
        );

        state.pending_effect = None;
        state.gcp_resources.network = None;
        state
            .active_destroy
            .as_mut()
            .unwrap()
            .advance(&target)
            .unwrap();
        assert!(state.active_destroy.as_ref().unwrap().is_complete());
        assert!(state.validate().is_ok());

        state.phase = DeploymentPhase::Destroyed;
        state.active_destroy = None;
        assert!(state.validate().is_ok());
    }

    #[test]
    fn purge_cursor_requires_disk_removal_before_advancing() {
        let mut state = active_destroy_state(true);
        let disk = state.gcp_resources.boot_disk.as_ref().unwrap().clone();
        assert_eq!(
            state
                .active_destroy
                .as_ref()
                .unwrap()
                .current_target()
                .unwrap()
                .resource,
            disk
        );

        let mut advanced_without_receipt = state.clone();
        advanced_without_receipt
            .active_destroy
            .as_mut()
            .unwrap()
            .advance(&disk)
            .unwrap();
        assert!(advanced_without_receipt.validate().is_err());

        state.gcp_resources.boot_disk = None;
        state
            .active_destroy
            .as_mut()
            .unwrap()
            .advance(&disk)
            .unwrap();
        assert!(state.validate().is_ok());
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
    fn gcp_receipt_attribute_shapes_are_explicit_per_resource_kind() {
        let network = BTreeMap::from([
            ("auto_create_subnetworks".into(), "false".into()),
            ("routing_mode".into(), "GLOBAL".into()),
        ]);
        let subnet = BTreeMap::from([
            ("ip_cidr_range".into(), "10.42.0.0/24".into()),
            (
                "network".into(),
                "projects/dirextalk-prod/global/networks/dt-network".into(),
            ),
        ]);
        let firewall = BTreeMap::from([
            (
                "allowed".into(),
                r#"[{"ports":["3478"],"protocol":"tcp"},{"ports":["3478","49160-49200"],"protocol":"udp"}]"#.into(),
            ),
            (
                "network".into(),
                "projects/dirextalk-prod/global/networks/dt-network".into(),
            ),
            ("source_ranges".into(), r#"["0.0.0.0/0"]"#.into()),
            ("target_tags".into(), r#"["dt-0123456789ab"]"#.into()),
        ]);
        let address = BTreeMap::from([("address".into(), "8.8.8.8".into())]);
        let disk = BTreeMap::from([
            ("size_gb".into(), "50".into()),
            (
                "source_image".into(),
                "ubuntu-2404-noble-amd64-v20260801".into(),
            ),
            ("source_image_id".into(), "123456789".into()),
            ("type".into(), "pd-balanced".into()),
        ]);
        let instance = BTreeMap::from([
            ("access_config_count".into(), "1".into()),
            (
                "boot_disk".into(),
                "projects/dirextalk-prod/zones/us-central1-a/disks/dt-boot".into(),
            ),
            ("boot_disk_auto_delete".into(), "false".into()),
            ("can_ip_forward".into(), "false".into()),
            ("deletion_protection".into(), "false".into()),
            ("disk_count".into(), "1".into()),
            ("machine_type".into(), "e2-custom-2-4096".into()),
            ("metadata_key_count".into(), "1".into()),
            ("nat_ip".into(), "8.8.8.8".into()),
            ("network_interface_count".into(), "1".into()),
            ("network_tags".into(), r#"["dt-0123456789ab"]"#.into()),
            ("service_account_count".into(), "0".into()),
            ("ssh_keys_sha256".into(), "a".repeat(64)),
            (
                "subnetwork".into(),
                "projects/dirextalk-prod/regions/us-central1/subnetworks/dt-subnet".into(),
            ),
        ]);

        for (kind, attributes) in [
            (ResourceKind::Network, network),
            (ResourceKind::Subnet, subnet),
            (ResourceKind::Firewall, firewall),
            (ResourceKind::Address, address),
            (ResourceKind::Disk, disk),
            (ResourceKind::Instance, instance),
        ] {
            validate_resource_attributes(kind, &attributes)
                .unwrap_or_else(|error| panic!("{kind:?} attributes failed: {error}"));
        }

        assert!(
            validate_resource_attributes(
                ResourceKind::Network,
                &BTreeMap::from([("ip_cidr_range".into(), "10.42.0.0/24".into())])
            )
            .is_err()
        );
    }

    #[test]
    fn planned_firewall_source_accepts_open_but_rejects_invalid_cidrs() {
        assert!(
            validate_attributes(&BTreeMap::from([(
                "source".to_owned(),
                "0.0.0.0/0".to_owned(),
            )]))
            .is_ok()
        );

        for invalid in ["203.0.113.7/24", "0.0.0.0/33", "not-a-cidr"] {
            assert!(
                validate_attributes(&BTreeMap::from([
                    ("source".to_owned(), invalid.to_owned(),)
                ]))
                .is_err()
            );
        }
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
