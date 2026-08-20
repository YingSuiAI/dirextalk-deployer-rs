use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{validate_attributes, validate_resource, validate_resource_name_and_location};
use crate::{
    CoreError, DeploymentConfig, DeploymentState, DnsMode, EffectAction, ExactReleaseIdentity,
    PlanDigest, PricingQuote, ProjectIdentity, ReleaseSelection, ResourceKind, ResourceRef, Result,
    SCHEMA_VERSION, canonical_plan_digest,
};

/// Float-free canonical deployment specification bound by a deployment plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDeploymentSpec {
    pub deployment_name: String,
    pub project_id: String,
    pub region: String,
    pub zone: String,
    pub domain: String,
    pub dns_mode: DnsMode,
    pub machine_type: String,
    pub boot_disk_size_gib: u32,
    pub boot_disk_type: String,
    pub operator_ssh_cidr: String,
    pub maximum_monthly_microusd: u64,
    pub release: ReleaseSelection,
    pub connect_agent: String,
    pub install_connect: bool,
}

impl TryFrom<&DeploymentConfig> for CanonicalDeploymentSpec {
    type Error = CoreError;

    fn try_from(config: &DeploymentConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            deployment_name: config.deployment_name.clone(),
            project_id: config.project_id.clone(),
            region: config.region.clone(),
            zone: config.zone.clone(),
            domain: config.domain.clone(),
            dns_mode: config.dns_mode,
            machine_type: config.machine_type.clone(),
            boot_disk_size_gib: config.boot_disk_size_gib,
            boot_disk_type: config.boot_disk_type.clone(),
            operator_ssh_cidr: config.operator_ssh_cidr.clone(),
            maximum_monthly_microusd: config.maximum_monthly_microusd()?,
            release: config.release.clone(),
            connect_agent: config.connect_agent.clone(),
            install_connect: config.install_connect,
        })
    }
}

impl CanonicalDeploymentSpec {
    /// Revalidates a deserialized canonical spec against schema-v1 config
    /// constraints and exact micro-USD conversion.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] unless every field is a canonical
    /// schema-v1 value.
    pub fn validate(&self) -> Result<()> {
        let maximum_monthly_usd = self
            .maximum_monthly_microusd
            .to_string()
            .parse::<f64>()
            .map_err(|_| CoreError::InvalidPlan("deployment budget is invalid"))?
            / 1_000_000.0;
        let config = DeploymentConfig {
            schema_version: SCHEMA_VERSION,
            deployment_name: self.deployment_name.clone(),
            project_id: self.project_id.clone(),
            region: self.region.clone(),
            zone: self.zone.clone(),
            domain: self.domain.clone(),
            dns_mode: self.dns_mode,
            machine_type: self.machine_type.clone(),
            boot_disk_size_gib: self.boot_disk_size_gib,
            boot_disk_type: self.boot_disk_type.clone(),
            operator_ssh_cidr: self.operator_ssh_cidr.clone(),
            maximum_monthly_usd,
            release: self.release.clone(),
            connect_agent: self.connect_agent.clone(),
            install_connect: self.install_connect,
        };
        let rebuilt = Self::try_from(&config)
            .map_err(|_| CoreError::InvalidPlan("deployment spec is invalid"))?;
        if rebuilt != *self {
            return Err(CoreError::InvalidPlan(
                "deployment spec is not in canonical form",
            ));
        }
        Ok(())
    }
}

/// Stable DNS observation. Sets intentionally serialize in sorted order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "management")]
pub enum PlanDnsObservation {
    CloudDns {
        zone_name: String,
        zone_numeric_id: u64,
        current_ipv4: BTreeSet<Ipv4Addr>,
        change: Option<DnsChangeApproval>,
    },
    External {
        current_ipv4: BTreeSet<Ipv4Addr>,
    },
}

/// Exact DNS replacement approved only after the reserved address is known.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsChangeApproval {
    pub replacement_ipv4: Ipv4Addr,
}

/// Whether a plan starts a deployment or continues the same authenticated
/// deployment after its static address has been reserved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "stage")]
pub enum DeploymentPlanStage {
    Initial,
    DnsContinuation {
        previous_plan_digest: PlanDigest,
        address: ResourceRef,
    },
}

impl<'de> Deserialize<'de> for DeploymentPlanStage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "snake_case", tag = "stage")]
        enum StrictStage {
            Initial {},
            DnsContinuation {
                previous_plan_digest: PlanDigest,
                address: ResourceRef,
            },
        }

        Ok(match StrictStage::deserialize(deserializer)? {
            StrictStage::Initial {} => Self::Initial,
            StrictStage::DnsContinuation {
                previous_plan_digest,
                address,
            } => Self::DnsContinuation {
                previous_plan_digest,
                address,
            },
        })
    }
}

/// Exact immutable Ubuntu 24.04 amd64 image resolved before planning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceImageIdentity {
    pub project_id: String,
    pub name: String,
    pub numeric_id: u64,
    pub self_link: String,
}

impl SourceImageIdentity {
    fn validate(&self) -> Result<()> {
        if self.project_id != "ubuntu-os-cloud"
            || self.numeric_id == 0
            || !self.name.starts_with("ubuntu-2404-")
            || !self.name.contains("amd64")
            || self.name.contains("family")
        {
            return Err(CoreError::InvalidPlan(
                "Ubuntu source image identity is invalid",
            ));
        }
        let url = url::Url::parse(&self.self_link)
            .map_err(|_| CoreError::InvalidPlan("Ubuntu source image self-link is invalid"))?;
        let expected_path = format!(
            "/compute/v1/projects/{}/global/images/{}",
            self.project_id, self.name
        );
        if self.self_link.len() > 2_048
            || url.scheme() != "https"
            || !matches!(
                url.host_str(),
                Some("compute.googleapis.com" | "www.googleapis.com")
            )
            || url.path() != expected_path
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(CoreError::InvalidPlan(
                "Ubuntu source image self-link is invalid",
            ));
        }
        Ok(())
    }
}

/// An exact planned mutation. Update/delete targets carry full immutable
/// identity; creates are protected by the eventual `PendingEffect.effect_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedEffect {
    pub action: EffectAction,
    pub resource_kind: ResourceKind,
    pub resource_name: String,
    pub location: String,
    pub expected_attributes: std::collections::BTreeMap<String, String>,
    pub source_image: Option<SourceImageIdentity>,
    pub target: Option<ResourceRef>,
}

impl PlannedEffect {
    fn validate(&self, identity: &ProjectIdentity, deployment_uuid: Uuid) -> Result<()> {
        validate_resource_name_and_location(
            self.resource_kind,
            &self.resource_name,
            &self.location,
        )
        .map_err(|_| CoreError::InvalidPlan("planned effect identity is incomplete"))?;
        validate_attributes(&self.expected_attributes)
            .map_err(|_| CoreError::InvalidPlan("planned effect attributes are unsafe"))?;
        if let Some(image) = &self.source_image {
            image.validate()?;
        }
        match (self.action, &self.target) {
            (EffectAction::Create, None) => Ok(()),
            (EffectAction::Update | EffectAction::Delete, Some(target)) => {
                validate_resource(target, identity.project_number, deployment_uuid)
                    .map_err(|_| CoreError::InvalidPlan("planned target identity is invalid"))?;
                if target.resource_kind != self.resource_kind
                    || target.name != self.resource_name
                    || target.location != self.location
                {
                    return Err(CoreError::InvalidPlan(
                        "planned target does not match the effect",
                    ));
                }
                Ok(())
            }
            _ => Err(CoreError::InvalidPlan(
                "planned target identity is missing or unexpected",
            )),
        }
    }
}

/// The v0.1 product has no cloud Worker implementation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudWorkerDisposition {
    DisabledByProductScope,
}

/// Complete, deterministic input to a deployment approval digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPlan {
    pub schema_version: u32,
    pub deployment_uuid: Uuid,
    pub stage: DeploymentPlanStage,
    pub spec: CanonicalDeploymentSpec,
    pub project_identity: ProjectIdentity,
    pub observed_dns: PlanDnsObservation,
    pub release: ExactReleaseIdentity,
    pub pricing: PricingQuote,
    pub effects: Vec<PlannedEffect>,
    pub cloud_worker: CloudWorkerDisposition,
}

impl DeploymentPlan {
    /// Checks every field required by the frozen v0.1 approval contract.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] for incomplete or contradictory
    /// identity, DNS, cost, release, or effect inputs.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION || self.deployment_uuid.is_nil() {
            return Err(CoreError::InvalidPlan("plan schema or UUID is invalid"));
        }
        validate_project(&self.project_identity)?;
        self.spec.validate()?;
        if self.project_identity.project_id != self.spec.project_id {
            return Err(CoreError::InvalidPlan("plan project identity mismatch"));
        }
        if let ReleaseSelection::Exact(configured) = &self.spec.release
            && configured != &self.release.release_tag
        {
            return Err(CoreError::InvalidPlan(
                "resolved release differs from exact config selection",
            ));
        }
        self.pricing.validate(self.spec.maximum_monthly_microusd)?;
        validate_dns(&self.spec, &self.observed_dns, &self.effects)?;
        validate_plan_stage(self)?;
        if self.effects.is_empty() {
            return Err(CoreError::InvalidPlan("deployment plan has no effects"));
        }
        let mut identities = BTreeSet::new();
        for effect in &self.effects {
            effect.validate(&self.project_identity, self.deployment_uuid)?;
            if !identities.insert((
                effect.resource_kind,
                effect.location.as_str(),
                effect.resource_name.as_str(),
            )) {
                return Err(CoreError::InvalidPlan("deployment plan repeats a resource"));
            }
        }
        Ok(())
    }

    /// Computes the SHA-256 approval over the complete validated plan.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or canonical serialization fails.
    pub fn digest(&self) -> Result<PlanDigest> {
        self.validate()?;
        canonical_plan_digest(self)
    }

    /// Revalidates a DNS continuation against the authenticated current state.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] unless UUID, project, previous
    /// approval, and full reserved-address identity still match.
    pub fn validate_against_state(&self, state: &DeploymentState) -> Result<()> {
        self.validate()?;
        state.validate()?;
        if self.deployment_uuid != state.deployment_uuid
            || self.project_identity != state.project_identity
            || state.release_identity.as_ref() != Some(&self.release)
        {
            return Err(CoreError::InvalidPlan(
                "continuation state or release identity mismatch",
            ));
        }
        let DeploymentPlanStage::DnsContinuation {
            previous_plan_digest,
            address,
        } = &self.stage
        else {
            return Err(CoreError::InvalidPlan("plan is not a DNS continuation"));
        };
        if state.approved_plan_digest.as_ref() != Some(previous_plan_digest)
            || state.gcp_resources.address.as_ref() != Some(address)
        {
            return Err(CoreError::InvalidPlan(
                "continuation previous plan or address identity mismatch",
            ));
        }
        Ok(())
    }
}

fn validate_dns(
    spec: &CanonicalDeploymentSpec,
    observation: &PlanDnsObservation,
    effects: &[PlannedEffect],
) -> Result<()> {
    let dns_mutation = effects
        .iter()
        .any(|effect| effect.resource_kind == ResourceKind::DnsRecord);
    match observation {
        PlanDnsObservation::CloudDns {
            zone_name,
            zone_numeric_id,
            current_ipv4,
            change,
        } => {
            if spec.dns_mode == DnsMode::External || zone_name.is_empty() || *zone_numeric_id == 0 {
                return Err(CoreError::InvalidPlan("Cloud DNS observation is invalid"));
            }
            if dns_mutation && change.is_none() {
                return Err(CoreError::InvalidPlan(
                    "DNS mutation requires a staged exact replacement",
                ));
            }
            if !dns_mutation && change.is_some() {
                return Err(CoreError::InvalidPlan(
                    "DNS replacement approval has no planned mutation",
                ));
            }
            if let Some(change) = change {
                validate_cloud_dns_effect(
                    spec,
                    zone_name,
                    *zone_numeric_id,
                    current_ipv4,
                    *change,
                    effects,
                )?;
            }
        }
        PlanDnsObservation::External { .. } => {
            if spec.dns_mode == DnsMode::CloudDns || dns_mutation {
                return Err(CoreError::InvalidPlan(
                    "external DNS plan cannot contain a cloud DNS mutation",
                ));
            }
        }
    }
    Ok(())
}

fn validate_cloud_dns_effect(
    spec: &CanonicalDeploymentSpec,
    zone_name: &str,
    zone_numeric_id: u64,
    current_ipv4: &BTreeSet<Ipv4Addr>,
    change: DnsChangeApproval,
    effects: &[PlannedEffect],
) -> Result<()> {
    let mut dns_effects = effects
        .iter()
        .filter(|effect| effect.resource_kind == ResourceKind::DnsRecord);
    let effect = dns_effects
        .next()
        .ok_or(CoreError::InvalidPlan("DNS change effect is missing"))?;
    let current_values =
        serde_json::to_string(current_ipv4).map_err(|_| CoreError::CanonicalSerialization)?;
    let expected_attributes = BTreeMap::from([
        ("current_values".to_owned(), current_values.clone()),
        ("ttl".to_owned(), "300".to_owned()),
        ("value".to_owned(), change.replacement_ipv4.to_string()),
        ("zone_name".to_owned(), zone_name.to_owned()),
        ("zone_numeric_id".to_owned(), zone_numeric_id.to_string()),
    ]);
    if dns_effects.next().is_some()
        || effect.resource_name != spec.domain
        || effect.location != "global"
        || effect.source_image.is_some()
    {
        return Err(CoreError::InvalidPlan("DNS change effect is not exact"));
    }
    if effect.expected_attributes != expected_attributes {
        return Err(CoreError::InvalidPlan("DNS change effect is not exact"));
    }
    if current_ipv4.is_empty() {
        if effect.action != EffectAction::Create || effect.target.is_some() {
            return Err(CoreError::InvalidPlan(
                "new DNS record has an unexpected target",
            ));
        }
    } else {
        let target = effect
            .target
            .as_ref()
            .ok_or(CoreError::InvalidPlan("DNS overwrite target is missing"))?;
        let expected_target_attributes = BTreeMap::from([
            ("current_values".to_owned(), current_values),
            ("zone_name".to_owned(), zone_name.to_owned()),
            ("zone_numeric_id".to_owned(), zone_numeric_id.to_string()),
        ]);
        if effect.action != EffectAction::Update
            || target.numeric_id != zone_numeric_id
            || target.observed_attributes != expected_target_attributes
        {
            return Err(CoreError::InvalidPlan(
                "DNS overwrite does not bind exact old values and zone",
            ));
        }
    }
    Ok(())
}

fn validate_plan_stage(plan: &DeploymentPlan) -> Result<()> {
    let dns_mutation = plan
        .effects
        .iter()
        .any(|effect| effect.resource_kind == ResourceKind::DnsRecord);
    match &plan.stage {
        DeploymentPlanStage::Initial => {
            if dns_mutation {
                return Err(CoreError::InvalidPlan(
                    "initial plan cannot mutate DNS before address reservation",
                ));
            }
            validate_initial_effects(plan)?;
        }
        DeploymentPlanStage::DnsContinuation { address, .. } => {
            validate_resource(
                address,
                plan.project_identity.project_number,
                plan.deployment_uuid,
            )
            .map_err(|_| CoreError::InvalidPlan("continuation address identity is invalid"))?;
            if address.resource_kind != ResourceKind::Address
                || !dns_mutation
                || plan.effects.len() != 1
            {
                return Err(CoreError::InvalidPlan(
                    "DNS continuation lacks address identity or DNS mutation",
                ));
            }
            let PlanDnsObservation::CloudDns {
                change: Some(change),
                ..
            } = &plan.observed_dns
            else {
                return Err(CoreError::InvalidPlan(
                    "DNS continuation lacks an exact replacement",
                ));
            };
            let recorded: Ipv4Addr = address
                .observed_attributes
                .get("address")
                .ok_or(CoreError::InvalidPlan("reserved address value is missing"))?
                .parse()
                .map_err(|_| CoreError::InvalidPlan("reserved address value is invalid"))?;
            if recorded != change.replacement_ipv4 {
                return Err(CoreError::InvalidPlan(
                    "DNS replacement differs from the reserved address",
                ));
            }
        }
    }
    Ok(())
}

fn validate_initial_effects(plan: &DeploymentPlan) -> Result<()> {
    if plan.effects.len() != 8 {
        return Err(CoreError::InvalidPlan(
            "initial plan does not contain the exact v0.1 topology",
        ));
    }
    let suffix = &plan.deployment_uuid.simple().to_string()[..12];
    let base = format!("dt-{}-{suffix}", plan.spec.deployment_name);
    let expected = [
        (
            ResourceKind::Network,
            format!("{base}-net"),
            "global".to_owned(),
            BTreeMap::from([("cidr".to_owned(), "10.42.0.0/24".to_owned())]),
        ),
        (
            ResourceKind::Subnet,
            format!("{base}-subnet"),
            plan.spec.region.clone(),
            BTreeMap::from([("cidr".to_owned(), "10.42.0.0/24".to_owned())]),
        ),
        (
            ResourceKind::Firewall,
            format!("{base}-web"),
            "global".to_owned(),
            BTreeMap::from([("ports".to_owned(), "tcp:80,tcp:443".to_owned())]),
        ),
        (
            ResourceKind::Firewall,
            format!("{base}-turn"),
            "global".to_owned(),
            BTreeMap::from([(
                "ports".to_owned(),
                "tcp:3478,udp:3478,udp:49160-49200".to_owned(),
            )]),
        ),
        (
            ResourceKind::Firewall,
            format!("{base}-ssh"),
            "global".to_owned(),
            BTreeMap::from([("source".to_owned(), plan.spec.operator_ssh_cidr.clone())]),
        ),
        (
            ResourceKind::Address,
            format!("{base}-ip"),
            plan.spec.region.clone(),
            BTreeMap::new(),
        ),
        (
            ResourceKind::Disk,
            format!("{base}-boot"),
            plan.spec.zone.clone(),
            BTreeMap::from([
                (
                    "size_gib".to_owned(),
                    plan.spec.boot_disk_size_gib.to_string(),
                ),
                ("type".to_owned(), plan.spec.boot_disk_type.clone()),
            ]),
        ),
        (
            ResourceKind::Instance,
            format!("{base}-vm"),
            plan.spec.zone.clone(),
            BTreeMap::from([
                ("machine_type".to_owned(), plan.spec.machine_type.clone()),
                ("service_account".to_owned(), "none".to_owned()),
            ]),
        ),
    ];
    for (index, (kind, name, location, attributes)) in expected.into_iter().enumerate() {
        let effect = &plan.effects[index];
        let image_shape_valid = if kind == ResourceKind::Disk {
            effect.source_image.is_some()
        } else {
            effect.source_image.is_none()
        };
        if effect.action != EffectAction::Create
            || effect.resource_kind != kind
            || effect.resource_name != name
            || effect.location != location
            || effect.expected_attributes != attributes
            || effect.target.is_some()
            || !image_shape_valid
        {
            return Err(CoreError::InvalidPlan(
                "initial plan does not contain the exact v0.1 topology",
            ));
        }
    }
    Ok(())
}

/// Exact disposition of the boot disk in a destroy approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "mode")]
pub enum BootDiskDisposition {
    Retain { disk: Option<ResourceRef> },
    Purge { disk: ResourceRef },
}

/// One identity-bound deletion, including the exact DNS value where relevant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestroyTarget {
    pub resource: ResourceRef,
    pub expected_dns_ipv4: Option<Ipv4Addr>,
}

/// Complete deterministic input for default destroy or distinct disk purge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestroyPlan {
    pub schema_version: u32,
    pub deployment_uuid: Uuid,
    pub service_id: String,
    pub project_identity: ProjectIdentity,
    pub targets: Vec<DestroyTarget>,
    pub boot_disk: BootDiskDisposition,
}

impl DestroyPlan {
    /// Builds the exact current destroy plan from authenticated deployment
    /// state. Supplying a numeric id creates a distinct purge plan and must
    /// match the complete recorded boot-disk identity.
    ///
    /// # Errors
    ///
    /// Returns an error if state is invalid, DNS identity is incomplete, or a
    /// requested disk id is not the recorded boot disk.
    pub fn from_state(state: &DeploymentState, purge_disk: Option<u64>) -> Result<Self> {
        state.validate()?;
        let disk = state.gcp_resources.boot_disk.clone();
        let boot_disk = match purge_disk {
            None => BootDiskDisposition::Retain { disk: disk.clone() },
            Some(numeric_id) => {
                let disk = disk.ok_or(CoreError::InvalidPlan("boot disk is not recorded"))?;
                if disk.numeric_id != numeric_id {
                    return Err(CoreError::InvalidPlan("boot disk numeric id mismatch"));
                }
                BootDiskDisposition::Purge { disk }
            }
        };
        let mut targets = Vec::new();
        push_target(&mut targets, state.gcp_resources.dns_record.as_ref())?;
        push_target(&mut targets, state.gcp_resources.instance.as_ref())?;
        if let BootDiskDisposition::Purge { disk } = &boot_disk {
            targets.push(DestroyTarget {
                resource: disk.clone(),
                expected_dns_ipv4: None,
            });
        }
        push_target(&mut targets, state.gcp_resources.web_firewall.as_ref())?;
        push_target(&mut targets, state.gcp_resources.turn_firewall.as_ref())?;
        push_target(&mut targets, state.gcp_resources.ssh_firewall.as_ref())?;
        push_target(&mut targets, state.gcp_resources.address.as_ref())?;
        push_target(&mut targets, state.gcp_resources.subnet.as_ref())?;
        push_target(&mut targets, state.gcp_resources.network.as_ref())?;
        let plan = Self {
            schema_version: SCHEMA_VERSION,
            deployment_uuid: state.deployment_uuid,
            service_id: state.service_id.clone(),
            project_identity: state.project_identity.clone(),
            targets,
            boot_disk,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validates destroy and purge identity invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] if any deletion lacks exact identity,
    /// DNS value, or the correct disk disposition.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION || self.deployment_uuid.is_nil() {
            return Err(CoreError::InvalidPlan("destroy schema or UUID is invalid"));
        }
        crate::validate_service_id(&self.service_id)
            .map_err(|_| CoreError::InvalidPlan("destroy service id is invalid"))?;
        validate_project(&self.project_identity)?;
        let mut identities = BTreeSet::new();
        for target in &self.targets {
            validate_resource(
                &target.resource,
                self.project_identity.project_number,
                self.deployment_uuid,
            )
            .map_err(|_| CoreError::InvalidPlan("destroy target identity is invalid"))?;
            if target.resource.resource_kind == ResourceKind::DnsRecord {
                if target.expected_dns_ipv4.is_none() {
                    return Err(CoreError::InvalidPlan("destroy DNS value is missing"));
                }
            } else if target.expected_dns_ipv4.is_some() {
                return Err(CoreError::InvalidPlan(
                    "DNS value is attached to a non-DNS target",
                ));
            }
            if !identities.insert((
                target.resource.resource_kind,
                target.resource.numeric_id,
                target.resource.self_link.as_str(),
            )) {
                return Err(CoreError::InvalidPlan("destroy target is repeated"));
            }
        }
        validate_disk_disposition(
            &self.boot_disk,
            &self.targets,
            &self.project_identity,
            self.deployment_uuid,
        )
    }

    /// Computes the distinct SHA-256 approval for this destroy or purge plan.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or canonical serialization fails.
    pub fn digest(&self) -> Result<PlanDigest> {
        self.validate()?;
        canonical_plan_digest(self)
    }

    /// Rebuilds the current destroy/purge plan from authenticated state and
    /// requires byte-for-byte semantic equality before execution.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] if any resource, DNS value, or disk
    /// disposition differs from current authenticated state.
    pub fn validate_against_state(&self, state: &DeploymentState) -> Result<()> {
        let purge_id = match &self.boot_disk {
            BootDiskDisposition::Retain { .. } => None,
            BootDiskDisposition::Purge { disk } => Some(disk.numeric_id),
        };
        let current = Self::from_state(state, purge_id)?;
        if current != *self {
            return Err(CoreError::InvalidPlan(
                "destroy plan differs from current authenticated state",
            ));
        }
        Ok(())
    }
}

fn push_target(targets: &mut Vec<DestroyTarget>, resource: Option<&ResourceRef>) -> Result<()> {
    let Some(resource) = resource else {
        return Ok(());
    };
    let expected_dns_ipv4 = if resource.resource_kind == ResourceKind::DnsRecord {
        Some(
            resource
                .observed_attributes
                .get("value")
                .ok_or(CoreError::InvalidPlan("recorded DNS value is missing"))?
                .parse()
                .map_err(|_| CoreError::InvalidPlan("recorded DNS value is invalid"))?,
        )
    } else {
        None
    };
    targets.push(DestroyTarget {
        resource: resource.clone(),
        expected_dns_ipv4,
    });
    Ok(())
}

fn validate_disk_disposition(
    disposition: &BootDiskDisposition,
    targets: &[DestroyTarget],
    identity: &ProjectIdentity,
    deployment_uuid: Uuid,
) -> Result<()> {
    let planned_disks: Vec<_> = targets
        .iter()
        .filter(|target| target.resource.resource_kind == ResourceKind::Disk)
        .collect();
    match disposition {
        BootDiskDisposition::Retain { disk } => {
            if !planned_disks.is_empty() {
                return Err(CoreError::InvalidPlan(
                    "retained boot disk is scheduled for deletion",
                ));
            }
            if let Some(disk) = disk {
                validate_resource(disk, identity.project_number, deployment_uuid).map_err(
                    |_| CoreError::InvalidPlan("retained boot disk identity is invalid"),
                )?;
                if disk.resource_kind != ResourceKind::Disk {
                    return Err(CoreError::InvalidPlan("retained resource is not a disk"));
                }
            }
        }
        BootDiskDisposition::Purge { disk } => {
            validate_resource(disk, identity.project_number, deployment_uuid)
                .map_err(|_| CoreError::InvalidPlan("purged boot disk identity is invalid"))?;
            if disk.resource_kind != ResourceKind::Disk
                || planned_disks.len() != 1
                || planned_disks[0].resource != *disk
            {
                return Err(CoreError::InvalidPlan(
                    "purge disk target identity mismatch",
                ));
            }
        }
    }
    Ok(())
}

fn validate_project(identity: &ProjectIdentity) -> Result<()> {
    if identity.project_id.is_empty() || identity.project_number == 0 {
        return Err(CoreError::InvalidPlan("project identity is incomplete"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        DeploymentPhase, GcpResources, GoogleSubject, LinuxAmd64ApplicationIdentity,
        LinuxAmd64UpdaterIdentity, LocalWiringStatus, PricingCurrency, PricingLine, PricingQuote,
        ProjectIdentity, RationalQuantity, ReleaseTag, Sha256Digest, SigningKeyIdentity,
        SourceRevision, UnpricedExclusion, service_id,
    };

    fn config() -> DeploymentConfig {
        DeploymentConfig::parse(
            r#"
schema_version = 1
deployment_name = "production"
project_id = "dirextalk-prod"
region = "us-central1"
zone = "us-central1-a"
domain = "talk.example.com"
operator_ssh_cidr = "203.0.113.7/32"
maximum_monthly_usd = 150.0
release = "stable"
"#,
        )
        .unwrap()
    }

    fn identity() -> ProjectIdentity {
        ProjectIdentity {
            project_id: "dirextalk-prod".to_owned(),
            project_number: 42,
            oauth_principal: GoogleSubject::parse("operator.example").unwrap(),
        }
    }

    fn sha(character: char) -> Sha256Digest {
        Sha256Digest::parse(character.to_string().repeat(64)).unwrap()
    }

    fn revision(character: char) -> SourceRevision {
        SourceRevision::parse(character.to_string().repeat(40)).unwrap()
    }

    fn release() -> ExactReleaseIdentity {
        ExactReleaseIdentity {
            release_tag: ReleaseTag::parse("v0.1.0").unwrap(),
            release_manifest_sha256: sha('1'),
            release_manifest_source_revision: revision('2'),
            host_installer_linux_amd64_sha256: sha('3'),
            runtime_bundle_linux_amd64_sha256: sha('4'),
            signed_runtime_manifest_linux_amd64_sha256: sha('5'),
            runtime_manifest_signing_key: SigningKeyIdentity::parse("6".repeat(64)).unwrap(),
            message_server: LinuxAmd64ApplicationIdentity {
                version: ReleaseTag::parse("v1.2.3").unwrap(),
                source_revision: revision('7'),
                image_sha256: sha('8'),
            },
            agent: LinuxAmd64ApplicationIdentity {
                version: ReleaseTag::parse("v2.3.4").unwrap(),
                source_revision: revision('9'),
                image_sha256: sha('a'),
            },
            updater: LinuxAmd64UpdaterIdentity {
                version: ReleaseTag::parse("v3.4.5").unwrap(),
                source_revision: revision('b'),
                asset_sha256: sha('c'),
            },
        }
    }

    fn pricing() -> PricingQuote {
        PricingQuote {
            currency: PricingCurrency::Usd,
            lines: BTreeSet::from([PricingLine {
                sku_id: "SKU-VM".to_owned(),
                tier_start_base_units: 0,
                usage_unit: "h".to_owned(),
                base_unit: "s".to_owned(),
                base_unit_conversion: RationalQuantity {
                    numerator: 3_600,
                    denominator: 1,
                },
                usage_quantity: RationalQuantity {
                    numerator: 730,
                    denominator: 1,
                },
                unit_price_nanos: 136_986_370,
                subtotal_microusd: 100_000_051,
            }]),
            unpriced_exclusions: BTreeSet::from([UnpricedExclusion::NetworkEgress]),
            total_microusd: 100_000_051,
        }
    }

    fn resource(kind: ResourceKind, uuid: Uuid, name: &str, numeric_id: u64) -> ResourceRef {
        ResourceRef {
            resource_kind: kind,
            name: name.to_owned(),
            project_number: 42,
            location: match kind {
                ResourceKind::Instance | ResourceKind::Disk => "us-central1-a".to_owned(),
                ResourceKind::Subnet | ResourceKind::Address => "us-central1".to_owned(),
                ResourceKind::Network | ResourceKind::Firewall | ResourceKind::DnsRecord => {
                    "global".to_owned()
                }
            },
            numeric_id,
            self_link: format!("https://compute.googleapis.com/{name}/{numeric_id}"),
            deployment_uuid: uuid,
            observed_attributes: BTreeMap::from([("name".to_owned(), name.to_owned())]),
        }
    }

    fn deployment_plan() -> DeploymentPlan {
        let config = config();
        let mut plan = DeploymentPlan {
            schema_version: 1,
            deployment_uuid: Uuid::new_v4(),
            stage: DeploymentPlanStage::Initial,
            spec: CanonicalDeploymentSpec::try_from(&config).unwrap(),
            project_identity: identity(),
            observed_dns: PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            },
            release: release(),
            pricing: pricing(),
            effects: Vec::new(),
            cloud_worker: CloudWorkerDisposition::DisabledByProductScope,
        };
        let suffix = &plan.deployment_uuid.simple().to_string()[..12];
        let base = format!("dt-production-{suffix}");
        let effect =
            |resource_kind, suffix: &str, location: &str, expected_attributes| PlannedEffect {
                action: EffectAction::Create,
                resource_kind,
                resource_name: format!("{base}-{suffix}"),
                location: location.to_owned(),
                expected_attributes,
                source_image: None,
                target: None,
            };
        plan.effects = vec![
            effect(
                ResourceKind::Network,
                "net",
                "global",
                BTreeMap::from([("cidr".to_owned(), "10.42.0.0/24".to_owned())]),
            ),
            effect(
                ResourceKind::Subnet,
                "subnet",
                "us-central1",
                BTreeMap::from([("cidr".to_owned(), "10.42.0.0/24".to_owned())]),
            ),
            effect(
                ResourceKind::Firewall,
                "web",
                "global",
                BTreeMap::from([("ports".to_owned(), "tcp:80,tcp:443".to_owned())]),
            ),
            effect(
                ResourceKind::Firewall,
                "turn",
                "global",
                BTreeMap::from([(
                    "ports".to_owned(),
                    "tcp:3478,udp:3478,udp:49160-49200".to_owned(),
                )]),
            ),
            effect(
                ResourceKind::Firewall,
                "ssh",
                "global",
                BTreeMap::from([("source".to_owned(), "203.0.113.7/32".to_owned())]),
            ),
            effect(ResourceKind::Address, "ip", "us-central1", BTreeMap::new()),
            PlannedEffect {
                source_image: Some(SourceImageIdentity {
                    project_id: "ubuntu-os-cloud".to_owned(),
                    name: "ubuntu-2404-noble-amd64-v20260801".to_owned(),
                    numeric_id: 123,
                    self_link: "https://compute.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20260801".to_owned(),
                }),
                ..effect(
                    ResourceKind::Disk,
                    "boot",
                    "us-central1-a",
                    BTreeMap::from([
                        ("size_gib".to_owned(), "50".to_owned()),
                        ("type".to_owned(), "pd-balanced".to_owned()),
                    ]),
                )
            },
            effect(
                ResourceKind::Instance,
                "vm",
                "us-central1-a",
                BTreeMap::from([
                    ("machine_type".to_owned(), "e2-custom-2-4096".to_owned()),
                    ("service_account".to_owned(), "none".to_owned()),
                ]),
            ),
        ];
        plan
    }

    #[test]
    fn typed_deployment_plan_digest_is_stable_for_dns_set_order() {
        let mut first = deployment_plan();
        first.observed_dns = PlanDnsObservation::External {
            current_ipv4: [
                "203.0.113.2".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
        };
        let mut second = first.clone();
        second.observed_dns = PlanDnsObservation::External {
            current_ipv4: [
                "203.0.113.1".parse().unwrap(),
                "203.0.113.2".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn initial_plan_requires_exact_order_and_exact_source_image() {
        let mut reordered = deployment_plan();
        reordered.effects.swap(0, 1);
        assert!(matches!(reordered.digest(), Err(CoreError::InvalidPlan(_))));

        let mut missing_image = deployment_plan();
        missing_image.effects[6].source_image = None;
        assert!(matches!(
            missing_image.digest(),
            Err(CoreError::InvalidPlan(_))
        ));

        let mut family_image = deployment_plan();
        let image = family_image.effects[6].source_image.as_mut().unwrap();
        image.name = "ubuntu-2404-lts-amd64-family".to_owned();
        image.self_link = "https://compute.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64".to_owned();
        assert!(matches!(
            family_image.digest(),
            Err(CoreError::InvalidPlan(
                "Ubuntu source image identity is invalid"
                    | "Ubuntu source image self-link is invalid"
            ))
        ));

        let mut wrong_attribute = deployment_plan();
        wrong_attribute.effects[2]
            .expected_attributes
            .insert("ports".to_owned(), "tcp:443".to_owned());
        assert!(matches!(
            wrong_attribute.digest(),
            Err(CoreError::InvalidPlan(_))
        ));
    }

    #[test]
    fn tagged_plan_enums_reject_unknown_fields() {
        assert!(
            serde_json::from_str::<DeploymentPlanStage>(r#"{"stage":"initial","unexpected":true}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<PlanDnsObservation>(
                r#"{"management":"external","current_ipv4":[],"unexpected":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<BootDiskDisposition>(
                r#"{"mode":"retain","disk":null,"unexpected":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn deployment_digest_binds_every_external_contract_category() {
        let base = deployment_plan();
        let digest = base.digest().unwrap();
        let variants = [
            {
                let mut plan = base.clone();
                plan.project_identity.oauth_principal =
                    GoogleSubject::parse("other.subject").unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                plan.spec.region = "us-east1".to_owned();
                plan.spec.zone = "us-east1-b".to_owned();
                plan.effects[1].location = "us-east1".to_owned();
                plan.effects[5].location = "us-east1".to_owned();
                plan.effects[6].location = "us-east1-b".to_owned();
                plan.effects[7].location = "us-east1-b".to_owned();
                plan
            },
            {
                let mut plan = base.clone();
                plan.observed_dns = PlanDnsObservation::External {
                    current_ipv4: BTreeSet::from(["203.0.113.8".parse().unwrap()]),
                };
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.release_tag = ReleaseTag::parse("v0.1.1").unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                let mut line = plan.pricing.lines.pop_first().unwrap();
                line.unit_price_nanos += 1;
                plan.pricing.lines.insert(line);
                plan
            },
            {
                let mut plan = base.clone();
                let image = plan.effects[6].source_image.as_mut().unwrap();
                image.name = "ubuntu-2404-noble-amd64-v20260802".to_owned();
                image.numeric_id += 1;
                image.self_link = format!(
                    "https://compute.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/{}",
                    image.name
                );
                plan
            },
        ];
        for variant in variants {
            assert_ne!(variant.digest().unwrap(), digest);
        }
    }

    #[test]
    fn deployment_digest_binds_every_release_artifact_identity() {
        let base = deployment_plan();
        let digest = base.digest().unwrap();
        let variants = [
            {
                let mut plan = base.clone();
                plan.release.release_tag = ReleaseTag::parse("v0.1.1").unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.release_manifest_sha256 = sha('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.release_manifest_source_revision = revision('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.host_installer_linux_amd64_sha256 = sha('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.runtime_bundle_linux_amd64_sha256 = sha('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.signed_runtime_manifest_linux_amd64_sha256 = sha('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.runtime_manifest_signing_key =
                    SigningKeyIdentity::parse("d".repeat(64)).unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.message_server.version = ReleaseTag::parse("v1.2.4").unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.message_server.source_revision = revision('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.message_server.image_sha256 = sha('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.agent.version = ReleaseTag::parse("v2.3.5").unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.agent.source_revision = revision('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.agent.image_sha256 = sha('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.updater.version = ReleaseTag::parse("v3.4.6").unwrap();
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.updater.source_revision = revision('d');
                plan
            },
            {
                let mut plan = base.clone();
                plan.release.updater.asset_sha256 = sha('d');
                plan
            },
        ];
        for variant in variants {
            assert_ne!(variant.digest().unwrap(), digest);
        }
    }

    #[test]
    fn deployment_digest_binds_pricing_details_even_when_total_is_unchanged() {
        let base = deployment_plan();
        let digest = base.digest().unwrap();
        let mutate_line = |mutation: fn(&mut PricingLine)| {
            let mut plan = base.clone();
            let mut line = plan.pricing.lines.pop_first().unwrap();
            mutation(&mut line);
            plan.pricing.lines.insert(line);
            plan
        };
        let variants = [
            mutate_line(|line| line.sku_id = "SKU-VM-OTHER".to_owned()),
            mutate_line(|line| line.tier_start_base_units = 1),
            mutate_line(|line| line.usage_unit = "month".to_owned()),
            mutate_line(|line| line.base_unit = "min".to_owned()),
            mutate_line(|line| {
                line.base_unit_conversion = RationalQuantity {
                    numerator: 60,
                    denominator: 1,
                };
            }),
            mutate_line(|line| {
                line.usage_quantity = RationalQuantity {
                    numerator: 730_000_001,
                    denominator: 1_000_000,
                };
            }),
            mutate_line(|line| line.unit_price_nanos += 1),
            {
                let mut plan = base.clone();
                plan.pricing
                    .unpriced_exclusions
                    .insert(UnpricedExclusion::Taxes);
                plan
            },
        ];
        for variant in variants {
            assert_eq!(variant.pricing.total_microusd, base.pricing.total_microusd);
            assert_ne!(variant.digest().unwrap(), digest);
        }
    }

    #[test]
    fn conflicting_dns_requires_explicit_overwrite() {
        let mut plan = deployment_plan();
        plan.spec.dns_mode = DnsMode::CloudDns;
        plan.observed_dns = PlanDnsObservation::CloudDns {
            zone_name: "example-com".to_owned(),
            zone_numeric_id: 7,
            current_ipv4: BTreeSet::from(["203.0.113.1".parse().unwrap()]),
            change: None,
        };
        plan.effects.push(PlannedEffect {
            action: EffectAction::Create,
            resource_kind: ResourceKind::DnsRecord,
            resource_name: "talk.example.com".to_owned(),
            location: "global".to_owned(),
            expected_attributes: BTreeMap::new(),
            source_image: None,
            target: None,
        });
        assert!(matches!(plan.digest(), Err(CoreError::InvalidPlan(_))));
    }

    #[test]
    fn dns_continuation_binds_previous_plan_address_and_new_ip() {
        let initial = deployment_plan();
        let previous = initial.digest().unwrap();
        let mut continuation = initial.clone();
        let mut address = resource(
            ResourceKind::Address,
            continuation.deployment_uuid,
            "static-ip",
            81,
        );
        address
            .observed_attributes
            .insert("address".to_owned(), "203.0.113.42".to_owned());
        continuation.stage = DeploymentPlanStage::DnsContinuation {
            previous_plan_digest: previous.clone(),
            address,
        };
        continuation.spec.dns_mode = DnsMode::CloudDns;
        continuation.observed_dns = PlanDnsObservation::CloudDns {
            zone_name: "example-com".to_owned(),
            zone_numeric_id: 7,
            current_ipv4: BTreeSet::from(["203.0.113.1".parse().unwrap()]),
            change: Some(DnsChangeApproval {
                replacement_ipv4: "203.0.113.42".parse().unwrap(),
            }),
        };
        continuation.effects = vec![PlannedEffect {
            action: EffectAction::Update,
            resource_kind: ResourceKind::DnsRecord,
            resource_name: "talk.example.com".to_owned(),
            location: "global".to_owned(),
            expected_attributes: BTreeMap::from([
                ("current_values".to_owned(), "[\"203.0.113.1\"]".to_owned()),
                ("ttl".to_owned(), "300".to_owned()),
                ("value".to_owned(), "203.0.113.42".to_owned()),
                ("zone_name".to_owned(), "example-com".to_owned()),
                ("zone_numeric_id".to_owned(), "7".to_owned()),
            ]),
            source_image: None,
            target: Some(ResourceRef {
                resource_kind: ResourceKind::DnsRecord,
                name: "talk.example.com".to_owned(),
                project_number: 42,
                location: "global".to_owned(),
                numeric_id: 7,
                self_link: "https://dns.googleapis.com/dns/v1/projects/dirextalk-prod/managedZones/example-com/rrsets/talk.example.com".to_owned(),
                deployment_uuid: continuation.deployment_uuid,
                observed_attributes: BTreeMap::from([
                    ("current_values".to_owned(), "[\"203.0.113.1\"]".to_owned()),
                    ("zone_name".to_owned(), "example-com".to_owned()),
                    ("zone_numeric_id".to_owned(), "7".to_owned()),
                ]),
            }),
        }];
        continuation.digest().unwrap();

        let mut state = DeploymentState {
            schema_version: 1,
            deployment_uuid: continuation.deployment_uuid,
            service_id: service_id("production", 42).unwrap(),
            project_identity: identity(),
            phase: DeploymentPhase::Applying,
            approved_plan_digest: Some(previous),
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(continuation.release.clone()),
            gcp_resources: GcpResources {
                address: Some(match &continuation.stage {
                    DeploymentPlanStage::DnsContinuation { address, .. } => address.clone(),
                    DeploymentPlanStage::Initial => unreachable!(),
                }),
                ..GcpResources::default()
            },
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus::default(),
            integrity_digest: String::new(),
        };
        assert!(continuation.validate_against_state(&state).is_ok());
        state
            .release_identity
            .as_mut()
            .unwrap()
            .runtime_bundle_linux_amd64_sha256 = sha('d');
        assert!(matches!(
            continuation.validate_against_state(&state),
            Err(CoreError::InvalidPlan(
                "continuation state or release identity mismatch"
            ))
        ));
    }

    #[test]
    fn purge_plan_binds_the_complete_recorded_disk_identity() {
        let uuid = Uuid::new_v4();
        let disk = resource(ResourceKind::Disk, uuid, "boot", 91);
        let state = DeploymentState {
            schema_version: 1,
            deployment_uuid: uuid,
            service_id: service_id("production", 42).unwrap(),
            project_identity: identity(),
            phase: DeploymentPhase::Applying,
            approved_plan_digest: Some(deployment_plan().digest().unwrap()),
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(release()),
            gcp_resources: GcpResources {
                boot_disk: Some(disk.clone()),
                network: Some(resource(ResourceKind::Network, uuid, "network", 11)),
                ..GcpResources::default()
            },
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus::default(),
            integrity_digest: String::new(),
        };
        let retain = DestroyPlan::from_state(&state, None).unwrap();
        let purge = DestroyPlan::from_state(&state, Some(91)).unwrap();
        assert_ne!(retain.digest().unwrap(), purge.digest().unwrap());
        assert!(DestroyPlan::from_state(&state, Some(92)).is_err());
        assert!(matches!(
            purge.boot_disk,
            BootDiskDisposition::Purge { disk: bound } if bound == disk
        ));
        assert!(retain.validate_against_state(&state).is_ok());
        let mut incomplete = retain;
        incomplete.targets.clear();
        assert!(incomplete.validate_against_state(&state).is_err());
    }
}
