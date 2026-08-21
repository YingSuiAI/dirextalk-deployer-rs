#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use deployer_core::{
    ActiveDestroyPlan, CanonicalDeploymentSpec, CloudWorkerDisposition, DeploymentConfig,
    DeploymentPhase, DeploymentPlan, DeploymentPlanStage, DeploymentState, DestroyPlan,
    DnsChangeApproval, EffectAction, ExactReleaseIdentity, GcpResources, HostReceipt,
    LocalWiringStatus, OperationRef, PendingEffect, PlanDigest, PlanDnsObservation, PlannedEffect,
    PricingQuote, ProjectIdentity, ResourceKind, ResourceRef, SourceImageIdentity, SshHostIdentity,
    canonical_json, service_id,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("deployment configuration could not be read")]
    ConfigRead,
    #[error("deployment core rejected the operation: {0}")]
    Core(#[from] deployer_core::CoreError),
    #[error("approved plan does not match the exact current plan")]
    ApprovalMismatch,
    #[error("deployment state does not exist")]
    MissingState,
    #[error("deployment state belongs to a different plan or configuration")]
    StatePlanMismatch,
    #[error("a deployment already exists for this service")]
    ExistingState,
    #[error("boot disk numeric id does not match the recorded disk")]
    DiskIdentityMismatch,
    #[error("cloud or host operation failed: {0}")]
    Backend(String),
    #[error("operator action is required: {0}")]
    WaitingUser(String),
    #[error("state operation failed: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanObservations {
    pub project_identity: ProjectIdentity,
    pub observed_dns: PlanDnsObservation,
    pub boot_image: deployer_gcp::ImageIdentity,
    pub release: ExactReleaseIdentity,
    pub pricing: PricingQuote,
}

#[derive(Clone, Debug)]
pub enum Completion {
    Complete { initialization_code: SecretString },
    WaitingExternalDns { name: String, value: String },
}

impl PartialEq for Completion {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Complete {
                    initialization_code: left,
                },
                Self::Complete {
                    initialization_code: right,
                },
            ) => left.expose_secret() == right.expose_secret(),
            (
                Self::WaitingExternalDns {
                    name: left_name,
                    value: left_value,
                },
                Self::WaitingExternalDns {
                    name: right_name,
                    value: right_value,
                },
            ) => left_name == right_name && left_value == right_value,
            _ => false,
        }
    }
}

impl Eq for Completion {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectReceipt {
    Present(ResourceRef),
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectStart {
    Started(OperationRef),
    AlreadySatisfied(EffectReceipt),
}

#[async_trait]
pub trait DeploymentBackend: Send + Sync {
    async fn observe(&self, config: &DeploymentConfig) -> Result<PlanObservations>;
    async fn revalidate_project(&self, identity: &ProjectIdentity) -> Result<()>;
    async fn start_effect(
        &self,
        state: &DeploymentState,
        effect: &PendingEffect,
        source_image: Option<&SourceImageIdentity>,
    ) -> Result<EffectStart>;
    async fn poll_effect(
        &self,
        state: &DeploymentState,
        effect: &PendingEffect,
        source_image: Option<&SourceImageIdentity>,
    ) -> Result<EffectReceipt>;
    async fn revalidate_resource(
        &self,
        identity: &ProjectIdentity,
        resource: &ResourceRef,
    ) -> Result<()>;
    async fn revalidate_effect(
        &self,
        identity: &ProjectIdentity,
        effect: &PendingEffect,
        receipt: &EffectReceipt,
    ) -> Result<()>;
    async fn external_dns_ready(&self, domain: &str, address: &str) -> Result<bool>;
    async fn install_host(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<(SshHostIdentity, HostReceipt)>;
    async fn complete_product(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<SecretString>;
    async fn install_connect(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<LocalWiringStatus>;
    async fn uninstall_connect(&self, state: &DeploymentState) -> Result<LocalWiringStatus>;
    async fn verify_product(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<()>;
}

pub trait DeploymentStore {
    fn read(&self) -> Result<Option<DeploymentState>>;
    fn write(&self, state: &DeploymentState) -> Result<()>;
    fn read_plan(&self) -> Result<Option<DeploymentPlan>>;
    fn write_plan(&self, plan: &DeploymentPlan) -> Result<()>;
}

impl DeploymentStore for deployer_core::StateStore {
    fn read(&self) -> Result<Option<DeploymentState>> {
        deployer_core::StateStore::read(self).map_err(EngineError::from)
    }

    fn write(&self, state: &DeploymentState) -> Result<()> {
        deployer_core::StateStore::write(self, state).map_err(EngineError::from)
    }

    fn read_plan(&self) -> Result<Option<DeploymentPlan>> {
        read_plan_file(&self.paths().root().join("approved-plan.json"))
    }

    fn write_plan(&self, plan: &DeploymentPlan) -> Result<()> {
        write_plan_file(&self.paths().root().join("approved-plan.json"), plan)
    }
}

pub struct Orchestrator<'a, B, S> {
    backend: &'a B,
    store: &'a S,
}

impl<'a, B: DeploymentBackend, S: DeploymentStore> Orchestrator<'a, B, S> {
    pub const fn new(backend: &'a B, store: &'a S) -> Self {
        Self { backend, store }
    }

    pub async fn apply(&self, plan: &DeploymentPlan, approved: &PlanDigest) -> Result<Completion> {
        let digest = plan.digest()?;
        if &digest != approved {
            return Err(EngineError::ApprovalMismatch);
        }
        if let Some(mut state) = self.store.read()? {
            plan.validate_against_state(&state)?;
            self.backend
                .revalidate_project(&state.project_identity)
                .await?;
            state.approved_plan_digest = Some(digest);
            state.phase = DeploymentPhase::Applying;
            self.store.write_plan(plan)?;
            self.store.write(&state)?;
            let config = config_from_spec(&plan.spec)?;
            return self.resume_plan(&config, plan).await;
        }
        self.store.write_plan(plan)?;
        let service_id = service_id(
            &plan.spec.deployment_name,
            plan.project_identity.project_number,
        )?;
        let state = DeploymentState {
            schema_version: 1,
            deployment_uuid: plan.deployment_uuid,
            service_id,
            project_identity: plan.project_identity.clone(),
            approved_plan_digest: Some(digest),
            phase: DeploymentPhase::Applying,
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(plan.release.clone()),
            gcp_resources: GcpResources::default(),
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus {
                requested: plan.spec.install_connect,
                ..LocalWiringStatus::default()
            },
            integrity_digest: String::new(),
        };
        self.store.write(&state)?;
        let config = config_from_spec(&plan.spec)?;
        self.resume_plan(&config, plan).await
    }

    pub async fn resume_plan(
        &self,
        config: &DeploymentConfig,
        plan: &DeploymentPlan,
    ) -> Result<Completion> {
        let mut state = self.store.read()?.ok_or(EngineError::MissingState)?;
        let plan_digest = plan.digest()?;
        if state.approved_plan_digest.as_ref() != Some(&plan_digest)
            || state.deployment_uuid != plan.deployment_uuid
            || state.project_identity != plan.project_identity
            || plan.spec != CanonicalDeploymentSpec::try_from(config)?
        {
            return Err(EngineError::StatePlanMismatch);
        }
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        let automatic_dns = automatic_cloud_dns_effect(config, plan, &state)?;
        let pending_plan = match state.pending_effect.as_ref() {
            Some(pending) => Some(
                plan.effects
                    .iter()
                    .chain(automatic_dns.iter())
                    .find(|planned| planned_matches(pending, planned))
                    .ok_or(EngineError::StatePlanMismatch)?,
            ),
            None => None,
        };
        self.resume_pending(
            &mut state,
            pending_plan.and_then(|planned| planned.source_image.as_ref()),
        )
        .await?;
        for effect in &plan.effects {
            if resource_for_effect(&state.gcp_resources, effect).is_some() {
                continue;
            }
            self.execute_effect(&mut state, effect).await?;
        }

        if matches!(plan.observed_dns, PlanDnsObservation::External { .. }) {
            let address = public_address(&state)?;
            if !self
                .backend
                .external_dns_ready(&config.domain, &address)
                .await?
            {
                state.phase = DeploymentPhase::WaitingUser;
                self.store.write(&state)?;
                return Ok(Completion::WaitingExternalDns {
                    name: config.domain.clone(),
                    value: address,
                });
            }
        }

        if let Some(effect) = automatic_cloud_dns_effect(config, plan, &state)? {
            self.execute_effect(&mut state, &effect).await?;
        }

        if state.host_receipt.is_none() {
            self.backend
                .revalidate_project(&state.project_identity)
                .await?;
            revalidate_all(self.backend, &state).await?;
            let (ssh_identity, receipt) = self.backend.install_host(config, &state).await?;
            state.ssh_host_identity = Some(ssh_identity);
            state.host_receipt = Some(receipt);
            state.phase = DeploymentPhase::Installed;
            self.store.write(&state)?;
        }
        let initialization_code = self.backend.complete_product(config, &state).await?;
        if state.local_wiring.requested && !state.local_wiring.installed {
            state.local_wiring = self.backend.install_connect(config, &state).await?;
            self.store.write(&state)?;
        }
        self.backend.verify_product(config, &state).await?;
        state.phase = DeploymentPhase::Complete;
        self.store.write(&state)?;
        Ok(Completion::Complete {
            initialization_code,
        })
    }

    pub async fn resume(&self, config: &DeploymentConfig) -> Result<Completion> {
        let plan = self
            .store
            .read_plan()?
            .ok_or(EngineError::StatePlanMismatch)?;
        self.resume_plan(config, &plan).await
    }

    /// Reconciles exactly the currently journaled effect from the approved
    /// plan and stops before starting any later effect.
    pub async fn resume_pending_only(&self, config: &DeploymentConfig) -> Result<()> {
        let plan = self
            .store
            .read_plan()?
            .ok_or(EngineError::StatePlanMismatch)?;
        let mut state = self.store.read()?.ok_or(EngineError::MissingState)?;
        let plan_digest = plan.digest()?;
        if state.approved_plan_digest.as_ref() != Some(&plan_digest)
            || state.deployment_uuid != plan.deployment_uuid
            || state.project_identity != plan.project_identity
            || plan.spec != CanonicalDeploymentSpec::try_from(config)?
        {
            return Err(EngineError::StatePlanMismatch);
        }
        let pending = state.pending_effect.as_ref().ok_or_else(|| {
            EngineError::WaitingUser("there is no journaled effect to reconcile".into())
        })?;
        if pending.deployment_uuid != plan.deployment_uuid
            || pending.project_number != plan.project_identity.project_number
        {
            return Err(EngineError::StatePlanMismatch);
        }
        let automatic_dns = automatic_cloud_dns_effect(config, &plan, &state)?;
        let planned = plan
            .effects
            .iter()
            .chain(automatic_dns.iter())
            .find(|planned| planned_matches(pending, planned))
            .ok_or(EngineError::StatePlanMismatch)?;
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        self.resume_pending(&mut state, planned.source_image.as_ref())
            .await
    }

    pub async fn destroy(&self, plan: &DestroyPlan, approved: &PlanDigest) -> Result<()> {
        if plan.digest()? != *approved {
            return Err(EngineError::ApprovalMismatch);
        }
        let mut state = self.store.read()?.ok_or(EngineError::MissingState)?;
        if state.deployment_uuid != plan.deployment_uuid
            || state.project_identity != plan.project_identity
            || state.service_id != plan.service_id
        {
            return Err(EngineError::StatePlanMismatch);
        }
        if state.phase == DeploymentPhase::Destroying {
            let active = state
                .active_destroy
                .as_ref()
                .ok_or(EngineError::StatePlanMismatch)?;
            if active.plan != *plan || active.plan_digest != *approved {
                return Err(EngineError::StatePlanMismatch);
            }
        } else {
            plan.validate_against_state(&state)?;
            state.active_destroy = Some(ActiveDestroyPlan::new(plan.clone(), approved.clone())?);
            state.phase = DeploymentPhase::Destroying;
            self.store.write(&state)?;
        }
        self.resume_pending(&mut state, None).await?;
        while let Some(target) = state
            .active_destroy
            .as_ref()
            .and_then(ActiveDestroyPlan::current_target)
            .cloned()
        {
            let resource = target.resource.clone();
            let mut expected_attributes = resource.observed_attributes.clone();
            if let Some(value) = target.expected_dns_ipv4 {
                expected_attributes.insert("value".into(), value.to_string());
            }
            let effect = PlannedEffect {
                action: EffectAction::Delete,
                resource_kind: resource.resource_kind,
                resource_name: resource.name.clone(),
                location: resource.location.clone(),
                expected_attributes,
                source_image: None,
                target: Some(resource),
            };
            match resource_for_effect(&state.gcp_resources, &effect) {
                None => continue,
                Some(current) if effect.target.as_ref() != Some(current) => {
                    return Err(EngineError::StatePlanMismatch);
                }
                Some(_) => {}
            }
            self.backend
                .revalidate_project(&state.project_identity)
                .await?;
            let target = effect.target.as_ref().ok_or_else(|| {
                EngineError::State("approved delete effect lacks its immutable target".into())
            })?;
            self.backend
                .revalidate_resource(&state.project_identity, target)
                .await?;
            self.execute_effect(&mut state, &effect).await?;
        }
        if state.local_wiring.installed {
            state.local_wiring = self.backend.uninstall_connect(&state).await?;
        }
        state.phase = DeploymentPhase::Destroyed;
        state.active_destroy = None;
        state.ssh_host_identity = None;
        state.host_receipt = None;
        self.store.write(&state)
    }

    pub async fn plan_destroy(&self, purge_disk: Option<u64>) -> Result<DestroyPlan> {
        let state = self.store.read()?.ok_or(EngineError::MissingState)?;
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        if let Some(active) = &state.active_destroy {
            let active_purge = match &active.plan.boot_disk {
                deployer_core::BootDiskDisposition::Retain { .. } => None,
                deployer_core::BootDiskDisposition::Purge { disk } => Some(disk.numeric_id),
            };
            if active_purge != purge_disk {
                return Err(EngineError::StatePlanMismatch);
            }
            return Ok(active.plan.clone());
        }
        revalidate_all(self.backend, &state).await?;
        DestroyPlan::from_state(&state, purge_disk).map_err(EngineError::from)
    }

    pub fn status(&self) -> Result<DeploymentState> {
        self.store.read()?.ok_or(EngineError::MissingState)
    }

    pub async fn verify(&self, config: &DeploymentConfig) -> Result<()> {
        let state = self.store.read()?.ok_or(EngineError::MissingState)?;
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        revalidate_all(self.backend, &state).await?;
        self.backend.verify_product(config, &state).await
    }

    pub async fn install_connect(&self, config: &DeploymentConfig) -> Result<LocalWiringStatus> {
        let mut state = self.store.read()?.ok_or(EngineError::MissingState)?;
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        revalidate_all(self.backend, &state).await?;
        state.local_wiring = self.backend.install_connect(config, &state).await?;
        self.store.write(&state)?;
        Ok(state.local_wiring)
    }

    async fn execute_effect(
        &self,
        state: &mut DeploymentState,
        planned: &PlannedEffect,
    ) -> Result<()> {
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        let effect = PendingEffect {
            effect_id: Uuid::new_v4(),
            deployment_uuid: state.deployment_uuid,
            project_number: state.project_identity.project_number,
            action: planned.action,
            resource_kind: planned.resource_kind,
            resource_name: planned.resource_name.clone(),
            location: planned.location.clone(),
            expected_attributes: planned.expected_attributes.clone(),
            target: planned.target.clone(),
            operation: None,
        };
        state.pending_effect = Some(effect);
        self.store.write(state)?;
        self.resume_pending(state, planned.source_image.as_ref())
            .await
    }

    async fn resume_pending(
        &self,
        state: &mut DeploymentState,
        source_image: Option<&SourceImageIdentity>,
    ) -> Result<()> {
        let Some(mut pending) = state.pending_effect.clone() else {
            return Ok(());
        };
        self.backend
            .revalidate_project(&state.project_identity)
            .await?;
        let receipt = if pending.operation.is_none() {
            match self
                .backend
                .start_effect(state, &pending, source_image)
                .await?
            {
                EffectStart::Started(operation) => {
                    pending.operation = Some(operation);
                    state.pending_effect = Some(pending.clone());
                    self.store.write(state)?;
                    self.backend
                        .poll_effect(state, &pending, source_image)
                        .await?
                }
                EffectStart::AlreadySatisfied(receipt) => receipt,
            }
        } else {
            self.backend
                .poll_effect(state, &pending, source_image)
                .await?
        };
        self.backend
            .revalidate_effect(&state.project_identity, &pending, &receipt)
            .await?;
        apply_receipt(&mut state.gcp_resources, &pending, receipt)?;
        if pending.action == EffectAction::Delete {
            let deleted = pending
                .target
                .as_ref()
                .ok_or_else(|| EngineError::State("delete receipt lacks its target".into()))?;
            state
                .active_destroy
                .as_mut()
                .ok_or_else(|| EngineError::State("delete receipt lacks an active plan".into()))?
                .advance(deleted)?;
        }
        state.pending_effect = None;
        self.store.write(state)
    }
}

fn read_plan_file(path: &std::path::Path) -> Result<Option<DeploymentPlan>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(EngineError::State(
                "approved plan could not be inspected".into(),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(EngineError::State("approved plan path is unsafe".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let parent_uid = path
            .parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .filter(|parent| parent.is_dir() && !parent.file_type().is_symlink())
            .map(|parent| parent.uid())
            .ok_or_else(|| EngineError::State("approved plan directory is unsafe".into()))?;
        if metadata.uid() != parent_uid || metadata.mode() & 0o077 != 0 {
            return Err(EngineError::State("approved plan path is unsafe".into()));
        }
    }
    let bytes = std::fs::read(path)
        .map_err(|_| EngineError::State("approved plan could not be read".into()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| EngineError::State("approved plan is invalid".into()))
}

fn write_plan_file(path: &std::path::Path, plan: &DeploymentPlan) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| EngineError::State("approved plan path has no parent".into()))?;
    std::fs::create_dir_all(parent)
        .map_err(|_| EngineError::State("approved plan directory could not be created".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| EngineError::State("approved plan directory is not private".into()))?;
        let parent_metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| EngineError::State("approved plan directory is unsafe".into()))?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(EngineError::State(
                "approved plan directory is unsafe".into(),
            ));
        }
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(EngineError::State("approved plan path is unsafe".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let parent_uid = std::fs::symlink_metadata(parent)
                .map_err(|_| EngineError::State("approved plan directory is unsafe".into()))?
                .uid();
            if metadata.uid() != parent_uid {
                return Err(EngineError::State("approved plan path is unsafe".into()));
            }
        }
    }
    let bytes = canonical_json(plan)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".approved-plan-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|_| {
            EngineError::State("approved plan temporary file could not be created".into())
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| {
                EngineError::State("approved plan permissions could not be restricted".into())
            })?;
    }
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| EngineError::State("approved plan could not be synchronized".into()))?;
    temporary
        .persist(path)
        .map_err(|_| EngineError::State("approved plan could not be replaced".into()))?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn build_plan(
    config: &DeploymentConfig,
    observed: PlanObservations,
    existing: Option<&DeploymentState>,
) -> Result<DeploymentPlan> {
    if observed.project_identity.project_id != config.project_id {
        return Err(EngineError::Backend(
            "observed project id differs from config".into(),
        ));
    }
    let spec = CanonicalDeploymentSpec::try_from(config)?;
    let deployment_uuid = existing.map_or_else(
        || deterministic_deployment_uuid(config, &observed.project_identity),
        |state| Ok(state.deployment_uuid),
    )?;
    let suffix = &deployment_uuid.simple().to_string()[..12];
    let base = format!("dt-{}-{suffix}", config.deployment_name);
    let initial_effects = vec![
        effect(ResourceKind::Network, &format!("{base}-net"), "global", []),
        effect(
            ResourceKind::Subnet,
            &format!("{base}-subnet"),
            &config.region,
            [("cidr", "10.42.0.0/24")],
        ),
        effect(
            ResourceKind::Firewall,
            &format!("{base}-web"),
            "global",
            [("ports", "tcp:80,tcp:443")],
        ),
        effect(
            ResourceKind::Firewall,
            &format!("{base}-turn"),
            "global",
            [("ports", "tcp:3478,udp:3478,udp:49160-49200")],
        ),
        effect(
            ResourceKind::Firewall,
            &format!("{base}-ssh"),
            "global",
            [("source", config.operator_ssh_cidr.as_str())],
        ),
        effect(
            ResourceKind::Address,
            &format!("{base}-ip"),
            &config.region,
            [],
        ),
        PlannedEffect {
            source_image: Some(SourceImageIdentity {
                project_id: observed.boot_image.project_id.clone(),
                name: observed.boot_image.name.clone(),
                numeric_id: observed
                    .boot_image
                    .numeric_id
                    .parse()
                    .map_err(|_| EngineError::Backend("GCP boot image id is invalid".into()))?,
                self_link: observed.boot_image.self_link.clone(),
            }),
            ..effect(
                ResourceKind::Disk,
                &format!("{base}-boot"),
                &config.zone,
                [
                    ("size_gib", &config.boot_disk_size_gib.to_string()),
                    ("type", config.boot_disk_type.as_str()),
                ],
            )
        },
        effect(
            ResourceKind::Instance,
            &format!("{base}-vm"),
            &config.zone,
            [
                ("machine_type", config.machine_type.as_str()),
                ("service_account", "none"),
            ],
        ),
    ];
    let (stage, observed_dns, effects) = match existing {
        None => (
            DeploymentPlanStage::Initial,
            observed.observed_dns,
            initial_effects,
        ),
        Some(state) => {
            if state.project_identity != observed.project_identity
                || state.release_identity.as_ref() != Some(&observed.release)
                || state.gcp_resources.dns_record.is_some()
            {
                return Err(EngineError::ExistingState);
            }
            let address = state
                .gcp_resources
                .address
                .clone()
                .ok_or(EngineError::ExistingState)?;
            let replacement: Ipv4Addr = address
                .observed_attributes
                .get("address")
                .ok_or_else(|| EngineError::State("reserved address value is missing".into()))?
                .parse()
                .map_err(|_| EngineError::State("reserved address value is invalid".into()))?;
            let previous_plan_digest = state
                .approved_plan_digest
                .clone()
                .ok_or(EngineError::StatePlanMismatch)?;
            let PlanDnsObservation::CloudDns {
                zone_name,
                zone_numeric_id,
                current_ipv4,
                change: None,
            } = observed.observed_dns
            else {
                return Err(EngineError::ExistingState);
            };
            let current_values = serde_json::to_string(&current_ipv4)
                .map_err(|_| EngineError::Backend("DNS values could not be encoded".into()))?;
            let target = (!current_ipv4.is_empty()).then(|| ResourceRef {
                resource_kind: ResourceKind::DnsRecord,
                name: config.domain.clone(),
                project_number: state.project_identity.project_number,
                location: "global".into(),
                numeric_id: zone_numeric_id,
                self_link: format!(
                    "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{zone_name}/rrsets/{}/A",
                    state.project_identity.project_id, config.domain
                ),
                deployment_uuid: state.deployment_uuid,
                observed_attributes: BTreeMap::from([
                    ("zone_name".into(), zone_name.clone()),
                    ("zone_numeric_id".into(), zone_numeric_id.to_string()),
                    ("current_values".into(), current_values.clone()),
                ]),
            });
            let action = if target.is_some() {
                EffectAction::Update
            } else {
                EffectAction::Create
            };
            let dns_effect = PlannedEffect {
                action,
                resource_kind: ResourceKind::DnsRecord,
                resource_name: config.domain.clone(),
                location: "global".into(),
                expected_attributes: BTreeMap::from([
                    ("zone_name".into(), zone_name.clone()),
                    ("zone_numeric_id".into(), zone_numeric_id.to_string()),
                    ("current_values".into(), current_values),
                    ("value".into(), replacement.to_string()),
                    ("ttl".into(), "300".into()),
                ]),
                source_image: None,
                target,
            };
            (
                DeploymentPlanStage::DnsContinuation {
                    previous_plan_digest,
                    address,
                },
                PlanDnsObservation::CloudDns {
                    zone_name,
                    zone_numeric_id,
                    current_ipv4,
                    change: Some(DnsChangeApproval {
                        replacement_ipv4: replacement,
                    }),
                },
                vec![dns_effect],
            )
        }
    };
    let plan = DeploymentPlan {
        schema_version: 1,
        deployment_uuid,
        stage,
        spec,
        project_identity: observed.project_identity,
        observed_dns,
        release: observed.release,
        pricing: observed.pricing,
        effects,
        cloud_worker: CloudWorkerDisposition::DisabledByProductScope,
    };
    plan.validate()?;
    if let Some(state) = existing {
        plan.validate_against_state(state)?;
    }
    Ok(plan)
}

fn deterministic_deployment_uuid(
    config: &DeploymentConfig,
    identity: &ProjectIdentity,
) -> Result<Uuid> {
    let bytes = canonical_json(&(config, identity))?;
    let digest = Sha256::digest(bytes);
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(uuid))
}

fn config_from_spec(spec: &CanonicalDeploymentSpec) -> Result<DeploymentConfig> {
    #[allow(clippy::cast_precision_loss)]
    let maximum_monthly_usd = spec.maximum_monthly_microusd as f64 / 1_000_000.0;
    let config = DeploymentConfig {
        schema_version: 1,
        deployment_name: spec.deployment_name.clone(),
        project_id: spec.project_id.clone(),
        region: spec.region.clone(),
        zone: spec.zone.clone(),
        domain: spec.domain.clone(),
        dns_mode: spec.dns_mode,
        machine_type: spec.machine_type.clone(),
        boot_disk_size_gib: spec.boot_disk_size_gib,
        boot_disk_type: spec.boot_disk_type.clone(),
        operator_ssh_cidr: spec.operator_ssh_cidr.clone(),
        maximum_monthly_usd,
        release: spec.release.clone(),
        connect_agent: spec.connect_agent.clone(),
        install_connect: spec.install_connect,
    };
    config.validate()?;
    Ok(config)
}

fn effect<'a, const N: usize>(
    kind: ResourceKind,
    name: &str,
    location: &str,
    attributes: [(&'a str, &'a str); N],
) -> PlannedEffect {
    PlannedEffect {
        action: EffectAction::Create,
        resource_kind: kind,
        resource_name: name.into(),
        location: location.into(),
        expected_attributes: attributes
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect(),
        source_image: None,
        target: None,
    }
}

fn planned_matches(pending: &PendingEffect, planned: &PlannedEffect) -> bool {
    pending.deployment_uuid != Uuid::nil()
        && pending.action == planned.action
        && pending.resource_kind == planned.resource_kind
        && pending.resource_name == planned.resource_name
        && pending.location == planned.location
        && pending.expected_attributes == planned.expected_attributes
        && pending.target == planned.target
}

fn automatic_cloud_dns_effect(
    config: &DeploymentConfig,
    plan: &DeploymentPlan,
    state: &DeploymentState,
) -> Result<Option<PlannedEffect>> {
    if state.gcp_resources.dns_record.is_some()
        || !matches!(plan.stage, DeploymentPlanStage::Initial)
    {
        return Ok(None);
    }
    let PlanDnsObservation::CloudDns {
        zone_name,
        zone_numeric_id,
        current_ipv4,
        change: None,
    } = &plan.observed_dns
    else {
        return Ok(None);
    };
    let Some(address) = state.gcp_resources.address.as_ref() else {
        return Ok(None);
    };
    let replacement: Ipv4Addr = address
        .observed_attributes
        .get("address")
        .ok_or_else(|| EngineError::State("reserved address value is missing".into()))?
        .parse()
        .map_err(|_| EngineError::State("reserved address value is invalid".into()))?;
    let current_values = serde_json::to_string(current_ipv4)
        .map_err(|_| EngineError::Backend("DNS values could not be encoded".into()))?;
    let target = (!current_ipv4.is_empty()).then(|| ResourceRef {
        resource_kind: ResourceKind::DnsRecord,
        name: config.domain.clone(),
        project_number: state.project_identity.project_number,
        location: "global".into(),
        numeric_id: *zone_numeric_id,
        self_link: format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{zone_name}/rrsets/{}/A",
            state.project_identity.project_id, config.domain
        ),
        deployment_uuid: state.deployment_uuid,
        observed_attributes: BTreeMap::from([
            ("zone_name".into(), zone_name.clone()),
            ("zone_numeric_id".into(), zone_numeric_id.to_string()),
            ("current_values".into(), current_values.clone()),
        ]),
    });
    Ok(Some(PlannedEffect {
        action: if target.is_some() {
            EffectAction::Update
        } else {
            EffectAction::Create
        },
        resource_kind: ResourceKind::DnsRecord,
        resource_name: config.domain.clone(),
        location: "global".into(),
        expected_attributes: BTreeMap::from([
            ("zone_name".into(), zone_name.clone()),
            ("zone_numeric_id".into(), zone_numeric_id.to_string()),
            ("current_values".into(), current_values),
            ("value".into(), replacement.to_string()),
            ("ttl".into(), "300".into()),
        ]),
        source_image: None,
        target,
    }))
}

fn public_address(state: &DeploymentState) -> Result<String> {
    state
        .gcp_resources
        .address
        .as_ref()
        .and_then(|address| address.observed_attributes.get("address"))
        .cloned()
        .ok_or_else(|| EngineError::Backend("static address receipt is incomplete".into()))
}

async fn revalidate_all<B: DeploymentBackend>(backend: &B, state: &DeploymentState) -> Result<()> {
    for resource in all_resources(&state.gcp_resources) {
        backend.revalidate_project(&state.project_identity).await?;
        backend
            .revalidate_resource(&state.project_identity, resource)
            .await?;
    }
    Ok(())
}

fn all_resources(resources: &GcpResources) -> impl Iterator<Item = &ResourceRef> {
    [
        resources.network.as_ref(),
        resources.subnet.as_ref(),
        resources.web_firewall.as_ref(),
        resources.turn_firewall.as_ref(),
        resources.ssh_firewall.as_ref(),
        resources.address.as_ref(),
        resources.boot_disk.as_ref(),
        resources.instance.as_ref(),
        resources.dns_record.as_ref(),
    ]
    .into_iter()
    .flatten()
}

fn resource_for_effect<'a>(
    resources: &'a GcpResources,
    effect: &PlannedEffect,
) -> Option<&'a ResourceRef> {
    match effect.resource_kind {
        ResourceKind::Network => resources.network.as_ref(),
        ResourceKind::Subnet => resources.subnet.as_ref(),
        ResourceKind::Address => resources.address.as_ref(),
        ResourceKind::Instance => resources.instance.as_ref(),
        ResourceKind::Disk => resources.boot_disk.as_ref(),
        ResourceKind::DnsRecord => resources.dns_record.as_ref(),
        ResourceKind::Firewall if effect.resource_name.ends_with("-web") => {
            resources.web_firewall.as_ref()
        }
        ResourceKind::Firewall if effect.resource_name.ends_with("-turn") => {
            resources.turn_firewall.as_ref()
        }
        ResourceKind::Firewall => resources.ssh_firewall.as_ref(),
    }
}

fn apply_receipt(
    resources: &mut GcpResources,
    effect: &PendingEffect,
    receipt: EffectReceipt,
) -> Result<()> {
    let target = match effect.resource_kind {
        ResourceKind::Network => &mut resources.network,
        ResourceKind::Subnet => &mut resources.subnet,
        ResourceKind::Address => &mut resources.address,
        ResourceKind::Instance => &mut resources.instance,
        ResourceKind::Disk => &mut resources.boot_disk,
        ResourceKind::DnsRecord => &mut resources.dns_record,
        ResourceKind::Firewall if effect.resource_name.ends_with("-web") => {
            &mut resources.web_firewall
        }
        ResourceKind::Firewall if effect.resource_name.ends_with("-turn") => {
            &mut resources.turn_firewall
        }
        ResourceKind::Firewall => &mut resources.ssh_firewall,
    };
    match (effect.action, receipt) {
        (EffectAction::Delete, EffectReceipt::Deleted) => *target = None,
        (EffectAction::Create | EffectAction::Update, EffectReceipt::Present(receipt)) => {
            *target = Some(receipt);
        }
        _ => {
            return Err(EngineError::Backend(
                "effect receipt does not match action".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        state: Mutex<Option<DeploymentState>>,
        plan: Mutex<Option<DeploymentPlan>>,
        events: Arc<Mutex<Vec<String>>>,
        writes: Mutex<Vec<DeploymentState>>,
    }

    impl MemoryStore {
        fn with_events(events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                state: Mutex::new(None),
                plan: Mutex::new(None),
                events,
                writes: Mutex::new(Vec::new()),
            }
        }

        fn with_state(events: Arc<Mutex<Vec<String>>>, state: DeploymentState) -> Self {
            Self {
                state: Mutex::new(Some(state)),
                plan: Mutex::new(None),
                events,
                writes: Mutex::new(Vec::new()),
            }
        }
    }

    impl DeploymentStore for MemoryStore {
        fn read(&self) -> Result<Option<DeploymentState>> {
            Ok(self.state.lock().expect("state lock").clone())
        }

        fn write(&self, state: &DeploymentState) -> Result<()> {
            state.validate()?;
            let event = match &state.pending_effect {
                Some(effect) if effect.operation.is_none() => {
                    format!("persist-start:{}", effect.resource_name)
                }
                Some(effect) => format!("persist-operation:{}", effect.resource_name),
                None => "persist-clear".to_owned(),
            };
            self.events.lock().expect("events lock").push(event);
            self.writes.lock().expect("writes lock").push(state.clone());
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(())
        }

        fn read_plan(&self) -> Result<Option<DeploymentPlan>> {
            Ok(self.plan.lock().expect("plan lock").clone())
        }

        fn write_plan(&self, plan: &DeploymentPlan) -> Result<()> {
            self.events
                .lock()
                .expect("events lock")
                .push("persist-plan".into());
            *self.plan.lock().expect("plan lock") = Some(plan.clone());
            Ok(())
        }
    }

    struct FakeBackend {
        events: Arc<Mutex<Vec<String>>>,
        dns_ready: bool,
        already_absent: BTreeSet<String>,
        missing_during_revalidation: BTreeSet<String>,
        replacement: BTreeSet<String>,
        fail_start: BTreeSet<String>,
        fail_poll_once: Mutex<BTreeSet<String>>,
    }

    impl FakeBackend {
        fn new(events: Arc<Mutex<Vec<String>>>, dns_ready: bool) -> Self {
            Self {
                events,
                dns_ready,
                already_absent: BTreeSet::new(),
                missing_during_revalidation: BTreeSet::new(),
                replacement: BTreeSet::new(),
                fail_start: BTreeSet::new(),
                fail_poll_once: Mutex::new(BTreeSet::new()),
            }
        }

        fn event(&self, event: impl Into<String>) {
            self.events.lock().expect("events lock").push(event.into());
        }
    }

    #[async_trait]
    impl DeploymentBackend for FakeBackend {
        async fn observe(&self, _config: &DeploymentConfig) -> Result<PlanObservations> {
            self.event("observe");
            Ok(observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }))
        }

        async fn revalidate_project(&self, _identity: &ProjectIdentity) -> Result<()> {
            self.event("revalidate-project");
            Ok(())
        }

        async fn start_effect(
            &self,
            state: &DeploymentState,
            effect: &PendingEffect,
            _source_image: Option<&SourceImageIdentity>,
        ) -> Result<EffectStart> {
            self.event(format!("start:{}", effect.resource_name));
            if self.fail_start.contains(&effect.resource_name) {
                return Err(EngineError::Backend(
                    "injected infrastructure failure".into(),
                ));
            }
            if effect.action == EffectAction::Delete
                && self.already_absent.contains(&effect.resource_name)
            {
                return Ok(EffectStart::AlreadySatisfied(EffectReceipt::Deleted));
            }
            let numeric_id = numeric(&effect.resource_name);
            let operation_url = match effect.resource_kind {
                ResourceKind::Network | ResourceKind::Firewall => format!(
                    "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/global/operations/{numeric_id}"
                ),
                ResourceKind::Subnet | ResourceKind::Address => {
                    format!(
                        "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/regions/{}/operations/{numeric_id}",
                        effect.location
                    )
                }
                ResourceKind::Disk | ResourceKind::Instance => {
                    format!(
                        "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/zones/{}/operations/{numeric_id}",
                        effect.location
                    )
                }
                ResourceKind::DnsRecord => format!(
                    "https://dns.googleapis.com/dns/v1/projects/dirextalk-prod/managedZones/{}/changes/{numeric_id}",
                    effect.expected_attributes.get("zone_name").expect("zone"),
                ),
            };
            Ok(EffectStart::Started(OperationRef {
                request_id: effect.effect_id,
                project_number: state.project_identity.project_number,
                location: effect.location.clone(),
                name: numeric_id.to_string(),
                numeric_id,
                self_link: deployer_core::OperationUri::parse(operation_url)?,
            }))
        }

        async fn poll_effect(
            &self,
            state: &DeploymentState,
            effect: &PendingEffect,
            _source_image: Option<&SourceImageIdentity>,
        ) -> Result<EffectReceipt> {
            self.event(format!("poll:{}", effect.resource_name));
            if self
                .fail_poll_once
                .lock()
                .expect("poll failure lock")
                .remove(&effect.resource_name)
            {
                return Err(EngineError::Backend(
                    "injected interrupted operation".into(),
                ));
            }
            if effect.action == EffectAction::Delete {
                return Ok(EffectReceipt::Deleted);
            }
            Ok(EffectReceipt::Present(ResourceRef {
                resource_kind: effect.resource_kind,
                name: effect.resource_name.clone(),
                project_number: state.project_identity.project_number,
                location: effect.location.clone(),
                numeric_id: numeric(&effect.resource_name),
                self_link: format!(
                    "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/global/resources/{}",
                    effect.resource_name
                ),
                deployment_uuid: effect.deployment_uuid,
                observed_attributes: fake_observed_attributes(effect),
            }))
        }

        async fn revalidate_resource(
            &self,
            _identity: &ProjectIdentity,
            resource: &ResourceRef,
        ) -> Result<()> {
            self.event(format!("revalidate-resource:{}", resource.numeric_id));
            if self.missing_during_revalidation.contains(&resource.name) {
                return Err(EngineError::Backend(
                    "recorded GCP resource is absent".into(),
                ));
            }
            if self.replacement.contains(&resource.name) {
                return Err(EngineError::Backend(
                    "same-name resource has a different immutable identity".into(),
                ));
            }
            Ok(())
        }

        async fn revalidate_effect(
            &self,
            _identity: &ProjectIdentity,
            effect: &PendingEffect,
            receipt: &EffectReceipt,
        ) -> Result<()> {
            match (effect.action, receipt) {
                (EffectAction::Delete, EffectReceipt::Deleted)
                | (EffectAction::Create | EffectAction::Update, EffectReceipt::Present(_)) => {}
                _ => return Err(EngineError::Backend("bad fake receipt".into())),
            }
            self.event(format!("postcondition:{}", effect.resource_name));
            Ok(())
        }

        async fn external_dns_ready(&self, _domain: &str, _address: &str) -> Result<bool> {
            self.event("dns-proof");
            Ok(self.dns_ready)
        }

        async fn install_host(
            &self,
            _config: &DeploymentConfig,
            state: &DeploymentState,
        ) -> Result<(SshHostIdentity, HostReceipt)> {
            self.event("install-host");
            Ok((
                SshHostIdentity {
                    address: "8.8.8.8".parse().expect("address"),
                    algorithm: deployer_core::SshHostKeyAlgorithm::Ed25519,
                    fingerprint_sha256: deployer_core::SshSha256Fingerprint::parse(format!(
                        "SHA256:{}",
                        "a".repeat(64)
                    ))?,
                },
                HostReceipt {
                    deployment_uuid: state.deployment_uuid,
                    release_tag: state
                        .release_identity
                        .as_ref()
                        .expect("release")
                        .release_tag
                        .clone(),
                    host_installer_sha256: state
                        .release_identity
                        .as_ref()
                        .expect("release")
                        .host_installer_linux_amd64_sha256
                        .clone(),
                    runtime_bundle_sha256: state
                        .release_identity
                        .as_ref()
                        .expect("release")
                        .runtime_bundle_linux_amd64_sha256
                        .clone(),
                    installed_at_unix_ms: 1,
                    receipt_signature: "d".repeat(64),
                },
            ))
        }

        async fn complete_product(
            &self,
            _config: &DeploymentConfig,
            _state: &DeploymentState,
        ) -> Result<SecretString> {
            self.event("complete-product");
            Ok(SecretString::from("12345678"))
        }

        async fn install_connect(
            &self,
            _config: &DeploymentConfig,
            _state: &DeploymentState,
        ) -> Result<LocalWiringStatus> {
            self.event("install-connect");
            Ok(LocalWiringStatus {
                requested: true,
                installed: true,
                service_active: true,
                last_checked_unix_ms: Some(1),
            })
        }

        async fn uninstall_connect(&self, _state: &DeploymentState) -> Result<LocalWiringStatus> {
            self.event("uninstall-connect");
            Ok(LocalWiringStatus::default())
        }

        async fn verify_product(
            &self,
            _config: &DeploymentConfig,
            _state: &DeploymentState,
        ) -> Result<()> {
            self.event("verify-product");
            Ok(())
        }
    }

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
        .expect("config")
    }

    fn observations(dns: PlanDnsObservation) -> PlanObservations {
        PlanObservations {
            project_identity: ProjectIdentity {
                project_id: "dirextalk-prod".into(),
                project_number: 42,
                oauth_principal: deployer_core::GoogleSubject::parse("operator-123")
                    .expect("subject"),
            },
            observed_dns: dns,
            boot_image: deployer_gcp::ImageIdentity {
                project_id: "ubuntu-os-cloud".into(),
                family: "ubuntu-2404-lts-amd64".into(),
                name: "ubuntu-2404-noble-amd64-v20260801".into(),
                numeric_id: "123456789".into(),
                self_link: "https://compute.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20260801".into(),
                status: "READY".into(),
                architecture: "X86_64".into(),
            },
            release: release_identity(),
            pricing: pricing_quote(),
        }
    }

    fn release_identity() -> ExactReleaseIdentity {
        let sha = |character: char| {
            deployer_core::Sha256Digest::parse(character.to_string().repeat(64)).unwrap()
        };
        let revision = |character: char| {
            deployer_core::SourceRevision::parse(character.to_string().repeat(40)).unwrap()
        };
        ExactReleaseIdentity {
            release_tag: deployer_core::ReleaseTag::parse("v0.1.0").unwrap(),
            release_manifest_sha256: sha('1'),
            release_manifest_source_revision: revision('2'),
            host_installer_linux_amd64_sha256: sha('3'),
            runtime_bundle_linux_amd64_sha256: sha('4'),
            signed_runtime_manifest_linux_amd64_sha256: sha('5'),
            runtime_manifest_signing_key: deployer_core::SigningKeyIdentity::parse("6".repeat(64))
                .unwrap(),
            message_server: deployer_core::LinuxAmd64ApplicationIdentity {
                version: deployer_core::ReleaseTag::parse("v0.1.0").unwrap(),
                source_revision: revision('7'),
                image_sha256: sha('8'),
            },
            agent: deployer_core::LinuxAmd64ApplicationIdentity {
                version: deployer_core::ReleaseTag::parse("v0.1.0").unwrap(),
                source_revision: revision('9'),
                image_sha256: sha('a'),
            },
            updater: deployer_core::LinuxAmd64UpdaterIdentity {
                version: deployer_core::ReleaseTag::parse("v0.1.0").unwrap(),
                source_revision: revision('b'),
                asset_sha256: sha('c'),
            },
        }
    }

    fn pricing_quote() -> PricingQuote {
        let mut line = deployer_core::PricingLine {
            sku_id: "SKU-VM".into(),
            tier_start_base_units: 0,
            usage_unit: "h".into(),
            base_unit: "s".into(),
            base_unit_conversion: deployer_core::RationalQuantity {
                numerator: 3_600,
                denominator: 1,
            },
            usage_quantity: deployer_core::RationalQuantity {
                numerator: 730,
                denominator: 1,
            },
            unit_price_nanos: 100_000_000,
            subtotal_microusd: 1,
        };
        line.subtotal_microusd = line.conservative_subtotal_microusd().unwrap();
        PricingQuote {
            currency: deployer_core::PricingCurrency::Usd,
            total_microusd: line.subtotal_microusd,
            lines: BTreeSet::from([line]),
            unpriced_exclusions: BTreeSet::from([
                deployer_core::UnpricedExclusion::NetworkEgress,
                deployer_core::UnpricedExclusion::CloudDnsQueries,
            ]),
        }
    }

    fn numeric(value: &str) -> u64 {
        let bytes = Sha256::digest(value.as_bytes());
        u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes")).max(1)
    }

    fn find_after(events: &[String], needle: &str, after: usize) -> usize {
        events
            .iter()
            .enumerate()
            .skip(after)
            .find_map(|(index, value)| (value == needle).then_some(index))
            .unwrap_or_else(|| panic!("missing event {needle}: {events:?}"))
    }

    #[tokio::test]
    async fn apply_journals_every_effect_before_start_and_operation_before_poll() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let backend = FakeBackend::new(Arc::clone(&events), true);
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }),
            None,
        )
        .expect("plan");
        let digest = plan.digest().expect("digest");
        let completion = Orchestrator::new(&backend, &store)
            .apply(&plan, &digest)
            .await
            .expect("apply");
        assert!(matches!(completion, Completion::Complete { .. }));

        let events = events.lock().expect("events lock");
        let mut cursor = 0;
        for effect in &plan.effects {
            let persisted = find_after(
                &events,
                &format!("persist-start:{}", effect.resource_name),
                cursor,
            );
            let started = find_after(
                &events,
                &format!("start:{}", effect.resource_name),
                persisted + 1,
            );
            let operation = find_after(
                &events,
                &format!("persist-operation:{}", effect.resource_name),
                started + 1,
            );
            let polled = find_after(
                &events,
                &format!("poll:{}", effect.resource_name),
                operation + 1,
            );
            cursor = find_after(&events, "persist-clear", polled + 1) + 1;
        }
        assert!(events.iter().any(|event| event == "install-host"));
        assert!(events.iter().any(|event| event == "verify-product"));
        assert_eq!(
            store.read().expect("state").expect("present").phase,
            DeploymentPhase::Complete
        );
    }

    #[tokio::test]
    async fn pending_only_reconciles_one_effect_and_stops_before_the_next() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let config = config();
        let plan = build_plan(
            &config,
            observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }),
            None,
        )
        .expect("plan");
        let first = plan.effects.first().expect("first effect");
        let second = plan.effects.get(1).expect("second effect");
        let digest = plan.digest().expect("digest");
        let mut interrupted_backend = FakeBackend::new(Arc::clone(&events), true);
        interrupted_backend
            .fail_start
            .insert(first.resource_name.clone());
        assert!(
            Orchestrator::new(&interrupted_backend, &store)
                .apply(&plan, &digest)
                .await
                .is_err()
        );
        let interrupted = store.read().expect("state").expect("present");
        assert_eq!(
            interrupted
                .pending_effect
                .as_ref()
                .expect("pending")
                .resource_name,
            first.resource_name
        );
        assert!(
            interrupted
                .pending_effect
                .as_ref()
                .expect("pending")
                .operation
                .is_none()
        );

        let recovery_backend = FakeBackend::new(Arc::clone(&events), true);
        Orchestrator::new(&recovery_backend, &store)
            .resume_pending_only(&config)
            .await
            .expect("pending-only recovery");

        let recovered = store.read().expect("state").expect("present");
        assert!(recovered.pending_effect.is_none());
        assert!(resource_for_effect(&recovered.gcp_resources, first).is_some());
        assert!(resource_for_effect(&recovered.gcp_resources, second).is_none());
        assert_eq!(recovered.phase, DeploymentPhase::Applying);
        {
            let events = events.lock().expect("events");
            assert_eq!(
                events
                    .iter()
                    .filter(|event| *event == &format!("start:{}", first.resource_name))
                    .count(),
                2
            );
            assert!(
                !events
                    .iter()
                    .any(|event| event == &format!("start:{}", second.resource_name))
            );
            assert!(!events.iter().any(|event| event == "install-host"));
        }
        assert!(matches!(
            Orchestrator::new(&recovery_backend, &store)
                .resume_pending_only(&config)
                .await,
            Err(EngineError::WaitingUser(_))
        ));
    }

    #[tokio::test]
    async fn approval_mismatch_has_no_effect_or_state_write() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let backend = FakeBackend::new(Arc::clone(&events), true);
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }),
            None,
        )
        .expect("plan");
        let wrong: PlanDigest = format!("sha256:{}", "0".repeat(64))
            .parse()
            .expect("digest");
        assert!(matches!(
            Orchestrator::new(&backend, &store)
                .apply(&plan, &wrong)
                .await,
            Err(EngineError::ApprovalMismatch)
        ));
        assert!(events.lock().expect("events").is_empty());
        assert!(store.read().expect("state").is_none());
    }

    #[tokio::test]
    async fn external_dns_is_expected_waiting_user_after_address_is_recorded() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let backend = FakeBackend::new(events, false);
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }),
            None,
        )
        .expect("plan");
        let digest = plan.digest().expect("digest");
        assert_eq!(
            Orchestrator::new(&backend, &store)
                .apply(&plan, &digest)
                .await
                .expect("waiting"),
            Completion::WaitingExternalDns {
                name: "talk.example.com".into(),
                value: "8.8.8.8".into()
            }
        );
        let state = store.read().expect("state").expect("present");
        assert_eq!(state.phase, DeploymentPhase::WaitingUser);
        assert!(state.host_receipt.is_none());
    }

    #[tokio::test]
    async fn managed_dns_is_derived_from_the_approved_intent_without_a_second_plan() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let backend = FakeBackend::new(Arc::clone(&events), true);
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::CloudDns {
                zone_name: "example-com".into(),
                zone_numeric_id: 77,
                current_ipv4: BTreeSet::new(),
                change: None,
            }),
            None,
        )
        .expect("plan");
        let digest = plan.digest().expect("digest");

        assert!(matches!(
            Orchestrator::new(&backend, &store)
                .apply(&plan, &digest)
                .await
                .expect("complete"),
            Completion::Complete { .. }
        ));

        let state = store.read().expect("state").expect("present");
        assert_eq!(state.phase, DeploymentPhase::Complete);
        let dns = state.gcp_resources.dns_record.expect("managed DNS receipt");
        assert_eq!(dns.name, "talk.example.com");
        assert_eq!(dns.observed_attributes["value"], "8.8.8.8");
        let events = events.lock().expect("events");
        let dns_start = events
            .iter()
            .position(|event| event == "start:talk.example.com")
            .expect("DNS start");
        let host_install = events
            .iter()
            .position(|event| event == "install-host")
            .expect("host install");
        assert!(dns_start < host_install);
    }

    #[tokio::test]
    async fn interrupted_derived_dns_operation_resumes_from_the_initial_plan() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::CloudDns {
                zone_name: "example-com".into(),
                zone_numeric_id: 77,
                current_ipv4: BTreeSet::new(),
                change: None,
            }),
            None,
        )
        .expect("plan");
        let digest = plan.digest().expect("digest");
        let first_backend = FakeBackend::new(Arc::clone(&events), true);
        first_backend
            .fail_poll_once
            .lock()
            .expect("poll failure lock")
            .insert("talk.example.com".into());

        assert!(matches!(
            Orchestrator::new(&first_backend, &store)
                .apply(&plan, &digest)
                .await,
            Err(EngineError::Backend(message)) if message.contains("interrupted operation")
        ));
        let interrupted = store.read().expect("state").expect("present");
        assert_eq!(
            interrupted
                .pending_effect
                .as_ref()
                .expect("pending DNS")
                .resource_name,
            "talk.example.com"
        );

        let resumed_backend = FakeBackend::new(events, true);
        assert!(matches!(
            Orchestrator::new(&resumed_backend, &store)
                .resume(&config())
                .await
                .expect("resumed"),
            Completion::Complete { .. }
        ));
        let complete = store.read().expect("state").expect("present");
        assert_eq!(complete.phase, DeploymentPhase::Complete);
        assert!(complete.gcp_resources.dns_record.is_some());
    }

    #[tokio::test]
    async fn pending_only_reconciles_a_journaled_derived_dns_operation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = MemoryStore::with_events(Arc::clone(&events));
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::CloudDns {
                zone_name: "example-com".into(),
                zone_numeric_id: 77,
                current_ipv4: BTreeSet::new(),
                change: None,
            }),
            None,
        )
        .expect("plan");
        let digest = plan.digest().expect("digest");
        let first_backend = FakeBackend::new(Arc::clone(&events), true);
        first_backend
            .fail_poll_once
            .lock()
            .expect("poll failure lock")
            .insert("talk.example.com".into());
        assert!(
            Orchestrator::new(&first_backend, &store)
                .apply(&plan, &digest)
                .await
                .is_err()
        );

        let recovery_backend = FakeBackend::new(Arc::clone(&events), true);
        Orchestrator::new(&recovery_backend, &store)
            .resume_pending_only(&config())
            .await
            .expect("derived DNS pending-only recovery");

        let recovered = store.read().expect("state").expect("present");
        assert!(recovered.pending_effect.is_none());
        assert!(recovered.gcp_resources.dns_record.is_some());
        assert!(recovered.host_receipt.is_none());
        assert_eq!(recovered.phase, DeploymentPhase::Applying);
        assert!(
            !events
                .lock()
                .expect("events")
                .iter()
                .any(|event| event == "install-host")
        );
    }

    fn resource_from_plan(plan: &DeploymentPlan, kind: ResourceKind) -> ResourceRef {
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.resource_kind == kind)
            .expect("planned resource");
        ResourceRef {
            resource_kind: kind,
            name: effect.resource_name.clone(),
            project_number: plan.project_identity.project_number,
            location: effect.location.clone(),
            numeric_id: numeric(&effect.resource_name),
            self_link: format!(
                "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/global/resources/{}",
                effect.resource_name
            ),
            deployment_uuid: plan.deployment_uuid,
            observed_attributes: fake_observed_attributes(&PendingEffect {
                effect_id: Uuid::new_v4(),
                deployment_uuid: plan.deployment_uuid,
                project_number: plan.project_identity.project_number,
                action: effect.action,
                resource_kind: effect.resource_kind,
                resource_name: effect.resource_name.clone(),
                location: effect.location.clone(),
                expected_attributes: effect.expected_attributes.clone(),
                target: effect.target.clone(),
                operation: None,
            }),
        }
    }

    fn fake_observed_attributes(effect: &PendingEffect) -> BTreeMap<String, String> {
        let base = effect
            .resource_name
            .rsplit_once('-')
            .map_or(effect.resource_name.as_str(), |(base, _)| base);
        let network = format!("projects/dirextalk-prod/global/networks/{base}-net");
        match effect.resource_kind {
            ResourceKind::Network => BTreeMap::from([
                ("auto_create_subnetworks".into(), "false".into()),
                ("routing_mode".into(), "GLOBAL".into()),
            ]),
            ResourceKind::Subnet => BTreeMap::from([
                (
                    "ip_cidr_range".into(),
                    effect
                        .expected_attributes
                        .get("cidr")
                        .cloned()
                        .unwrap_or_else(|| "10.42.0.0/24".into()),
                ),
                ("network".into(), network),
            ]),
            ResourceKind::Firewall => BTreeMap::from([
                (
                    "allowed".into(),
                    r#"[{"ports":["443"],"protocol":"tcp"}]"#.into(),
                ),
                ("network".into(), network),
                ("source_ranges".into(), r#"["0.0.0.0/0"]"#.into()),
                ("target_tags".into(), format!(r#"["{base}"]"#)),
            ]),
            ResourceKind::Address => BTreeMap::from([("address".into(), "8.8.8.8".into())]),
            ResourceKind::Disk => BTreeMap::from([
                (
                    "size_gb".into(),
                    effect
                        .expected_attributes
                        .get("size_gib")
                        .cloned()
                        .unwrap_or_else(|| "50".into()),
                ),
                (
                    "source_image".into(),
                    "ubuntu-2404-noble-amd64-v20260801".into(),
                ),
                ("source_image_id".into(), "123456789".into()),
                ("type".into(), "pd-balanced".into()),
            ]),
            ResourceKind::Instance => {
                let region = effect
                    .location
                    .rsplit_once('-')
                    .map_or("us-central1", |(region, _)| region);
                BTreeMap::from([
                    ("access_config_count".into(), "1".into()),
                    (
                        "boot_disk".into(),
                        format!(
                            "projects/dirextalk-prod/zones/{}/disks/{base}-boot",
                            effect.location
                        ),
                    ),
                    ("boot_disk_auto_delete".into(), "false".into()),
                    ("can_ip_forward".into(), "false".into()),
                    ("deletion_protection".into(), "false".into()),
                    ("disk_count".into(), "1".into()),
                    (
                        "machine_type".into(),
                        effect
                            .expected_attributes
                            .get("machine_type")
                            .cloned()
                            .unwrap_or_else(|| "e2-custom-2-4096".into()),
                    ),
                    ("metadata_key_count".into(), "1".into()),
                    ("nat_ip".into(), "8.8.8.8".into()),
                    ("network_interface_count".into(), "1".into()),
                    ("network_tags".into(), format!(r#"["{base}"]"#)),
                    ("service_account_count".into(), "0".into()),
                    ("ssh_keys_sha256".into(), "a".repeat(64)),
                    (
                        "subnetwork".into(),
                        format!(
                            "projects/dirextalk-prod/regions/{region}/subnetworks/{base}-subnet"
                        ),
                    ),
                ])
            }
            ResourceKind::DnsRecord => effect.expected_attributes.clone(),
        }
    }

    fn destroy_state(include_address: bool) -> DeploymentState {
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }),
            None,
        )
        .expect("plan");
        let network = resource_from_plan(&plan, ResourceKind::Network);
        let address = include_address.then(|| resource_from_plan(&plan, ResourceKind::Address));
        let ssh_host_identity = include_address.then(|| SshHostIdentity {
            address: "8.8.8.8".parse().expect("address"),
            algorithm: deployer_core::SshHostKeyAlgorithm::Ed25519,
            fingerprint_sha256: deployer_core::SshSha256Fingerprint::parse(format!(
                "SHA256:{}",
                "a".repeat(64)
            ))
            .expect("fingerprint"),
        });
        let host_receipt = include_address.then(|| HostReceipt {
            deployment_uuid: plan.deployment_uuid,
            release_tag: plan.release.release_tag.clone(),
            host_installer_sha256: plan.release.host_installer_linux_amd64_sha256.clone(),
            runtime_bundle_sha256: plan.release.runtime_bundle_linux_amd64_sha256.clone(),
            installed_at_unix_ms: 1,
            receipt_signature: "d".repeat(64),
        });
        DeploymentState {
            schema_version: 1,
            deployment_uuid: plan.deployment_uuid,
            service_id: service_id("production", 42).expect("service id"),
            project_identity: plan.project_identity.clone(),
            approved_plan_digest: Some(plan.digest().expect("digest")),
            phase: DeploymentPhase::Failed,
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(plan.release),
            gcp_resources: GcpResources {
                network: Some(network),
                address,
                ..GcpResources::default()
            },
            ssh_host_identity,
            host_receipt,
            local_wiring: if include_address {
                LocalWiringStatus {
                    requested: true,
                    installed: true,
                    service_active: true,
                    last_checked_unix_ms: Some(1),
                }
            } else {
                LocalWiringStatus::default()
            },
            integrity_digest: String::new(),
        }
    }

    #[tokio::test]
    async fn destroy_absent_target_advances_with_deleted_receipt_atomically() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let state = destroy_state(false);
        let target_name = state
            .gcp_resources
            .network
            .as_ref()
            .expect("network")
            .name
            .clone();
        let plan = DestroyPlan::from_state(&state, None).expect("destroy plan");
        let digest = plan.digest().expect("digest");
        let store = MemoryStore::with_state(Arc::clone(&events), state);
        let mut backend = FakeBackend::new(events, true);
        backend.already_absent.insert(target_name);

        Orchestrator::new(&backend, &store)
            .destroy(&plan, &digest)
            .await
            .expect("destroy already-absent target");

        let writes = store.writes.lock().expect("writes lock");
        let advanced = writes
            .iter()
            .find(|state| {
                state
                    .active_destroy
                    .as_ref()
                    .is_some_and(|active| active.next_target_index == 1)
            })
            .expect("atomic receipt and cursor write");
        assert!(advanced.gcp_resources.network.is_none());
        assert!(advanced.pending_effect.is_none());
        let final_state = store.read().expect("state").expect("present");
        assert_eq!(final_state.phase, DeploymentPhase::Destroyed);
        assert!(final_state.active_destroy.is_none());
    }

    #[tokio::test]
    async fn destroy_same_name_replacement_fails_closed_before_delete() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let state = destroy_state(false);
        let target_name = state
            .gcp_resources
            .network
            .as_ref()
            .expect("network")
            .name
            .clone();
        let plan = DestroyPlan::from_state(&state, None).expect("destroy plan");
        let digest = plan.digest().expect("digest");
        let store = MemoryStore::with_state(Arc::clone(&events), state);
        let mut backend = FakeBackend::new(events, true);
        backend.replacement.insert(target_name);

        assert!(matches!(
            Orchestrator::new(&backend, &store)
                .destroy(&plan, &digest)
                .await,
            Err(EngineError::Backend(message)) if message.contains("immutable identity")
        ));
        let persisted = store.read().expect("state").expect("present");
        assert_eq!(persisted.phase, DeploymentPhase::Destroying);
        assert_eq!(
            persisted
                .active_destroy
                .as_ref()
                .expect("active destroy")
                .next_target_index,
            0
        );
        assert!(persisted.pending_effect.is_none());
        assert!(persisted.gcp_resources.network.is_some());
    }

    #[tokio::test]
    async fn destroy_infrastructure_failure_keeps_cursor_before_target() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let state = destroy_state(false);
        let target_name = state
            .gcp_resources
            .network
            .as_ref()
            .expect("network")
            .name
            .clone();
        let plan = DestroyPlan::from_state(&state, None).expect("destroy plan");
        let digest = plan.digest().expect("digest");
        let store = MemoryStore::with_state(Arc::clone(&events), state);
        let mut backend = FakeBackend::new(events, true);
        backend.fail_start.insert(target_name.clone());

        assert!(matches!(
            Orchestrator::new(&backend, &store)
                .destroy(&plan, &digest)
                .await,
            Err(EngineError::Backend(message)) if message.contains("infrastructure failure")
        ));
        let persisted = store.read().expect("state").expect("present");
        assert_eq!(
            persisted
                .active_destroy
                .as_ref()
                .expect("active destroy")
                .next_target_index,
            0
        );
        assert_eq!(
            persisted
                .pending_effect
                .as_ref()
                .expect("pending effect")
                .resource_name,
            target_name
        );
        assert!(persisted.gcp_resources.network.is_some());
    }

    #[tokio::test]
    async fn destroy_rerun_resumes_frozen_digest_from_cursor_and_operation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let state = destroy_state(true);
        let network_name = state
            .gcp_resources
            .network
            .as_ref()
            .expect("network")
            .name
            .clone();
        let plan = DestroyPlan::from_state(&state, None).expect("destroy plan");
        let digest = plan.digest().expect("digest");
        let store = MemoryStore::with_state(Arc::clone(&events), state);
        let first_backend = FakeBackend::new(Arc::clone(&events), true);
        first_backend
            .fail_poll_once
            .lock()
            .expect("poll failure lock")
            .insert(network_name.clone());

        assert!(matches!(
            Orchestrator::new(&first_backend, &store)
                .destroy(&plan, &digest)
                .await,
            Err(EngineError::Backend(message)) if message.contains("interrupted operation")
        ));
        let interrupted = store.read().expect("state").expect("present");
        assert_eq!(
            interrupted
                .active_destroy
                .as_ref()
                .expect("active destroy")
                .next_target_index,
            1
        );
        assert!(interrupted.gcp_resources.address.is_none());
        assert!(interrupted.gcp_resources.network.is_some());
        assert!(
            interrupted
                .pending_effect
                .as_ref()
                .expect("pending effect")
                .operation
                .is_some()
        );

        let mut resumed_backend = FakeBackend::new(Arc::clone(&events), true);
        resumed_backend
            .missing_during_revalidation
            .insert(network_name.clone());
        let resumed = Orchestrator::new(&resumed_backend, &store)
            .plan_destroy(None)
            .await
            .expect("frozen resume plan");
        assert_eq!(resumed, plan);
        assert_eq!(resumed.digest().expect("resumed digest"), digest);
        Orchestrator::new(&resumed_backend, &store)
            .destroy(&resumed, &digest)
            .await
            .expect("resume destroy");

        let events = events.lock().expect("events lock");
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == &format!("start:{network_name}"))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == &format!("poll:{network_name}"))
                .count(),
            2
        );
        let final_state = store.read().expect("state").expect("present");
        assert_eq!(final_state.phase, DeploymentPhase::Destroyed);
        assert!(final_state.active_destroy.is_none());
        assert!(final_state.pending_effect.is_none());
        assert!(final_state.ssh_host_identity.is_none());
        assert!(final_state.host_receipt.is_none());
        assert_eq!(final_state.local_wiring, LocalWiringStatus::default());
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == "uninstall-connect")
                .count(),
            1
        );
        assert!(final_state.gcp_resources.network.is_none());
    }

    #[test]
    fn destroy_retains_disk_unless_exact_numeric_id_is_requested() {
        let plan = build_plan(
            &config(),
            observations(PlanDnsObservation::External {
                current_ipv4: BTreeSet::new(),
            }),
            None,
        )
        .expect("plan");
        let disk_effect = plan
            .effects
            .iter()
            .find(|effect| effect.resource_kind == ResourceKind::Disk)
            .expect("disk");
        let disk = ResourceRef {
            resource_kind: ResourceKind::Disk,
            name: disk_effect.resource_name.clone(),
            project_number: 42,
            location: disk_effect.location.clone(),
            numeric_id: 777,
            self_link: format!(
                "https://compute.googleapis.com/compute/v1/projects/dirextalk-prod/zones/{}/disks/{}",
                disk_effect.location, disk_effect.resource_name
            ),
            deployment_uuid: plan.deployment_uuid,
            observed_attributes: fake_observed_attributes(&PendingEffect {
                effect_id: Uuid::new_v4(),
                deployment_uuid: plan.deployment_uuid,
                project_number: plan.project_identity.project_number,
                action: EffectAction::Create,
                resource_kind: ResourceKind::Disk,
                resource_name: disk_effect.resource_name.clone(),
                location: disk_effect.location.clone(),
                expected_attributes: disk_effect.expected_attributes.clone(),
                target: None,
                operation: None,
            }),
        };
        let state = DeploymentState {
            schema_version: 1,
            deployment_uuid: plan.deployment_uuid,
            service_id: service_id("production", 42).expect("service id"),
            project_identity: plan.project_identity.clone(),
            approved_plan_digest: Some(plan.digest().expect("digest")),
            phase: DeploymentPhase::Failed,
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(plan.release),
            gcp_resources: GcpResources {
                boot_disk: Some(disk),
                ..GcpResources::default()
            },
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus::default(),
            integrity_digest: String::new(),
        };
        let retain = DestroyPlan::from_state(&state, None).expect("retain plan");
        assert!(matches!(
            retain.boot_disk,
            deployer_core::BootDiskDisposition::Retain { .. }
        ));
        assert!(
            !retain
                .targets
                .iter()
                .any(|target| { target.resource.resource_kind == ResourceKind::Disk })
        );

        let purge = DestroyPlan::from_state(&state, Some(777)).expect("purge plan");
        assert!(matches!(
            purge.boot_disk,
            deployer_core::BootDiskDisposition::Purge { .. }
        ));
        assert!(
            purge
                .targets
                .iter()
                .any(|target| { target.resource.resource_kind == ResourceKind::Disk })
        );
        assert_ne!(
            retain.digest().expect("retain digest"),
            purge.digest().expect("purge digest")
        );
        assert!(DestroyPlan::from_state(&state, Some(778)).is_err());
    }
}
