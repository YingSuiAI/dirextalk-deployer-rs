use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use deployer_core::{PlanDigest, ProjectIdentity, canonical_json, canonical_plan_digest};
use deployer_gcp::{
    GCP_V01_REQUIRED_SERVICES, GcpProjectIdentity, GcpServiceUsage, ServiceUsageOperationState,
};
use serde::{Deserialize, Serialize};

use crate::engine::{EngineError, Result};
use crate::live_product::restrictive_replace;

const MAX_OPERATION_POLLS: usize = 180;
const MAX_SERVICE_READBACKS: usize = 60;
#[cfg(not(test))]
const POLL_DELAY: Duration = Duration::from_secs(2);
#[cfg(test)]
const POLL_DELAY: Duration = Duration::ZERO;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectServicePlan {
    pub schema_version: u32,
    pub project_identity: ProjectIdentity,
    pub services: Vec<String>,
}

impl ProjectServicePlan {
    fn digest(&self) -> Result<PlanDigest> {
        canonical_plan_digest(self).map_err(EngineError::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectPreparationOutcome {
    ApprovalRequired {
        plan_id: PlanDigest,
        project_id: String,
        project_number: u64,
        required_services: Vec<String>,
        enable_services: Vec<String>,
    },
    Complete {
        project_id: String,
        project_number: u64,
        enabled_services: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectPreparationState {
    schema_version: u32,
    plan: ProjectServicePlan,
    approved_plan_digest: PlanDigest,
    completed_services: BTreeSet<String>,
    pending_effect: Option<ServicePendingEffect>,
    complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicePendingEffect {
    service: String,
    operation_name: Option<String>,
}

/// Plans or resumes fixed prerequisite service enablement for one immutable
/// project identity.
///
/// # Errors
///
/// Returns an error when local state, approval, project identity, a Service
/// Usage operation, or its enabled-state postcondition is invalid.
pub async fn prepare_project_services<C>(
    home: &Path,
    client: &C,
    identity: &ProjectIdentity,
    approval: Option<&PlanDigest>,
) -> Result<ProjectPreparationOutcome>
where
    C: GcpProjectIdentity + GcpServiceUsage,
{
    let store = ProjectPreparationStore::open(home, identity.project_number)?;
    let existing = store.read()?;
    let plan = match existing.as_ref() {
        Some(state) if !state.complete => {
            validate_state_identity(state, identity)?;
            state.plan.clone()
        }
        _ => discover_plan(client, identity).await?,
    };
    let plan_id = plan.digest()?;
    if plan.services.is_empty() {
        return Ok(ProjectPreparationOutcome::Complete {
            project_id: identity.project_id.clone(),
            project_number: identity.project_number,
            enabled_services: Vec::new(),
        });
    }
    let Some(approved) = approval else {
        return Ok(ProjectPreparationOutcome::ApprovalRequired {
            plan_id,
            project_id: identity.project_id.clone(),
            project_number: identity.project_number,
            required_services: GCP_V01_REQUIRED_SERVICES.map(str::to_owned).into(),
            enable_services: plan.services,
        });
    };
    if approved != &plan_id {
        return Err(EngineError::ApprovalMismatch);
    }

    let mut state = match existing {
        Some(state) if !state.complete => {
            if state.approved_plan_digest != plan_id {
                return Err(EngineError::StatePlanMismatch);
            }
            state
        }
        _ => {
            let state = ProjectPreparationState {
                schema_version: 1,
                plan,
                approved_plan_digest: plan_id,
                completed_services: BTreeSet::new(),
                pending_effect: None,
                complete: false,
            };
            store.write(&state)?;
            state
        }
    };

    let services = state.plan.services.clone();
    for service in services {
        if state.completed_services.contains(&service) {
            continue;
        }
        enable_one_service(client, identity, &store, &mut state, &service).await?;
    }
    for service in GCP_V01_REQUIRED_SERVICES {
        if !service_enabled(client, identity, service).await? {
            return Err(EngineError::Backend(format!(
                "required service {service} is not enabled at final readback"
            )));
        }
    }
    state.complete = true;
    state.pending_effect = None;
    store.write(&state)?;
    Ok(ProjectPreparationOutcome::Complete {
        project_id: identity.project_id.clone(),
        project_number: identity.project_number,
        enabled_services: state.completed_services.into_iter().collect(),
    })
}

async fn discover_plan<C>(client: &C, identity: &ProjectIdentity) -> Result<ProjectServicePlan>
where
    C: GcpProjectIdentity + GcpServiceUsage,
{
    revalidate_project(client, identity).await?;
    let mut services = Vec::new();
    for service in GCP_V01_REQUIRED_SERVICES {
        if !service_enabled(client, identity, service).await? {
            services.push(service.to_owned());
        }
    }
    Ok(ProjectServicePlan {
        schema_version: 1,
        project_identity: identity.clone(),
        services,
    })
}

async fn enable_one_service<C>(
    client: &C,
    identity: &ProjectIdentity,
    store: &ProjectPreparationStore,
    state: &mut ProjectPreparationState,
    service: &str,
) -> Result<()>
where
    C: GcpProjectIdentity + GcpServiceUsage,
{
    if state
        .pending_effect
        .as_ref()
        .is_some_and(|pending| pending.service != service)
    {
        return Err(EngineError::State(
            "project preparation pending effect does not match service order".into(),
        ));
    }
    let resuming = state.pending_effect.is_some();
    if !resuming {
        state.pending_effect = Some(ServicePendingEffect {
            service: service.to_owned(),
            operation_name: None,
        });
        store.write(state)?;
    }

    if service_enabled(client, identity, service).await? {
        finish_service(store, state, service)?;
        return Ok(());
    }

    let mut operation_name = state
        .pending_effect
        .as_ref()
        .and_then(|pending| pending.operation_name.clone());
    if operation_name.is_none()
        && resuming
        && wait_for_service_enabled(client, identity, service).await?
    {
        finish_service(store, state, service)?;
        return Ok(());
    }
    if operation_name.is_none() {
        revalidate_project(client, identity).await?;
        let operation = client
            .enable_service(&identity.project_number.to_string(), service)
            .await
            .map_err(gcp_error)?;
        operation_name = Some(operation.name.clone());
        state
            .pending_effect
            .as_mut()
            .ok_or_else(|| EngineError::State("project preparation effect disappeared".into()))?
            .operation_name
            .clone_from(&operation_name);
        store.write(state)?;
        match operation.state {
            ServiceUsageOperationState::Succeeded => {}
            ServiceUsageOperationState::Failed { code, message: _ } => {
                return Err(service_usage_failure("enable", code));
            }
            ServiceUsageOperationState::Pending => {
                poll_operation(client, identity, operation_name.as_deref().expect("set")).await?;
            }
        }
    } else {
        poll_operation(
            client,
            identity,
            operation_name.as_deref().expect("present"),
        )
        .await?;
    }

    if !wait_for_service_enabled(client, identity, service).await? {
        return Err(EngineError::Backend(format!(
            "enabled service {service} did not reach ENABLED state"
        )));
    }
    finish_service(store, state, service)
}

async fn poll_operation<C>(
    client: &C,
    identity: &ProjectIdentity,
    operation_name: &str,
) -> Result<()>
where
    C: GcpProjectIdentity + GcpServiceUsage,
{
    for _ in 0..MAX_OPERATION_POLLS {
        revalidate_project(client, identity).await?;
        let operation = client
            .service_operation(&identity.project_number.to_string(), operation_name)
            .await
            .map_err(gcp_error)?;
        if operation.name != operation_name {
            return Err(EngineError::Backend(
                "Service Usage operation identity changed".into(),
            ));
        }
        match operation.state {
            ServiceUsageOperationState::Pending => {
                tokio::time::sleep(POLL_DELAY).await;
            }
            ServiceUsageOperationState::Succeeded => return Ok(()),
            ServiceUsageOperationState::Failed { code, message: _ } => {
                return Err(service_usage_failure("operation", code));
            }
        }
    }
    Err(EngineError::Backend(
        "Service Usage operation polling timed out".into(),
    ))
}

async fn wait_for_service_enabled<C>(
    client: &C,
    identity: &ProjectIdentity,
    service: &str,
) -> Result<bool>
where
    C: GcpProjectIdentity + GcpServiceUsage,
{
    for _ in 0..MAX_SERVICE_READBACKS {
        if service_enabled(client, identity, service).await? {
            return Ok(true);
        }
        tokio::time::sleep(POLL_DELAY).await;
    }
    Ok(false)
}

async fn service_enabled<C>(client: &C, identity: &ProjectIdentity, service: &str) -> Result<bool>
where
    C: GcpProjectIdentity + GcpServiceUsage,
{
    revalidate_project(client, identity).await?;
    let status = client
        .service_status(&identity.project_number.to_string(), service)
        .await
        .map_err(gcp_error)?;
    let expected_name = format!("projects/{}/services/{service}", identity.project_number);
    if status.name != expected_name {
        return Err(EngineError::Backend(
            "Service Usage resource identity changed".into(),
        ));
    }
    Ok(status.enabled)
}

async fn revalidate_project<C>(client: &C, identity: &ProjectIdentity) -> Result<()>
where
    C: GcpProjectIdentity,
{
    client
        .revalidate_project_identity(&identity.project_id, &identity.project_number.to_string())
        .await
        .map_err(gcp_error)
}

fn finish_service(
    store: &ProjectPreparationStore,
    state: &mut ProjectPreparationState,
    service: &str,
) -> Result<()> {
    state.completed_services.insert(service.to_owned());
    state.pending_effect = None;
    store.write(state)
}

fn validate_state_identity(
    state: &ProjectPreparationState,
    identity: &ProjectIdentity,
) -> Result<()> {
    if state.schema_version != 1
        || state.plan.schema_version != 1
        || &state.plan.project_identity != identity
        || state.plan.services.is_empty()
        || state.plan.services
            != GCP_V01_REQUIRED_SERVICES
                .into_iter()
                .filter(|service| state.plan.services.iter().any(|value| value == service))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        || state
            .completed_services
            .iter()
            .any(|service| !state.plan.services.contains(service))
    {
        return Err(EngineError::State(
            "project preparation state identity is invalid".into(),
        ));
    }
    if state.pending_effect.as_ref().is_some_and(|pending| {
        !state.plan.services.contains(&pending.service)
            || state.completed_services.contains(&pending.service)
    }) || (state.complete
        && (state.pending_effect.is_some()
            || state.completed_services.len() != state.plan.services.len()))
    {
        return Err(EngineError::State(
            "project preparation pending effect is invalid".into(),
        ));
    }
    if state.plan.digest()? != state.approved_plan_digest {
        return Err(EngineError::State(
            "project preparation state plan digest is invalid".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn gcp_error(error: deployer_gcp::GcpError) -> EngineError {
    EngineError::Backend(error.to_string())
}

fn service_usage_failure(action: &str, code: i32) -> EngineError {
    EngineError::Backend(format!(
        "Service Usage {action} failed with Google error code {code}"
    ))
}

struct ProjectPreparationStore {
    state_path: PathBuf,
    _lock: File,
}

impl ProjectPreparationStore {
    fn open(home: &Path, project_number: u64) -> Result<Self> {
        let root = prepare_project_directory(home, project_number)?;
        let lock_path = root.join("prepare.lock");
        if fs::symlink_metadata(&lock_path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(EngineError::State("project state lock is unsafe".into()));
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|_| EngineError::State("project state lock could not be opened".into()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            lock.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| EngineError::State("project state lock is not private".into()))?;
            let metadata = lock.metadata().map_err(|_| {
                EngineError::State("project state lock could not be inspected".into())
            })?;
            if !metadata.is_file() || metadata.uid() != current_uid() || metadata.nlink() != 1 {
                return Err(EngineError::State(
                    "project state lock identity is unsafe".into(),
                ));
            }
        }
        lock.try_lock().map_err(|_| {
            EngineError::State("another project preparation is already running".into())
        })?;
        Ok(Self {
            state_path: root.join("service-preparation.json"),
            _lock: lock,
        })
    }

    fn read(&self) -> Result<Option<ProjectPreparationState>> {
        match crate::live_product::read_restrictive_optional(&self.state_path)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| EngineError::State("project preparation state is invalid".into())),
            None => Ok(None),
        }
    }

    fn write(&self, state: &ProjectPreparationState) -> Result<()> {
        validate_state_identity(state, &state.plan.project_identity)?;
        let bytes = canonical_json(state)?;
        restrictive_replace(&self.state_path, &bytes)
    }
}

fn prepare_project_directory(home: &Path, project_number: u64) -> Result<PathBuf> {
    if !home.is_absolute() || project_number == 0 {
        return Err(EngineError::State(
            "project state identity is invalid".into(),
        ));
    }
    require_real_directory(home, false, false)?;
    let dirextalk = home.join(".dirextalk");
    require_real_directory(&dirextalk, true, false)?;
    let projects = dirextalk.join("projects");
    require_real_directory(&projects, true, true)?;
    let root = projects.join(project_number.to_string());
    require_real_directory(&root, true, true)?;
    Ok(root)
}

fn require_real_directory(path: &Path, create: bool, private: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(EngineError::State(
                "project state directory is unsafe".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| {
                EngineError::State("project state directory could not be created".into())
            })?;
        }
        Err(_) => {
            return Err(EngineError::State(
                "project state directory could not be inspected".into(),
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            EngineError::State("project state directory could not be inspected".into())
        })?;
        if metadata.uid() != current_uid() {
            return Err(EngineError::State(
                "project state directory has the wrong owner".into(),
            ));
        }
        if private {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| EngineError::State("project state directory is not private".into()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    tempfile::tempfile()
        .ok()
        .and_then(|file| file.metadata().ok())
        .map_or(u32::MAX, |metadata| metadata.uid())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use deployer_core::GoogleSubject;
    use deployer_gcp::{
        GcpError, Result as GcpResult, ServiceStatus, ServiceUsageOperation,
        ServiceUsageOperationState,
    };

    use super::*;

    struct FakeProject {
        project_id: String,
        project_number: String,
        enabled: Mutex<BTreeSet<String>>,
        operations: Mutex<BTreeMap<String, String>>,
        enable_calls: AtomicUsize,
        fail_next_poll: AtomicBool,
        operation_failure: Mutex<Option<(i32, String)>>,
        pending_state_path: Option<PathBuf>,
        pending_seen: AtomicBool,
    }

    impl FakeProject {
        fn with_missing(missing: &[&str], pending_state_path: Option<PathBuf>) -> Self {
            let enabled = GCP_V01_REQUIRED_SERVICES
                .into_iter()
                .filter(|service| !missing.contains(service))
                .map(str::to_owned)
                .collect();
            Self {
                project_id: "dirextalk-prod".into(),
                project_number: "42".into(),
                enabled: Mutex::new(enabled),
                operations: Mutex::new(BTreeMap::new()),
                enable_calls: AtomicUsize::new(0),
                fail_next_poll: AtomicBool::new(false),
                operation_failure: Mutex::new(None),
                pending_state_path,
                pending_seen: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl GcpProjectIdentity for FakeProject {
        async fn revalidate_project_identity(
            &self,
            project_id: &str,
            project_number: &str,
        ) -> GcpResult<()> {
            if project_id == self.project_id && project_number == self.project_number {
                Ok(())
            } else {
                Err(GcpError::Contract("project identity changed".into()))
            }
        }
    }

    #[async_trait]
    impl GcpServiceUsage for FakeProject {
        async fn service_status(
            &self,
            project_number: &str,
            service: &str,
        ) -> GcpResult<ServiceStatus> {
            if project_number != self.project_number {
                return Err(GcpError::Contract("project number changed".into()));
            }
            Ok(ServiceStatus {
                name: format!("projects/{project_number}/services/{service}"),
                enabled: self.enabled.lock().expect("enabled").contains(service),
            })
        }

        async fn enable_service(
            &self,
            project_number: &str,
            service: &str,
        ) -> GcpResult<ServiceUsageOperation> {
            if project_number != self.project_number {
                return Err(GcpError::Contract("project number changed".into()));
            }
            self.enable_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(path) = &self.pending_state_path {
                let state: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).map_err(|_| {
                        GcpError::Infrastructure("pending effect was not persisted".into())
                    })?)?;
                let pending = &state["pending_effect"];
                if pending["service"] == service && pending["operation_name"].is_null() {
                    self.pending_seen.store(true, Ordering::SeqCst);
                }
            }
            let name = format!("operations/enable-{}", service.replace('.', "-"));
            self.operations
                .lock()
                .expect("operations")
                .insert(name.clone(), service.to_owned());
            Ok(ServiceUsageOperation {
                name,
                state: ServiceUsageOperationState::Pending,
            })
        }

        async fn service_operation(
            &self,
            project_number: &str,
            operation_name: &str,
        ) -> GcpResult<ServiceUsageOperation> {
            if project_number != self.project_number {
                return Err(GcpError::Contract("project number changed".into()));
            }
            if self.fail_next_poll.swap(false, Ordering::SeqCst) {
                return Err(GcpError::Infrastructure(
                    "simulated polling interruption".into(),
                ));
            }
            if let Some((code, message)) = self
                .operation_failure
                .lock()
                .expect("operation failure")
                .take()
            {
                return Ok(ServiceUsageOperation {
                    name: operation_name.to_owned(),
                    state: ServiceUsageOperationState::Failed { code, message },
                });
            }
            let service = self
                .operations
                .lock()
                .expect("operations")
                .get(operation_name)
                .cloned()
                .ok_or_else(|| GcpError::Contract("operation identity changed".into()))?;
            self.enabled.lock().expect("enabled").insert(service);
            Ok(ServiceUsageOperation {
                name: operation_name.to_owned(),
                state: ServiceUsageOperationState::Succeeded,
            })
        }
    }

    fn identity(subject: &str) -> ProjectIdentity {
        ProjectIdentity {
            project_id: "dirextalk-prod".into(),
            project_number: 42,
            oauth_principal: GoogleSubject::parse(subject).expect("subject"),
        }
    }

    #[tokio::test]
    async fn dry_plan_is_fixed_identity_bound_and_never_enables() {
        let home = tempfile::tempdir().expect("home");
        let client = FakeProject::with_missing(
            &[
                "serviceusage.googleapis.com",
                "cloudbilling.googleapis.com",
                "dns.googleapis.com",
            ],
            None,
        );
        let outcome = prepare_project_services(home.path(), &client, &identity("subject-a"), None)
            .await
            .expect("plan");
        let ProjectPreparationOutcome::ApprovalRequired {
            plan_id,
            required_services,
            enable_services,
            ..
        } = outcome
        else {
            panic!("approval plan expected");
        };
        assert_eq!(
            required_services,
            GCP_V01_REQUIRED_SERVICES.map(str::to_owned)
        );
        assert_eq!(
            enable_services,
            [
                "serviceusage.googleapis.com",
                "cloudbilling.googleapis.com",
                "dns.googleapis.com",
            ]
        );
        assert_eq!(client.enable_calls.load(Ordering::SeqCst), 0);

        let other_home = tempfile::tempdir().expect("other home");
        let other =
            prepare_project_services(other_home.path(), &client, &identity("subject-b"), None)
                .await
                .expect("other plan");
        let ProjectPreparationOutcome::ApprovalRequired {
            plan_id: other_id, ..
        } = other
        else {
            panic!("approval plan expected");
        };
        assert_ne!(plan_id, other_id);
    }

    #[tokio::test]
    async fn approved_enable_persists_pending_before_mutation() {
        let home = tempfile::tempdir().expect("home");
        let state_path = home
            .path()
            .join(".dirextalk/projects/42/service-preparation.json");
        let client = FakeProject::with_missing(&["dns.googleapis.com"], Some(state_path.clone()));
        let subject = identity("subject-a");
        let ProjectPreparationOutcome::ApprovalRequired { plan_id, .. } =
            prepare_project_services(home.path(), &client, &subject, None)
                .await
                .expect("plan")
        else {
            panic!("plan expected");
        };

        let outcome = prepare_project_services(home.path(), &client, &subject, Some(&plan_id))
            .await
            .expect("apply");
        assert!(matches!(
            outcome,
            ProjectPreparationOutcome::Complete { .. }
        ));
        assert!(client.pending_seen.load(Ordering::SeqCst));
        assert_eq!(client.enable_calls.load(Ordering::SeqCst), 1);
        let state: ProjectPreparationState =
            serde_json::from_slice(&std::fs::read(state_path).expect("state")).expect("decode");
        assert!(state.complete);
        assert!(state.pending_effect.is_none());
    }

    #[tokio::test]
    async fn resume_polls_the_recorded_operation_without_reenabling() {
        let home = tempfile::tempdir().expect("home");
        let client = FakeProject::with_missing(&["compute.googleapis.com"], None);
        let subject = identity("subject-a");
        let ProjectPreparationOutcome::ApprovalRequired { plan_id, .. } =
            prepare_project_services(home.path(), &client, &subject, None)
                .await
                .expect("plan")
        else {
            panic!("plan expected");
        };
        client.fail_next_poll.store(true, Ordering::SeqCst);
        assert!(
            prepare_project_services(home.path(), &client, &subject, Some(&plan_id))
                .await
                .is_err()
        );
        assert_eq!(client.enable_calls.load(Ordering::SeqCst), 1);

        let outcome = prepare_project_services(home.path(), &client, &subject, Some(&plan_id))
            .await
            .expect("resume");
        assert!(matches!(
            outcome,
            ProjectPreparationOutcome::Complete { .. }
        ));
        assert_eq!(client.enable_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unrecorded_operation_window_reconciles_then_retries_exact_idempotent_effect() {
        let home = tempfile::tempdir().expect("home");
        let subject = identity("subject-a");
        let plan = ProjectServicePlan {
            schema_version: 1,
            project_identity: subject.clone(),
            services: vec!["compute.googleapis.com".into()],
        };
        let approved_plan_digest = plan.digest().expect("digest");
        let store = ProjectPreparationStore::open(home.path(), 42).expect("store");
        store
            .write(&ProjectPreparationState {
                schema_version: 1,
                plan,
                approved_plan_digest: approved_plan_digest.clone(),
                completed_services: BTreeSet::new(),
                pending_effect: Some(ServicePendingEffect {
                    service: "compute.googleapis.com".into(),
                    operation_name: None,
                }),
                complete: false,
            })
            .expect("state");
        drop(store);
        let client = FakeProject::with_missing(&["compute.googleapis.com"], None);

        let outcome =
            prepare_project_services(home.path(), &client, &subject, Some(&approved_plan_digest))
                .await
                .expect("recover exact effect");
        assert!(matches!(
            outcome,
            ProjectPreparationOutcome::Complete { .. }
        ));
        assert_eq!(client.enable_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn upstream_operation_messages_are_never_relayed() {
        let home = tempfile::tempdir().expect("home");
        let client = FakeProject::with_missing(&["dns.googleapis.com"], None);
        let subject = identity("subject-a");
        let ProjectPreparationOutcome::ApprovalRequired { plan_id, .. } =
            prepare_project_services(home.path(), &client, &subject, None)
                .await
                .expect("plan")
        else {
            panic!("plan expected");
        };
        *client.operation_failure.lock().expect("operation failure") =
            Some((7, "operator@example.test secret detail".into()));

        let error = prepare_project_services(home.path(), &client, &subject, Some(&plan_id))
            .await
            .expect_err("operation failure")
            .to_string();
        assert!(error.contains('7'));
        assert!(!error.contains("operator@example.test"));
        assert!(!error.contains("secret detail"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_project_state_parent_is_rejected() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().expect("home");
        let target = tempfile::tempdir().expect("target");
        std::fs::create_dir(home.path().join(".dirextalk")).expect("dirextalk");
        symlink(target.path(), home.path().join(".dirextalk/projects")).expect("symlink");

        assert!(ProjectPreparationStore::open(home.path(), 42).is_err());
        assert!(!target.path().join("42").exists());
    }
}
