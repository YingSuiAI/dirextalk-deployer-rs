#![allow(clippy::missing_errors_doc)]

use std::path::Path;

use async_trait::async_trait;
use deployer_core::{
    DeploymentConfig, DeploymentPlan, DeploymentState, PlanDigest, ProgressEvent,
    ProgressOperation, ProgressStatus,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::{
    AuthCommand, Cli, ConnectCommand, DeployCommand, ProjectCommand, TopLevelCommand,
};
use crate::engine::{
    Completion, DeploymentBackend, DeploymentStore, EngineError, Orchestrator,
    Result as EngineResult, build_plan,
};
use crate::output::CommandEnvelope;
use crate::project_prepare::ProjectPreparationOutcome;

#[derive(Clone, Debug, Serialize)]
pub struct SafeResult {
    pub code: String,
    pub message: String,
    pub data: Value,
}

impl SafeResult {
    pub fn new(code: impl Into<String>, message: impl Into<String>, data: Value) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            data,
        }
    }
}

#[async_trait]
pub trait ControlPlane: DeploymentBackend {
    async fn auth_login(&self) -> EngineResult<SafeResult>;
    async fn auth_status(&self) -> EngineResult<SafeResult>;
    async fn auth_logout(&self) -> EngineResult<SafeResult>;
    async fn project_list(&self) -> EngineResult<SafeResult>;
    async fn project_inspect(&self, project_id: &str) -> EngineResult<SafeResult>;
    async fn project_prepare(
        &self,
        project_id: &str,
        approval: Option<&PlanDigest>,
    ) -> EngineResult<ProjectPreparationOutcome>;
    async fn connect_status(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> EngineResult<SafeResult>;
    async fn connect_doctor(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> EngineResult<SafeResult>;
}

pub trait StoreFactory {
    type Store: DeploymentStore;

    fn open_for_plan(&self, plan: &DeploymentPlan) -> EngineResult<Self::Store>;
    fn open_for_config(&self, config: &DeploymentConfig) -> EngineResult<Self::Store>;
    fn find_for_config(&self, config: &DeploymentConfig) -> EngineResult<Option<Self::Store>>;
}

pub struct Application<'a, C, F> {
    control: &'a C,
    stores: &'a F,
}

impl<'a, C: ControlPlane, F: StoreFactory> Application<'a, C, F> {
    pub const fn new(control: &'a C, stores: &'a F) -> Self {
        Self { control, stores }
    }

    pub async fn execute(&self, cli: &Cli) -> CommandEnvelope {
        let operation = progress_operation(cli);
        let started = progress_event(operation, ProgressStatus::Started);
        let mut envelope = match self.try_execute(cli).await {
            Ok(envelope) => envelope,
            Err(error) => failure_envelope(command_name(cli), &error),
        };
        let status = match envelope.status {
            crate::output::OutcomeStatus::Success => ProgressStatus::Succeeded,
            crate::output::OutcomeStatus::WaitingUser => ProgressStatus::WaitingUser,
            crate::output::OutcomeStatus::Failed => ProgressStatus::Failed,
        };
        envelope.progress = vec![started, progress_event(operation, status)];
        envelope
    }

    #[allow(clippy::too_many_lines)]
    async fn try_execute(&self, cli: &Cli) -> EngineResult<CommandEnvelope> {
        match &cli.command {
            TopLevelCommand::Auth(auth) => {
                let result = match auth.command {
                    AuthCommand::Login => self.control.auth_login().await?,
                    AuthCommand::Status => self.control.auth_status().await?,
                    AuthCommand::Logout => self.control.auth_logout().await?,
                };
                success(command_name(cli), result)
            }
            TopLevelCommand::Project(project) => match &project.command {
                ProjectCommand::List => {
                    success(command_name(cli), self.control.project_list().await?)
                }
                ProjectCommand::Inspect(args) => success(
                    command_name(cli),
                    self.control.project_inspect(&args.project).await?,
                ),
                ProjectCommand::Prepare(args) => {
                    let approval = args
                        .approve
                        .as_deref()
                        .map(str::parse::<PlanDigest>)
                        .transpose()?;
                    project_prepare_envelope(
                        command_name(cli),
                        self.control
                            .project_prepare(&args.project, approval.as_ref())
                            .await?,
                    )
                }
            },
            TopLevelCommand::Deploy(deploy) => match &deploy.command {
                DeployCommand::Plan(args) => {
                    let config = load_config(&args.config)?;
                    let observations = self.control.observe(&config).await?;
                    let existing = self.stores.find_for_config(&config)?;
                    let existing_state = existing
                        .as_ref()
                        .map(DeploymentStore::read)
                        .transpose()?
                        .flatten();
                    let plan = build_plan(&config, observations, existing_state.as_ref())?;
                    let digest = plan.digest()?;
                    let public_plan = privacy_minimized_output(&plan)?;
                    CommandEnvelope::success(
                        command_name(cli),
                        "DEPLOY_PLAN_READY",
                        "Deployment plan is ready for explicit approval.",
                    )
                    .with_data(json!({ "plan_id": digest, "plan": public_plan }))
                    .map_err(|_| EngineError::Backend("plan output could not be encoded".into()))
                }
                DeployCommand::Apply(args) => {
                    let config = load_config(&args.config)?;
                    let observations = self.control.observe(&config).await?;
                    let existing = self.stores.find_for_config(&config)?;
                    let existing_state = existing
                        .as_ref()
                        .map(DeploymentStore::read)
                        .transpose()?
                        .flatten();
                    let plan = build_plan(&config, observations, existing_state.as_ref())?;
                    let approved: PlanDigest = args.approve.parse()?;
                    let store = match existing {
                        Some(store) => store,
                        None => self.stores.open_for_plan(&plan)?,
                    };
                    completion_envelope(
                        command_name(cli),
                        Orchestrator::new(self.control, &store)
                            .apply(&plan, &approved)
                            .await?,
                    )
                }
                DeployCommand::Resume(args) => {
                    let config = load_config(&args.config)?;
                    let store = self.stores.open_for_config(&config)?;
                    completion_envelope(
                        command_name(cli),
                        Orchestrator::new(self.control, &store)
                            .resume(&config)
                            .await?,
                    )
                }
                DeployCommand::Status(args) => {
                    let config = load_config(&args.config)?;
                    let store = self.stores.open_for_config(&config)?;
                    let state = Orchestrator::new(self.control, &store).status()?;
                    let public_state = privacy_minimized_output(&state)?;
                    CommandEnvelope::success(
                        command_name(cli),
                        "DEPLOY_STATUS",
                        "Deployment status loaded from authenticated local state.",
                    )
                    .with_data(json!({ "state": public_state }))
                    .map_err(|_| EngineError::Backend("status output could not be encoded".into()))
                }
                DeployCommand::Verify(args) => {
                    let config = load_config(&args.config)?;
                    let store = self.stores.open_for_config(&config)?;
                    Orchestrator::new(self.control, &store)
                        .verify(&config)
                        .await?;
                    Ok(CommandEnvelope::success(
                        command_name(cli),
                        "DEPLOY_VERIFIED",
                        "Product, local bridge, and read-only MCP verification passed.",
                    ))
                }
                DeployCommand::Destroy(args) => {
                    let config = load_config(&args.config)?;
                    let store = self.stores.open_for_config(&config)?;
                    let orchestrator = Orchestrator::new(self.control, &store);
                    let plan = orchestrator.plan_destroy(args.purge_disk).await?;
                    let digest = plan.digest()?;
                    let Some(approval) = &args.approve else {
                        let public_plan = privacy_minimized_output(&plan)?;
                        return CommandEnvelope::waiting(
                            command_name(cli),
                            "DESTROY_APPROVAL_REQUIRED",
                            "Review the exact destroy plan and approve its SHA-256 digest.",
                        )
                        .with_data(json!({ "plan_id": digest, "plan": public_plan }))
                        .map_err(|_| {
                            EngineError::Backend("destroy plan output could not be encoded".into())
                        });
                    };
                    let approved: PlanDigest = approval.parse()?;
                    orchestrator.destroy(&plan, &approved).await?;
                    Ok(CommandEnvelope::success(
                        command_name(cli),
                        "DESTROY_COMPLETE",
                        if args.purge_disk.is_some() {
                            "Deployment resources and the exact approved boot disk were removed."
                        } else {
                            "Deployment resources were removed; the boot disk was retained."
                        },
                    ))
                }
            },
            TopLevelCommand::Connect(connect) => {
                let args = match &connect.command {
                    ConnectCommand::Install(args)
                    | ConnectCommand::Status(args)
                    | ConnectCommand::Doctor(args) => args,
                };
                let config = load_config(&args.config)?;
                let store = self.stores.open_for_config(&config)?;
                let orchestrator = Orchestrator::new(self.control, &store);
                match connect.command {
                    ConnectCommand::Install(_) => {
                        let status = orchestrator.install_connect(&config).await?;
                        CommandEnvelope::success(
                            command_name(cli),
                            "CONNECT_INSTALLED",
                            "Service-scoped dirextalk-connect is installed and active.",
                        )
                        .with_data(json!({ "connect": status }))
                        .map_err(|_| {
                            EngineError::Backend("connect output could not be encoded".into())
                        })
                    }
                    ConnectCommand::Status(_) => {
                        let state = orchestrator.status()?;
                        success(
                            command_name(cli),
                            self.control.connect_status(&config, &state).await?,
                        )
                    }
                    ConnectCommand::Doctor(_) => {
                        let state = orchestrator.status()?;
                        success(
                            command_name(cli),
                            self.control.connect_doctor(&config, &state).await?,
                        )
                    }
                }
            }
        }
    }
}

fn progress_operation(cli: &Cli) -> ProgressOperation {
    match &cli.command {
        TopLevelCommand::Deploy(deploy) => match deploy.command {
            DeployCommand::Plan(_) => ProgressOperation::Plan,
            DeployCommand::Apply(_) => ProgressOperation::Apply,
            DeployCommand::Resume(_) => ProgressOperation::Resume,
            DeployCommand::Destroy(_) => ProgressOperation::Destroy,
            DeployCommand::Status(_) | DeployCommand::Verify(_) => ProgressOperation::Verify,
        },
        TopLevelCommand::Connect(_) => ProgressOperation::ConnectInstall,
        TopLevelCommand::Auth(_) | TopLevelCommand::Project(_) => ProgressOperation::Verify,
    }
}

fn progress_event(operation: ProgressOperation, status: ProgressStatus) -> ProgressEvent {
    let timestamp_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    ProgressEvent {
        timestamp_unix_ms,
        operation,
        status,
        resource_kind: None,
    }
}

fn load_config(path: &Path) -> EngineResult<DeploymentConfig> {
    let text = std::fs::read_to_string(path).map_err(|_| EngineError::ConfigRead)?;
    DeploymentConfig::parse(&text).map_err(EngineError::from)
}

fn success(command: &str, result: SafeResult) -> EngineResult<CommandEnvelope> {
    CommandEnvelope::success(command, result.code, result.message)
        .with_data(result.data)
        .map_err(|_| EngineError::Backend("command output could not be encoded".into()))
}

fn project_prepare_envelope(
    command: &str,
    outcome: ProjectPreparationOutcome,
) -> EngineResult<CommandEnvelope> {
    match outcome {
        ProjectPreparationOutcome::ApprovalRequired {
            plan_id,
            project_id,
            project_number,
            required_services,
            enable_services,
        } => CommandEnvelope::waiting(
            command,
            "PROJECT_PREPARE_APPROVAL_REQUIRED",
            "Review the exact missing-service plan and approve its SHA-256 digest.",
        )
        .with_data(json!({
            "plan_id": plan_id,
            "plan": {
                "project_id": project_id,
                "project_number": project_number,
                "required_services": required_services,
                "enable_services": enable_services,
            }
        }))
        .map_err(|_| EngineError::Backend("project plan output could not be encoded".into())),
        ProjectPreparationOutcome::Complete {
            project_id,
            project_number,
            enabled_services,
        } => CommandEnvelope::success(
            command,
            "PROJECT_PREPARED",
            "The fixed Dirextalk GCP service set is enabled and identity-verified.",
        )
        .with_data(json!({
            "project_id": project_id,
            "project_number": project_number,
            "enabled_services": enabled_services,
        }))
        .map_err(|_| EngineError::Backend("project result could not be encoded".into())),
    }
}

fn privacy_minimized_output(value: &impl Serialize) -> EngineResult<Value> {
    let mut value = serde_json::to_value(value)
        .map_err(|_| EngineError::Backend("command output could not be encoded".into()))?;
    remove_oauth_principal(&mut value);
    Ok(value)
}

fn remove_oauth_principal(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.remove("oauth_principal");
            for value in fields.values_mut() {
                remove_oauth_principal(value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(remove_oauth_principal),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn completion_envelope(command: &str, completion: Completion) -> EngineResult<CommandEnvelope> {
    match completion {
        Completion::Complete {
            initialization_code,
        } => Ok(CommandEnvelope::success(
            command,
            "DEPLOY_COMPLETE",
            "Dirextalk deployment and local verification are complete.",
        )
        .with_human_initialization_code(initialization_code)),
        Completion::WaitingExternalDns { name, value } => CommandEnvelope::waiting(
            command,
            "DNS_RECORD_REQUIRED",
            "Create exactly one external DNS A record, then run deploy resume.",
        )
        .with_data(json!({ "record_type": "A", "name": name, "value": value }))
        .map_err(|_| EngineError::Backend("DNS output could not be encoded".into())),
        Completion::WaitingDnsReplan {
            name,
            value,
            current_values,
        } => CommandEnvelope::waiting(
            command,
            "DNS_REPLAN_REQUIRED",
            "The static address is reserved. Review a new exact DNS continuation plan.",
        )
        .with_data(json!({
            "record_type": "A",
            "name": name,
            "current_values": current_values,
            "replacement_value": value,
            "next_command": "deploy plan",
        }))
        .map_err(|_| EngineError::Backend("DNS continuation output could not be encoded".into())),
    }
}

fn failure_envelope(command: &str, error: &EngineError) -> CommandEnvelope {
    if let EngineError::WaitingUser(message) = error {
        return CommandEnvelope::waiting(command, "ACTION_REQUIRED", message);
    }
    let code = match error {
        EngineError::ConfigRead => "CONFIG_READ_FAILED",
        EngineError::Core(_) => "CORE_CONTRACT_FAILED",
        EngineError::ApprovalMismatch => "PLAN_APPROVAL_MISMATCH",
        EngineError::MissingState => "STATE_NOT_FOUND",
        EngineError::StatePlanMismatch => "STATE_PLAN_MISMATCH",
        EngineError::ExistingState => "STATE_ALREADY_EXISTS",
        EngineError::DiskIdentityMismatch => "DISK_IDENTITY_MISMATCH",
        EngineError::Backend(_) => "INFRASTRUCTURE_FAILED",
        EngineError::WaitingUser(_) => unreachable!("handled above"),
        EngineError::State(_) => "STATE_OPERATION_FAILED",
    };
    CommandEnvelope::failed(command, code, error.to_string())
}

#[must_use]
pub fn command_name(cli: &Cli) -> &'static str {
    match &cli.command {
        TopLevelCommand::Auth(auth) => match auth.command {
            AuthCommand::Login => "auth.login",
            AuthCommand::Status => "auth.status",
            AuthCommand::Logout => "auth.logout",
        },
        TopLevelCommand::Project(project) => match project.command {
            ProjectCommand::List => "project.list",
            ProjectCommand::Inspect(_) => "project.inspect",
            ProjectCommand::Prepare(_) => "project.prepare",
        },
        TopLevelCommand::Deploy(deploy) => match deploy.command {
            DeployCommand::Plan(_) => "deploy.plan",
            DeployCommand::Apply(_) => "deploy.apply",
            DeployCommand::Resume(_) => "deploy.resume",
            DeployCommand::Status(_) => "deploy.status",
            DeployCommand::Verify(_) => "deploy.verify",
            DeployCommand::Destroy(_) => "deploy.destroy",
        },
        TopLevelCommand::Connect(connect) => match connect.command {
            ConnectCommand::Install(_) => "connect.install",
            ConnectCommand::Status(_) => "connect.status",
            ConnectCommand::Doctor(_) => "connect.doctor",
        },
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::output::OutcomeStatus;

    #[test]
    fn failures_use_stable_secret_free_envelopes() {
        let cli = Cli::parse_from([
            "dirextalk-deployer",
            "deploy",
            "apply",
            "--config",
            "missing.toml",
            "--approve",
            "sha256:secret-must-not-appear",
        ]);
        let envelope = failure_envelope(command_name(&cli), &EngineError::ConfigRead);
        assert_eq!(envelope.status, OutcomeStatus::Failed);
        assert_eq!(envelope.code, "CONFIG_READ_FAILED");
        assert!(
            !serde_json::to_string(&envelope)
                .expect("JSON")
                .contains("secret")
        );
    }

    #[test]
    fn public_output_recursively_omits_opaque_oauth_subjects() {
        let output = privacy_minimized_output(&json!({
            "project_identity": { "oauth_principal": "opaque-subject", "project_id": "p" },
            "nested": [{ "oauth_principal": "other-subject" }]
        }))
        .expect("redacted output");
        let encoded = serde_json::to_string(&output).expect("JSON");

        assert!(!encoded.contains("oauth_principal"));
        assert!(!encoded.contains("opaque-subject"));
        assert!(!encoded.contains("other-subject"));
    }

    #[test]
    fn project_prepare_plan_is_waiting_and_privacy_minimized() {
        let plan_id =
            deployer_core::canonical_plan_digest(&json!({"plan": "prepare"})).expect("digest");
        let envelope = project_prepare_envelope(
            "project.prepare",
            ProjectPreparationOutcome::ApprovalRequired {
                plan_id,
                project_id: "dirextalk-prod".into(),
                project_number: 42,
                required_services: vec![
                    "serviceusage.googleapis.com".into(),
                    "cloudresourcemanager.googleapis.com".into(),
                    "cloudbilling.googleapis.com".into(),
                    "compute.googleapis.com".into(),
                    "dns.googleapis.com".into(),
                ],
                enable_services: vec!["compute.googleapis.com".into()],
            },
        )
        .expect("envelope");
        assert_eq!(envelope.status, OutcomeStatus::WaitingUser);
        assert_eq!(
            envelope.data["plan"]["required_services"],
            json!([
                "serviceusage.googleapis.com",
                "cloudresourcemanager.googleapis.com",
                "cloudbilling.googleapis.com",
                "compute.googleapis.com",
                "dns.googleapis.com",
            ])
        );
        assert_eq!(
            envelope.data["plan"]["enable_services"],
            json!(["compute.googleapis.com"])
        );
        let encoded = serde_json::to_string(&envelope).expect("JSON");
        assert!(encoded.contains("compute.googleapis.com"));
        assert!(encoded.contains("serviceusage.googleapis.com"));
        assert_eq!(encoded.matches("serviceusage.googleapis.com").count(), 1);
        assert!(!encoded.contains("oauth_principal"));
    }
}
