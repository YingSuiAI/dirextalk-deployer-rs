#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use deployer_connect::{
    AgentCapability, AgentSelection, ConnectAgent, ConnectConfig, DaemonController, DaemonState,
    HostRuntime, HttpMcpTransport, LocalPlatform, MatrixSession as ConnectMatrixSession, McpClient,
    McpInjection, ProcessExecutor, ProjectConfig, ReadOnlySmoke, Redactor, ReleaseChannel,
    ReleaseResolver, ServicePaths, render_matrix_config, resolve_capability, write_connect_config,
};
use deployer_core::{
    CanonicalDeploymentSpec, DeploymentConfig, DeploymentState, EffectAction, GoogleSubject,
    LocalWiringStatus, OperationRef, OperationUri, PendingEffect, PricingCurrency, PricingLine,
    PricingQuote, ProjectIdentity, RationalQuantity, ResourceKind as CoreResourceKind, ResourceRef,
    SourceImageIdentity, SshHostKeyAlgorithm, SshSha256Fingerprint, UnpricedExclusion,
};
use deployer_gcp::{
    AddressSpec, CredentialStore, DiskSpec, DnsChange, DnsPreflightMode, DnsPreflightStatus,
    DnsRecordSet, EncryptedFileStore, FirewallAllowance, FirewallSpec, GcpDiscovery,
    GcpImageDiscovery, GcpLifecycle, GoogleCloudClient, GoogleInstalledApp, ImageIdentity,
    InstalledAppConfig, InstanceSpec, KeyringStore, NetworkSpec, Operation, OperationScope,
    OperationState, PassphraseProvider, Preflight, RequiredQuota, RequiredService,
    ResourceIdentity, ResourceKind as GcpResourceKind, ResourceSpecRef, SecretStore,
    SubnetworkSpec, SystemBrowser, longest_matching_zone,
    require_resource_absent as require_gcp_resource_absent, validate_resource_identity,
    validate_resource_properties,
};
use deployer_host::{
    DigestHex, HostTarget, InstallRequest, SignedReceipt, canonical_json as host_canonical_json,
    verify_receipt,
};
use deployer_transport::{
    DnsName, DnsProofRequest, FixedRemoteCommand, HostKeyAlgorithm, HostKeyPin, HostTransport,
    RemoteArtifact, Sha256Digest, SshClient,
};
use directories::BaseDirs;
use rand::RngCore as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};
use zeroize::Zeroizing;

use crate::application::{ControlPlane, SafeResult};
use crate::engine::{
    DeploymentBackend, EffectReceipt, EffectStart, EngineError, PlanObservations, Result,
};
use crate::host_mcp::{OpenClawRegistry, ProcessHostMcpExecutor};
use crate::live_product::{
    HttpProductApi, StoredProductSecrets, read_restrictive, restrictive_replace,
};
use crate::product::{ProductBootstrap, initialize_product};
use crate::release::{GithubReleaseCatalog, ReleaseCatalog};

#[derive(Deserialize)]
struct TurnCredentials {
    uris: Vec<String>,
    username: SecretString,
    password: SecretString,
    ttl: u64,
}

pub struct LiveControlPlane {
    oauth: GoogleInstalledApp,
    releases: Arc<dyn ReleaseCatalog>,
}

impl LiveControlPlane {
    pub fn new() -> Result<Self> {
        let config = InstalledAppConfig::from_environment().map_err(gcp_error)?;
        let base = BaseDirs::new()
            .ok_or_else(|| EngineError::State("current user home is unavailable".into()))?;
        let service = "dirextalk-deployer-gcp-v1";
        let secrets: Arc<dyn SecretStore> = Arc::new(CredentialStore::new(
            KeyringStore::new(service),
            EncryptedFileStore::with_passphrase_provider(
                base.home_dir().join(".dirextalk/credentials"),
                service,
                Arc::new(InteractivePassphraseProvider),
            ),
        ));
        Ok(Self {
            oauth: GoogleInstalledApp::new(config, secrets, Arc::new(SystemBrowser)),
            releases: Arc::new(GithubReleaseCatalog::new()?),
        })
    }

    async fn token(&self) -> Result<deployer_gcp::OAuthToken> {
        self.oauth
            .refresh()
            .await
            .map_err(gcp_error)?
            .ok_or_else(|| EngineError::WaitingUser("run `dirextalk-deployer auth login`".into()))
    }

    async fn discovery(&self) -> Result<(deployer_gcp::OAuthToken, GoogleCloudClient)> {
        let token = self.token().await?;
        let client = GoogleCloudClient::new("unbound", "0", token.access_token.clone())
            .await
            .map_err(gcp_error)?;
        Ok((token, client))
    }

    async fn client_for(&self, identity: &ProjectIdentity) -> Result<GoogleCloudClient> {
        let token = self.token().await?;
        if token.principal != identity.oauth_principal.as_str() {
            return Err(EngineError::Backend("OAuth principal changed".into()));
        }
        GoogleCloudClient::new(
            &identity.project_id,
            identity.project_number.to_string(),
            token.access_token,
        )
        .await
        .map_err(gcp_error)
    }

    async fn verified_transport(&self, state: &DeploymentState) -> Result<SshClient> {
        self.revalidate_project(&state.project_identity).await?;
        for resource in [
            state.gcp_resources.instance.as_ref(),
            state.gcp_resources.address.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            self.revalidate_resource(&state.project_identity, resource)
                .await?;
        }
        let identity = state
            .ssh_host_identity
            .as_ref()
            .ok_or_else(|| EngineError::Backend("SSH host identity is not recorded".into()))?;
        let address = identity.address;
        if address != public_ipv4(state)? {
            return Err(EngineError::Backend(
                "recorded SSH address differs from the static address receipt".into(),
            ));
        }
        let pin = HostKeyPin {
            algorithm: transport_host_key_algorithm(identity.algorithm),
            sha256: Sha256Digest::parse(
                identity
                    .fingerprint_sha256
                    .as_str()
                    .strip_prefix("SHA256:")
                    .ok_or_else(|| {
                        EngineError::Backend("recorded SSH fingerprint is invalid".into())
                    })?,
            )
            .map_err(transport_error)?,
        };
        let private_key = ssh_private_key_path(state)?;
        let _validated_private_key = Zeroizing::new(read_restrictive(&private_key)?);
        SshClient::connect_with_private_key(
            SocketAddr::new(IpAddr::V4(address), 22),
            "dirextalk",
            &private_key,
            &pin,
        )
        .map_err(transport_error)
    }

    async fn install_transport(
        &self,
        state: &DeploymentState,
        address: Ipv4Addr,
    ) -> Result<(deployer_core::SshHostIdentity, HostKeyPin, SshClient)> {
        let pin_path = service_paths(state)?.root.join("ssh-host-identity.json");
        let mut identity = match (
            state.ssh_host_identity.clone(),
            pin_path
                .exists()
                .then(|| read_restrictive(&pin_path))
                .transpose()?,
        ) {
            (Some(state_identity), Some(bytes)) => {
                let persisted: deployer_core::SshHostIdentity = serde_json::from_slice(&bytes)
                    .map_err(|_| EngineError::State("persisted SSH host pin is invalid".into()))?;
                if persisted != state_identity {
                    return Err(EngineError::State(
                        "persisted SSH host pins disagree".into(),
                    ));
                }
                Some(state_identity)
            }
            (Some(state_identity), None) => {
                restrictive_replace(
                    &pin_path,
                    &serde_json::to_vec(&state_identity).map_err(|_| {
                        EngineError::State("SSH host pin could not be encoded".into())
                    })?,
                )?;
                Some(state_identity)
            }
            (None, Some(bytes)) => Some(
                serde_json::from_slice(&bytes)
                    .map_err(|_| EngineError::State("persisted SSH host pin is invalid".into()))?,
            ),
            (None, None) => None,
        };
        let socket = SocketAddr::new(IpAddr::V4(address), 22);
        let private_key = ssh_private_key_path(state)?;
        let _validated_private_key = Zeroizing::new(read_restrictive(&private_key)?);
        for attempt in 0..60 {
            self.revalidate_host_targets(state, address).await?;
            if identity.is_none() {
                match SshClient::observe_host_key(socket) {
                    Ok(pin) => {
                        let observed = ssh_identity(address, &pin)?;
                        restrictive_replace(
                            &pin_path,
                            &serde_json::to_vec(&observed).map_err(|_| {
                                EngineError::State("SSH host pin could not be encoded".into())
                            })?,
                        )?;
                        identity = Some(observed);
                    }
                    Err(_) if attempt < 59 => {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                    Err(_) => {
                        return Err(EngineError::Backend(
                            "SSH readiness timed out before host-key observation".into(),
                        ));
                    }
                }
            }
            self.revalidate_host_targets(state, address).await?;
            let recorded = identity
                .as_ref()
                .ok_or_else(|| EngineError::State("SSH host pin is missing".into()))?;
            let pin = host_pin(recorded, address)?;
            match SshClient::connect_with_private_key(socket, "dirextalk", &private_key, &pin) {
                Ok(transport) => return Ok((recorded.clone(), pin, transport)),
                Err(_) if attempt < 59 => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(_) => {
                    return Err(EngineError::Backend(
                        "SSH readiness timed out with the persisted host-key pin".into(),
                    ));
                }
            }
        }
        Err(EngineError::Backend("SSH readiness timed out".into()))
    }

    async fn revalidate_host_targets(
        &self,
        state: &DeploymentState,
        address: Ipv4Addr,
    ) -> Result<()> {
        self.revalidate_project(&state.project_identity).await?;
        for resource in [
            state.gcp_resources.instance.as_ref(),
            state.gcp_resources.address.as_ref(),
        ] {
            let resource = resource.ok_or_else(|| {
                EngineError::Backend("host target resource receipt is missing".into())
            })?;
            self.revalidate_resource(&state.project_identity, resource)
                .await?;
        }
        if public_ipv4(state)? != address {
            return Err(EngineError::Backend(
                "reserved host address identity changed".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl ControlPlane for LiveControlPlane {
    async fn auth_login(&self) -> Result<SafeResult> {
        let token = self.oauth.login().await.map_err(gcp_error)?;
        Ok(SafeResult::new(
            "AUTH_LOGIN_COMPLETE",
            "Browser OAuth login completed and the refresh credential was stored securely.",
            json!({
                "principal": token.principal,
                "verified_email": token.verified_email,
            }),
        ))
    }

    async fn auth_status(&self) -> Result<SafeResult> {
        let token = self.token().await?;
        Ok(SafeResult::new(
            "AUTHENTICATED",
            "A usable Google OAuth session is available.",
            json!({
                "principal": token.principal,
                "verified_email": token.verified_email,
            }),
        ))
    }

    async fn auth_logout(&self) -> Result<SafeResult> {
        self.oauth.logout().await.map_err(gcp_error)?;
        Ok(SafeResult::new(
            "AUTH_LOGOUT_COMPLETE",
            "The stored Google OAuth refresh credential was revoked and removed.",
            json!({}),
        ))
    }

    async fn project_list(&self) -> Result<SafeResult> {
        let (_token, client) = self.discovery().await?;
        let projects = client.list_projects().await.map_err(gcp_error)?;
        let projects: Vec<_> = projects
            .into_iter()
            .map(|project| {
                json!({
                    "project_id": project.project_id,
                    "project_number": project.project_number,
                    "display_name": project.display_name,
                    "lifecycle_state": project.lifecycle_state,
                })
            })
            .collect();
        Ok(SafeResult::new(
            "PROJECT_LIST",
            "Accessible GCP projects were read without mutation.",
            json!({ "projects": projects }),
        ))
    }

    async fn project_inspect(&self, project_id: &str) -> Result<SafeResult> {
        let (_token, client) = self.discovery().await?;
        let project = client.project(project_id).await.map_err(gcp_error)?;
        let billing = client.billing(project_id).await.map_err(gcp_error)?;
        Ok(SafeResult::new(
            "PROJECT_INSPECTED",
            "GCP project identity and billing prerequisites were read without mutation.",
            json!({
                "project_id": project.project_id,
                "project_number": project.project_number,
                "display_name": project.display_name,
                "lifecycle_state": project.lifecycle_state,
                "billing_enabled": billing.billing_enabled,
            }),
        ))
    }

    async fn connect_status(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<SafeResult> {
        let secrets = read_product_secrets(state)?;
        let (controller, capability, paths) = connect_controller(config, state, &secrets)?;
        let host_mcp = host_mcp_registry(config, state, &secrets)?;
        let evidence = controller.status().await.map_err(connect_error)?;
        let host_evidence = match &host_mcp {
            Some(registry) => Some(registry.status().await?),
            None => None,
        };
        Ok(SafeResult::new(
            "CONNECT_STATUS",
            "Service-scoped local bridge status was checked.",
            json!({
                "service_id": state.service_id,
                "capability": capability.as_str(),
                "config_path": paths.config,
                "daemon": daemon_name(evidence.state),
                "mcp": if state.local_wiring.installed { "configured" } else { "not_installed" },
                "host_mcp": host_evidence.map(|evidence| json!({
                    "profile": evidence.profile,
                    "server_name": evidence.server_name,
                    "status": "configured",
                })),
            }),
        ))
    }

    async fn connect_doctor(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<SafeResult> {
        let secrets = read_product_secrets(state)?;
        let (controller, capability, paths) = connect_controller(config, state, &secrets)?;
        let host_mcp = host_mcp_registry(config, state, &secrets)?;
        let evidence = controller.doctor().await.map_err(connect_error)?;
        verify_mcp(&secrets).await?;
        let host_evidence = match &host_mcp {
            Some(registry) => Some(registry.doctor().await?),
            None => None,
        };
        Ok(SafeResult::new(
            "CONNECT_HEALTHY",
            "The service-scoped bridge daemon and read-only remote MCP check passed.",
            json!({
                "service_id": state.service_id,
                "capability": capability.as_str(),
                "config_path": paths.config,
                "daemon": daemon_name(evidence.state),
                "mcp": "verified_read_only",
                "host_mcp": host_evidence.map(|evidence| json!({
                    "profile": evidence.profile,
                    "server_name": evidence.server_name,
                    "status": "verified",
                    "tool_count": evidence.tool_count,
                })),
            }),
        ))
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl DeploymentBackend for LiveControlPlane {
    #[allow(clippy::too_many_lines)]
    async fn observe(&self, config: &DeploymentConfig) -> Result<PlanObservations> {
        let token = self.token().await?;
        let unbound = GoogleCloudClient::new("unbound", "0", token.access_token.clone())
            .await
            .map_err(gcp_error)?;
        let project = unbound
            .project(&config.project_id)
            .await
            .map_err(gcp_error)?;
        let project_number = project
            .project_number
            .parse::<u64>()
            .map_err(|_| EngineError::Backend("GCP project number is invalid".into()))?;
        let client = GoogleCloudClient::new(
            &config.project_id,
            project.project_number.clone(),
            token.access_token,
        )
        .await
        .map_err(gcp_error)?;
        let (cpus, _) = parse_machine_capacity(&config.machine_type)?;
        let report = Preflight::new(&client, RequiredService::gcp_v01(), "6F81-5844-456A")
            .with_required_quotas(vec![
                RequiredQuota {
                    metric: "CPUS".into(),
                    required: cpus,
                },
                RequiredQuota {
                    metric: "INSTANCES".into(),
                    required: 1.0,
                },
                RequiredQuota {
                    metric: "IN_USE_ADDRESSES".into(),
                    required: 1.0,
                },
                RequiredQuota {
                    metric: "SSD_TOTAL_GB".into(),
                    required: f64::from(config.boot_disk_size_gib),
                },
            ])
            .inspect_with_dns_mode(
                &config.project_id,
                &config.region,
                match config.dns_mode {
                    deployer_core::DnsMode::Auto => DnsPreflightMode::Auto,
                    deployer_core::DnsMode::CloudDns => DnsPreflightMode::CloudDns,
                    deployer_core::DnsMode::External => DnsPreflightMode::External,
                },
            )
            .await
            .map_err(gcp_error)?;
        let observed_dns = match (config.dns_mode, report.dns) {
            (deployer_core::DnsMode::External, DnsPreflightStatus::External)
            | (
                deployer_core::DnsMode::Auto,
                DnsPreflightStatus::ApiDisabled
                | DnsPreflightStatus::PermissionMissing
                | DnsPreflightStatus::NoPublicZone,
            ) => deployer_core::PlanDnsObservation::External {
                current_ipv4: ipv4_set(public_a_records(&config.domain).await?)?,
            },
            (
                deployer_core::DnsMode::Auto | deployer_core::DnsMode::CloudDns,
                DnsPreflightStatus::Available,
            ) => match longest_matching_zone(&config.domain, &report.zones) {
                Some(zone) => {
                    let record = client
                        .dns_record_set(
                            &config.project_id,
                            &zone.name,
                            &format!("{}.", config.domain),
                            "A",
                        )
                        .await
                        .map_err(gcp_error)?;
                    deployer_core::PlanDnsObservation::CloudDns {
                        zone_name: zone.name.clone(),
                        zone_numeric_id: zone.id.parse().map_err(|_| {
                            EngineError::Backend("Cloud DNS zone id is invalid".into())
                        })?,
                        current_ipv4: ipv4_set(
                            record.map_or_else(Vec::new, |record| record.rrdatas),
                        )?,
                        change: None,
                    }
                }
                None if config.dns_mode == deployer_core::DnsMode::CloudDns => {
                    return Err(EngineError::WaitingUser(
                        "no matching public Cloud DNS managed zone exists".into(),
                    ));
                }
                None => deployer_core::PlanDnsObservation::External {
                    current_ipv4: ipv4_set(public_a_records(&config.domain).await?)?,
                },
            },
            _ => {
                return Err(EngineError::Backend(
                    "GCP DNS preflight mode and result disagree".into(),
                ));
            }
        };
        let release = self.releases.resolve(&config.release).await?;
        let boot_image = client
            .resolve_image_family("ubuntu-os-cloud", "ubuntu-2404-lts-amd64")
            .await
            .map_err(gcp_error)?;
        let pricing = pricing_quote(config, &report.prices)?;
        pricing.validate(CanonicalDeploymentSpec::try_from(config)?.maximum_monthly_microusd)?;
        Ok(PlanObservations {
            project_identity: ProjectIdentity {
                project_id: project.project_id,
                project_number,
                oauth_principal: GoogleSubject::parse(token.principal)?,
            },
            observed_dns,
            boot_image,
            release: release.identity,
            pricing,
        })
    }

    async fn revalidate_project(&self, identity: &ProjectIdentity) -> Result<()> {
        let (token, client) = self.discovery().await?;
        if token.principal != identity.oauth_principal.as_str() {
            return Err(EngineError::Backend("OAuth principal changed".into()));
        }
        let project = client
            .project(&identity.project_id)
            .await
            .map_err(gcp_error)?;
        if project.project_number.parse::<u64>().ok() != Some(identity.project_number)
            || !project.is_active()
        {
            return Err(EngineError::Backend("GCP project identity changed".into()));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn start_effect(
        &self,
        state: &DeploymentState,
        effect: &PendingEffect,
        source_image: Option<&SourceImageIdentity>,
    ) -> Result<EffectStart> {
        self.revalidate_project(&state.project_identity).await?;
        let client = self.client_for(&state.project_identity).await?;
        let project_number = state.project_identity.project_number.to_string();
        let operation = match effect.action {
            EffectAction::Delete => {
                if effect.resource_kind == CoreResourceKind::DnsRecord {
                    let Some(operation) = start_dns_delete(&client, state, effect).await? else {
                        return Ok(EffectStart::AlreadySatisfied(EffectReceipt::Deleted));
                    };
                    operation
                } else {
                    let target = effect.target.as_ref().ok_or_else(|| {
                        EngineError::Backend("delete effect lacks an immutable target".into())
                    })?;
                    let identity = gcp_identity(target)?;
                    match client
                        .get_resource(
                            &project_number,
                            identity.kind,
                            &identity.name,
                            identity.location.as_deref(),
                        )
                        .await
                    {
                        Ok(Some(observed)) => {
                            validate_resource_identity(&identity, &observed).map_err(gcp_error)?;
                        }
                        Ok(None) => {
                            return Ok(EffectStart::AlreadySatisfied(EffectReceipt::Deleted));
                        }
                        Err(error) => return Err(gcp_error(error)),
                    }
                    let Some(operation) = client
                        .start_delete(&project_number, effect.effect_id, &identity)
                        .await
                        .map_err(gcp_error)?
                    else {
                        return Ok(EffectStart::AlreadySatisfied(EffectReceipt::Deleted));
                    };
                    operation
                }
            }
            EffectAction::Create | EffectAction::Update
                if effect.resource_kind == CoreResourceKind::DnsRecord =>
            {
                let Some(operation) = start_dns_update(&client, state, effect).await? else {
                    return dns_effect_receipt(&client, state, effect)
                        .await
                        .map(EffectStart::AlreadySatisfied);
                };
                operation
            }
            EffectAction::Create => {
                start_create_effect(&client, state, effect, source_image).await?
            }
            EffectAction::Update => {
                return Err(EngineError::Backend(
                    "only exact Cloud DNS updates are supported".into(),
                ));
            }
        };
        operation_ref(effect, &operation).map(EffectStart::Started)
    }

    async fn poll_effect(
        &self,
        state: &DeploymentState,
        effect: &PendingEffect,
        source_image: Option<&SourceImageIdentity>,
    ) -> Result<EffectReceipt> {
        self.revalidate_project(&state.project_identity).await?;
        let recorded = effect.operation.as_ref().ok_or_else(|| {
            EngineError::Backend("pending effect lacks the recorded operation".into())
        })?;
        if recorded.request_id != effect.effect_id {
            return Err(EngineError::Backend(
                "recorded operation request id differs from the pending effect".into(),
            ));
        }
        let operation = gcp_operation(effect, recorded)?;
        let client = self.client_for(&state.project_identity).await?;
        for _ in 0..900 {
            self.revalidate_project(&state.project_identity).await?;
            match client
                .poll_operation(
                    &state.project_identity.project_number.to_string(),
                    &operation,
                )
                .await
                .map_err(gcp_error)?
            {
                OperationState::Pending => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                OperationState::Failed(failure) => {
                    return Err(EngineError::Backend(format!(
                        "GCP operation failed: {}",
                        failure.message
                    )));
                }
                OperationState::Succeeded => {
                    if effect.action == EffectAction::Delete {
                        if effect.resource_kind == CoreResourceKind::DnsRecord {
                            require_dns_absent(&client, state, effect).await?;
                        } else {
                            require_resource_absent(&client, state, effect).await?;
                        }
                        return Ok(EffectReceipt::Deleted);
                    }
                    if effect.resource_kind == CoreResourceKind::DnsRecord {
                        return dns_effect_receipt(&client, state, effect).await;
                    }
                    if effect.resource_kind == CoreResourceKind::Disk {
                        let image = gcp_image_identity(source_image.ok_or_else(|| {
                            EngineError::State(
                                "approved disk effect lacks its exact source image".into(),
                            )
                        })?);
                        client.revalidate_image(&image).await.map_err(gcp_error)?;
                    }
                    let receipt = client
                        .get_resource(
                            &state.project_identity.project_number.to_string(),
                            gcp_kind(effect.resource_kind)?,
                            &effect.resource_name,
                            gcp_location(effect.resource_kind, &effect.location),
                        )
                        .await
                        .map_err(gcp_error)?
                        .ok_or_else(|| {
                            EngineError::Backend(
                                "GCP resource is absent after create operation".into(),
                            )
                        })?;
                    validate_effect_properties(state, effect, source_image, &receipt)?;
                    return Ok(EffectReceipt::Present(core_receipt(effect, receipt)?));
                }
            }
        }
        Err(EngineError::Backend(
            "GCP operation polling timed out".into(),
        ))
    }

    async fn revalidate_resource(
        &self,
        identity: &ProjectIdentity,
        resource: &ResourceRef,
    ) -> Result<()> {
        self.revalidate_project(identity).await?;
        let client = self.client_for(identity).await?;
        if resource.resource_kind == CoreResourceKind::DnsRecord {
            return revalidate_dns_resource(&client, identity, resource).await;
        }
        let observed = client
            .get_resource(
                &identity.project_number.to_string(),
                gcp_kind(resource.resource_kind)?,
                &resource.name,
                gcp_location(resource.resource_kind, &resource.location),
            )
            .await
            .map_err(gcp_error)?
            .ok_or_else(|| EngineError::Backend("recorded GCP resource is absent".into()))?;
        validate_resource_identity(&gcp_identity(resource)?, &observed).map_err(gcp_error)?;
        if normalized_attributes(&observed.observed_attributes)? != resource.observed_attributes {
            return Err(EngineError::Backend(
                "recorded GCP resource properties changed".into(),
            ));
        }
        Ok(())
    }

    async fn revalidate_effect(
        &self,
        identity: &ProjectIdentity,
        effect: &PendingEffect,
        receipt: &EffectReceipt,
    ) -> Result<()> {
        match (effect.action, receipt) {
            (EffectAction::Delete, EffectReceipt::Deleted) => Ok(()),
            (EffectAction::Create | EffectAction::Update, EffectReceipt::Present(resource)) => {
                if resource.resource_kind != effect.resource_kind
                    || resource.name != effect.resource_name
                    || resource.project_number != identity.project_number
                    || resource.deployment_uuid != effect.deployment_uuid
                    || resource.location != effect.location
                {
                    return Err(EngineError::Backend(
                        "effect receipt identity differs from the pending effect".into(),
                    ));
                }
                for (key, expected) in &effect.expected_attributes {
                    if resource.observed_attributes.get(key) != Some(expected) {
                        return Err(EngineError::Backend(format!(
                            "effect postcondition {key} differs from the approved value"
                        )));
                    }
                }
                self.revalidate_resource(identity, resource).await
            }
            _ => Err(EngineError::Backend(
                "effect receipt action does not match the pending effect".into(),
            )),
        }
    }

    async fn external_dns_ready(&self, domain: &str, address: &str) -> Result<bool> {
        let expected: Ipv4Addr = address
            .parse()
            .map_err(|_| EngineError::Backend("expected DNS address is invalid".into()))?;
        Ok(public_a_records(domain)
            .await?
            .iter()
            .any(|value| value.parse::<Ipv4Addr>().ok() == Some(expected)))
    }

    async fn install_host(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<(deployer_core::SshHostIdentity, deployer_core::HostReceipt)> {
        self.revalidate_project(&state.project_identity).await?;
        for resource in [
            state.gcp_resources.instance.as_ref(),
            state.gcp_resources.address.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            self.revalidate_resource(&state.project_identity, resource)
                .await?;
        }
        let exact = state
            .release_identity
            .as_ref()
            .ok_or_else(|| EngineError::Backend("exact release is not recorded".into()))?;
        let resolved = self
            .releases
            .resolve(&deployer_core::ReleaseSelection::Exact(
                exact.release_tag.clone(),
            ))
            .await?;
        if resolved.identity != *exact {
            return Err(EngineError::Backend(
                "release catalog returned a different exact release".into(),
            ));
        }
        let payload = self.releases.load(&resolved).await?;
        let receipt_key_path = service_paths(state)?.root.join("host-receipt.key");
        let receipt_key = if receipt_key_path.exists() {
            let bytes = read_restrictive(&receipt_key_path)?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| {
                EngineError::State("persisted host receipt key has invalid length".into())
            })?;
            Zeroizing::new(key)
        } else {
            let mut key = Zeroizing::new([0_u8; 32]);
            rand::rng().fill_bytes(key.as_mut());
            restrictive_replace(&receipt_key_path, key.as_ref())?;
            key
        };
        let address = public_ipv4(state)?;
        let authoritative_dns_ipv4 = match authoritative_server(&config.domain).await? {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => {
                return Err(EngineError::Backend(
                    "authoritative DNS proof requires an IPv4 server".into(),
                ));
            }
        };
        let public_recursive_dns_ipv4: Ipv4Addr = "8.8.8.8"
            .parse()
            .expect("fixed public recursive resolver is valid");
        let request = InstallRequest {
            schema_version: 1,
            deployment_uuid: state.deployment_uuid,
            service_id: state.service_id.clone(),
            release: exact.release_tag.to_string(),
            target: HostTarget::LinuxAmd64,
            bundle_sha256: payload.bundle.bundle_sha256.clone(),
            manifest_sha256: payload.bundle.manifest_sha256.clone(),
            release_signing_public_key: payload.bundle.release_signing_public_key.clone(),
            receipt_key_sha256: DigestHex::calculate(receipt_key.as_ref()),
            domain: config.domain.clone(),
            public_ipv4: address,
            region: config.region.clone(),
            release_catalog_origin: payload.release_catalog_origin.clone(),
            account_generation: account_generation(state.deployment_uuid),
            authoritative_dns_ipv4,
            public_recursive_dns_ipv4,
            updater: payload.updater.clone(),
        };
        request.validate().map_err(host_error)?;
        let request_bytes = host_canonical_json(&request).map_err(host_error)?;
        let request_sha = DigestHex::calculate(&request_bytes);
        let transport_sha = Sha256Digest::parse(request_sha.as_str()).map_err(transport_error)?;
        let (identity, _pin, mut transport) = self.install_transport(state, address).await?;
        transport
            .upload(RemoteArtifact::HostInstaller, &payload.installer)
            .and_then(|()| transport.upload(RemoteArtifact::InstallRequest, &request_bytes))
            .and_then(|()| transport.upload(RemoteArtifact::ReleaseBundle, &payload.bundle.bytes))
            .and_then(|()| transport.upload(RemoteArtifact::ReceiptKey, receipt_key.as_ref()))
            .map_err(transport_error)?;
        let output = transport
            .execute(&FixedRemoteCommand::RunHostInstaller {
                request_sha256: transport_sha,
            })
            .map_err(transport_error)?;
        if output.exit_status == 2 {
            return Err(EngineError::WaitingUser(
                "host installer requires operator action".into(),
            ));
        }
        if output.exit_status != 0 {
            return Err(EngineError::Backend(format!(
                "host installer exited with status {}",
                output.exit_status
            )));
        }
        let signed: SignedReceipt = serde_json::from_slice(&output.stdout)
            .map_err(|_| EngineError::Backend("host receipt is invalid".into()))?;
        verify_receipt(&signed, receipt_key.as_ref()).map_err(host_error)?;
        if signed.receipt.deployment_uuid != state.deployment_uuid
            || signed.receipt.service_id != state.service_id
            || signed.receipt.release != exact.release_tag.as_str()
            || signed.receipt.request_sha256 != request_sha
            || signed.receipt.bundle_sha256 != payload.bundle.bundle_sha256
            || signed.receipt.manifest_sha256 != payload.bundle.manifest_sha256
            || signed.receipt.domain != config.domain
            || signed.receipt.public_ipv4 != address
            || signed.receipt.region != config.region
            || signed.receipt.account_generation != request.account_generation
            || signed.receipt.updater != request.updater
            || signed.receipt.runtime_status != deployer_host::RuntimeStatus::RuntimeHealthy
        {
            return Err(EngineError::Backend(
                "host receipt identity does not match the approved installation".into(),
            ));
        }
        let receipt = deployer_core::HostReceipt {
            deployment_uuid: state.deployment_uuid,
            release_tag: exact.release_tag.clone(),
            host_installer_sha256: deployer_core::Sha256Digest::parse(
                DigestHex::calculate(&payload.installer).as_str(),
            )?,
            runtime_bundle_sha256: deployer_core::Sha256Digest::parse(
                payload.bundle.bundle_sha256.as_str(),
            )?,
            installed_at_unix_ms: signed.receipt.completed_unix_seconds.saturating_mul(1000),
            receipt_signature: signed.hmac_sha256.as_str().to_owned(),
        };
        Ok((identity, receipt))
    }

    async fn complete_product(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<SecretString> {
        let paths = service_paths(state)?;
        if paths.credentials.exists() && paths.matrix_session.exists() {
            let secrets = StoredProductSecrets::read(&paths.credentials, &paths.matrix_session)?;
            validate_stored_product(config, &secrets)?;
            return Ok(secrets.initialization_code);
        }
        let mut transport = self.verified_transport(state).await?;
        prove_server_dns(&mut transport, config, state).await?;
        require_remote_success(
            &mut transport,
            &FixedRemoteCommand::VerifyHttps {
                name: DnsName::parse(&config.domain).map_err(transport_error)?,
            },
            "HTTPS",
        )?;
        let bootstrap_bytes = transport
            .read_product_bootstrap()
            .map_err(transport_error)?;
        let bootstrap = ProductBootstrap::parse(&config.domain, &bootstrap_bytes)?;
        let api = HttpProductApi::new()?;
        let sessions = initialize_product(&api, &bootstrap).await?;
        let secrets =
            StoredProductSecrets::from_initialized(&bootstrap, sessions, &state.service_id);
        secrets.write(&paths.credentials, &paths.matrix_session)?;
        Ok(secrets.initialization_code)
    }

    async fn install_connect(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<LocalWiringStatus> {
        let secrets = read_product_secrets(state)?;
        validate_stored_product(config, &secrets)?;
        let paths = service_paths(state)?;
        let selection = agent_selection(&config.connect_agent)?;
        let capability = resolve_capability(selection).map_err(connect_error)?;
        if capability == AgentCapability::Unsupported {
            return Err(EngineError::WaitingUser(
                "the selected local Agent does not support the required bridge".into(),
            ));
        }
        let host_mcp = host_mcp_registry(config, state, &secrets)?;
        let rendered =
            render_connect_config(state, &paths, selection, &secrets, host_mcp.as_ref())?;
        write_connect_config(&paths.config, &rendered).map_err(connect_error)?;
        let resolver = ReleaseResolver::new().map_err(release_error)?;
        let asset = resolver
            .fetch_verified_asset(
                &ReleaseChannel::LatestStable,
                LocalPlatform::current().map_err(connect_error)?,
            )
            .await
            .map_err(release_error)?;
        asset.install_binary(&paths.binary).map_err(release_error)?;
        let (controller, _, _) = connect_controller(config, state, &secrets)?;
        let evidence = controller.install().await.map_err(connect_error)?;
        if evidence.state != DaemonState::Running {
            return Err(EngineError::Backend(
                "local bridge daemon did not reach running state".into(),
            ));
        }
        verify_mcp(&secrets).await?;
        if let Some(registry) = &host_mcp {
            registry
                .install(&format!("{}/mcp", secrets.origin), &secrets.agent_token)
                .await?;
        }
        Ok(LocalWiringStatus {
            requested: true,
            installed: true,
            service_active: true,
            last_checked_unix_ms: Some(now_unix_ms()?),
        })
    }

    async fn verify_product(
        &self,
        config: &DeploymentConfig,
        state: &DeploymentState,
    ) -> Result<()> {
        let secrets = read_product_secrets(state)?;
        validate_stored_product(config, &secrets)?;
        let mut transport = self.verified_transport(state).await?;
        prove_server_dns(&mut transport, config, state).await?;
        for (command, name) in [
            (
                FixedRemoteCommand::VerifyCanonicalRuntime,
                "canonical runtime",
            ),
            (
                FixedRemoteCommand::VerifyHttps {
                    name: DnsName::parse(&config.domain).map_err(transport_error)?,
                },
                "HTTPS",
            ),
            (FixedRemoteCommand::VerifyUpdater, "updater"),
        ] {
            require_remote_success(&mut transport, &command, name)?;
        }
        verify_http_product(config, &secrets, public_ipv4(state)?).await?;
        verify_mcp(&secrets).await?;
        if state.local_wiring.requested {
            let (controller, _, _) = connect_controller(config, state, &secrets)?;
            controller.doctor().await.map_err(connect_error)?;
            if let Some(registry) = host_mcp_registry(config, state, &secrets)? {
                registry.doctor().await?;
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
async fn start_create_effect(
    client: &GoogleCloudClient,
    state: &DeploymentState,
    effect: &PendingEffect,
    source_image: Option<&SourceImageIdentity>,
) -> Result<Operation> {
    let project_number = state.project_identity.project_number.to_string();
    match effect.resource_kind {
        CoreResourceKind::Network => client
            .start_network(
                &project_number,
                effect.effect_id,
                &NetworkSpec {
                    name: effect.resource_name.clone(),
                    deployment_uuid: effect.deployment_uuid,
                },
            )
            .await
            .map_err(gcp_error),
        CoreResourceKind::Subnet => client
            .start_subnetwork(
                &project_number,
                effect.effect_id,
                &SubnetworkSpec {
                    name: effect.resource_name.clone(),
                    region: effect.location.clone(),
                    network_self_link: required_resource(
                        state.gcp_resources.network.as_ref(),
                        "network",
                    )?
                    .self_link
                    .clone(),
                    cidr: required_attribute(effect, "cidr")?.to_owned(),
                    deployment_uuid: effect.deployment_uuid,
                },
            )
            .await
            .map_err(gcp_error),
        CoreResourceKind::Firewall => {
            let (source_ranges, allowed) = firewall_properties(effect)?;
            client
                .start_firewall(
                    &project_number,
                    effect.effect_id,
                    &FirewallSpec {
                        name: effect.resource_name.clone(),
                        network_self_link: required_resource(
                            state.gcp_resources.network.as_ref(),
                            "network",
                        )?
                        .self_link
                        .clone(),
                        source_ranges,
                        target_tag: deployment_target_tag(state.deployment_uuid),
                        allowed,
                        deployment_uuid: effect.deployment_uuid,
                    },
                )
                .await
                .map_err(gcp_error)
        }
        CoreResourceKind::Address => client
            .start_address(
                &project_number,
                effect.effect_id,
                &AddressSpec {
                    name: effect.resource_name.clone(),
                    region: effect.location.clone(),
                    deployment_uuid: effect.deployment_uuid,
                },
            )
            .await
            .map_err(gcp_error),
        CoreResourceKind::Disk => {
            let image = gcp_image_identity(source_image.ok_or_else(|| {
                EngineError::State("approved disk effect lacks its exact source image".into())
            })?);
            client.revalidate_image(&image).await.map_err(gcp_error)?;
            client
                .start_disk(
                    &project_number,
                    effect.effect_id,
                    &DiskSpec {
                        name: effect.resource_name.clone(),
                        zone: effect.location.clone(),
                        size_gib: required_attribute(effect, "size_gib")?.parse().map_err(
                            |_| EngineError::Backend("planned disk size is invalid".into()),
                        )?,
                        disk_type: required_attribute(effect, "type")?.to_owned(),
                        source_image: image.self_link,
                        source_image_id: image.numeric_id,
                        deployment_uuid: effect.deployment_uuid,
                    },
                )
                .await
                .map_err(gcp_error)
        }
        CoreResourceKind::Instance => {
            let public_key = ensure_ssh_key(state)?;
            client
                .start_instance(
                    &project_number,
                    effect.effect_id,
                    &InstanceSpec {
                        name: effect.resource_name.clone(),
                        zone: effect.location.clone(),
                        machine_type: required_attribute(effect, "machine_type")?.to_owned(),
                        subnetwork_self_link: required_resource(
                            state.gcp_resources.subnet.as_ref(),
                            "subnetwork",
                        )?
                        .self_link
                        .clone(),
                        address: public_ipv4(state)?.to_string(),
                        boot_disk_self_link: required_resource(
                            state.gcp_resources.boot_disk.as_ref(),
                            "boot disk",
                        )?
                        .self_link
                        .clone(),
                        network_tags: vec![deployment_target_tag(state.deployment_uuid)],
                        ssh_username: "dirextalk".into(),
                        ssh_public_key: public_key,
                        deployment_uuid: effect.deployment_uuid,
                    },
                )
                .await
                .map_err(gcp_error)
        }
        CoreResourceKind::DnsRecord => Err(EngineError::Backend(
            "DNS creates use the exact DNS mutation adapter".into(),
        )),
    }
}

async fn start_dns_update(
    client: &GoogleCloudClient,
    state: &DeploymentState,
    effect: &PendingEffect,
) -> Result<Option<Operation>> {
    let zone = required_attribute(effect, "zone_name")?.to_owned();
    let current: Vec<String> = effect
        .expected_attributes
        .get("current_values")
        .map_or_else(|| Ok(Vec::new()), |values| serde_json::from_str(values))
        .map_err(|_| EngineError::Backend("planned DNS old values are invalid".into()))?;
    let old_record = (!current.is_empty()).then(|| DnsRecordSet {
        name: format!("{}.", effect.resource_name.trim_end_matches('.')),
        record_type: "A".into(),
        ttl: 300,
        rrdatas: current,
    });
    let value = effect
        .expected_attributes
        .get("value")
        .cloned()
        .unwrap_or(public_ipv4(state)?.to_string());
    let additions = vec![DnsRecordSet {
        name: format!("{}.", effect.resource_name.trim_end_matches('.')),
        record_type: "A".into(),
        ttl: 300,
        rrdatas: vec![value],
    }];
    client
        .start_dns_change(
            &state.project_identity.project_number.to_string(),
            effect.effect_id,
            &DnsChange {
                managed_zone: zone,
                expected_current: old_record.clone(),
                additions,
                deletions: old_record.into_iter().collect(),
            },
        )
        .await
        .map_err(gcp_error)
}

async fn start_dns_delete(
    client: &GoogleCloudClient,
    state: &DeploymentState,
    effect: &PendingEffect,
) -> Result<Option<Operation>> {
    let zone = required_attribute(effect, "zone_name")?;
    let name = format!("{}.", effect.resource_name.trim_end_matches('.'));
    let Some(observed) = client
        .dns_record_set(&state.project_identity.project_id, zone, &name, "A")
        .await
        .map_err(gcp_error)?
    else {
        return Ok(None);
    };
    let expected_value = required_attribute(effect, "value")?;
    if observed.name != name || observed.record_type != "A" || observed.rrdatas != [expected_value]
    {
        return Err(EngineError::Backend(
            "Cloud DNS delete target was replaced after approval".into(),
        ));
    }
    client
        .start_dns_change(
            &state.project_identity.project_number.to_string(),
            effect.effect_id,
            &DnsChange {
                managed_zone: zone.to_owned(),
                expected_current: Some(observed.clone()),
                additions: Vec::new(),
                deletions: vec![observed],
            },
        )
        .await
        .map_err(gcp_error)
}

async fn require_resource_absent(
    client: &GoogleCloudClient,
    state: &DeploymentState,
    effect: &PendingEffect,
) -> Result<()> {
    let target = effect
        .target
        .as_ref()
        .ok_or_else(|| EngineError::Backend("delete effect lacks an immutable target".into()))?;
    let identity = gcp_identity(target)?;
    let observed = client
        .get_resource(
            &state.project_identity.project_number.to_string(),
            identity.kind,
            &identity.name,
            identity.location.as_deref(),
        )
        .await
        .map_err(gcp_error)?;
    require_gcp_resource_absent(&identity, observed.as_ref()).map_err(gcp_error)
}

async fn require_dns_absent(
    client: &GoogleCloudClient,
    state: &DeploymentState,
    effect: &PendingEffect,
) -> Result<()> {
    let zone = required_attribute(effect, "zone_name")?;
    let observed = client
        .dns_record_set(
            &state.project_identity.project_id,
            zone,
            &format!("{}.", effect.resource_name.trim_end_matches('.')),
            "A",
        )
        .await
        .map_err(gcp_error)?;
    if observed.is_some() {
        return Err(EngineError::Backend(
            "Cloud DNS record is still present after delete operation".into(),
        ));
    }
    Ok(())
}

fn operation_ref(effect: &PendingEffect, operation: &Operation) -> Result<OperationRef> {
    if operation.project_number != effect.project_number.to_string() {
        return Err(EngineError::Backend(
            "GCP operation project number changed".into(),
        ));
    }
    let numeric_id = operation
        .name
        .parse()
        .map_err(|_| EngineError::Backend("GCP operation id is not numeric".into()))?;
    Ok(OperationRef {
        request_id: effect.effect_id,
        project_number: effect.project_number,
        location: effect.location.clone(),
        numeric_id,
        self_link: OperationUri::parse(operation.self_link.clone())?,
    })
}

fn gcp_operation(effect: &PendingEffect, recorded: &OperationRef) -> Result<Operation> {
    let scope = if effect.resource_kind == CoreResourceKind::DnsRecord {
        OperationScope::DnsZone(required_attribute(effect, "zone_name")?.to_owned())
    } else {
        match effect.resource_kind {
            CoreResourceKind::Network | CoreResourceKind::Firewall => OperationScope::Global,
            CoreResourceKind::Subnet | CoreResourceKind::Address => {
                OperationScope::Region(effect.location.clone())
            }
            CoreResourceKind::Disk | CoreResourceKind::Instance => {
                OperationScope::Zone(effect.location.clone())
            }
            CoreResourceKind::DnsRecord => unreachable!(),
        }
    };
    Ok(Operation {
        name: recorded.numeric_id.to_string(),
        self_link: recorded.self_link.to_string(),
        project_number: recorded.project_number.to_string(),
        scope,
    })
}

async fn dns_effect_receipt(
    client: &GoogleCloudClient,
    state: &DeploymentState,
    effect: &PendingEffect,
) -> Result<EffectReceipt> {
    let zone = required_attribute(effect, "zone_name")?;
    let expected = effect
        .expected_attributes
        .get("value")
        .cloned()
        .unwrap_or(public_ipv4(state)?.to_string());
    let record = client
        .dns_record_set(
            &state.project_identity.project_id,
            zone,
            &format!("{}.", effect.resource_name.trim_end_matches('.')),
            "A",
        )
        .await
        .map_err(gcp_error)?
        .ok_or_else(|| EngineError::Backend("Cloud DNS record is absent after mutation".into()))?;
    if record.rrdatas != [expected.clone()] {
        return Err(EngineError::Backend(
            "Cloud DNS record differs from the approved replacement".into(),
        ));
    }
    let numeric_id = required_attribute(effect, "zone_numeric_id")?
        .parse()
        .map_err(|_| EngineError::Backend("Cloud DNS zone id is invalid".into()))?;
    let mut attributes = effect.expected_attributes.clone();
    attributes.insert("value".into(), expected);
    Ok(EffectReceipt::Present(ResourceRef {
        resource_kind: CoreResourceKind::DnsRecord,
        name: effect.resource_name.clone(),
        project_number: effect.project_number,
        location: effect.location.clone(),
        numeric_id,
        self_link: format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{zone}/rrsets/{}/A",
            state.project_identity.project_id, effect.resource_name
        ),
        deployment_uuid: effect.deployment_uuid,
        observed_attributes: attributes,
    }))
}

fn core_receipt(
    effect: &PendingEffect,
    receipt: deployer_gcp::ResourceReceipt,
) -> Result<ResourceRef> {
    let numeric_id = receipt
        .identity
        .numeric_id
        .parse()
        .map_err(|_| EngineError::Backend("GCP resource numeric id is invalid".into()))?;
    let attributes = normalized_attributes(&receipt.observed_attributes)?;
    Ok(ResourceRef {
        resource_kind: effect.resource_kind,
        name: receipt.identity.name,
        project_number: effect.project_number,
        location: effect.location.clone(),
        numeric_id,
        self_link: receipt.identity.self_link,
        deployment_uuid: receipt.identity.deployment_uuid,
        observed_attributes: attributes,
    })
}

fn gcp_identity(resource: &ResourceRef) -> Result<ResourceIdentity> {
    Ok(ResourceIdentity {
        kind: gcp_kind(resource.resource_kind)?,
        name: resource.name.clone(),
        project_number: resource.project_number.to_string(),
        location: gcp_location(resource.resource_kind, &resource.location).map(str::to_owned),
        numeric_id: resource.numeric_id.to_string(),
        self_link: resource.self_link.clone(),
        deployment_uuid: resource.deployment_uuid,
    })
}

fn gcp_kind(kind: CoreResourceKind) -> Result<GcpResourceKind> {
    match kind {
        CoreResourceKind::Network => Ok(GcpResourceKind::Network),
        CoreResourceKind::Subnet => Ok(GcpResourceKind::Subnetwork),
        CoreResourceKind::Firewall => Ok(GcpResourceKind::Firewall),
        CoreResourceKind::Address => Ok(GcpResourceKind::Address),
        CoreResourceKind::Instance => Ok(GcpResourceKind::Instance),
        CoreResourceKind::Disk => Ok(GcpResourceKind::Disk),
        CoreResourceKind::DnsRecord => Err(EngineError::Backend(
            "Cloud DNS records use the exact DNS receipt adapter".into(),
        )),
    }
}

const fn gcp_location(kind: CoreResourceKind, location: &str) -> Option<&str> {
    match kind {
        CoreResourceKind::Network | CoreResourceKind::Firewall => None,
        _ => Some(location),
    }
}

async fn revalidate_dns_resource(
    client: &GoogleCloudClient,
    identity: &ProjectIdentity,
    resource: &ResourceRef,
) -> Result<()> {
    let zone = resource
        .observed_attributes
        .get("zone_name")
        .ok_or_else(|| EngineError::Backend("Cloud DNS receipt omitted zone name".into()))?;
    let expected = resource
        .observed_attributes
        .get("value")
        .ok_or_else(|| EngineError::Backend("Cloud DNS receipt omitted exact value".into()))?;
    let zone_id: u64 = resource
        .observed_attributes
        .get("zone_numeric_id")
        .ok_or_else(|| EngineError::Backend("Cloud DNS receipt omitted zone id".into()))?
        .parse()
        .map_err(|_| EngineError::Backend("Cloud DNS receipt zone id is invalid".into()))?;
    if zone_id != resource.numeric_id || resource.project_number != identity.project_number {
        return Err(EngineError::Backend(
            "Cloud DNS immutable identity differs from the receipt".into(),
        ));
    }
    let record = client
        .dns_record_set(
            &identity.project_id,
            zone,
            &format!("{}.", resource.name.trim_end_matches('.')),
            "A",
        )
        .await
        .map_err(gcp_error)?
        .ok_or_else(|| EngineError::Backend("Cloud DNS record is absent".into()))?;
    if record.rrdatas != [expected.clone()] {
        return Err(EngineError::Backend(
            "Cloud DNS record value changed".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_effect_properties(
    state: &DeploymentState,
    effect: &PendingEffect,
    source_image: Option<&SourceImageIdentity>,
    receipt: &deployer_gcp::ResourceReceipt,
) -> Result<()> {
    match effect.resource_kind {
        CoreResourceKind::Network => validate_resource_properties(
            ResourceSpecRef::Network(&NetworkSpec {
                name: effect.resource_name.clone(),
                deployment_uuid: effect.deployment_uuid,
            }),
            receipt,
        ),
        CoreResourceKind::Subnet => validate_resource_properties(
            ResourceSpecRef::Subnetwork(&SubnetworkSpec {
                name: effect.resource_name.clone(),
                region: effect.location.clone(),
                network_self_link: required_resource(
                    state.gcp_resources.network.as_ref(),
                    "network",
                )?
                .self_link
                .clone(),
                cidr: required_attribute(effect, "cidr")?.to_owned(),
                deployment_uuid: effect.deployment_uuid,
            }),
            receipt,
        ),
        CoreResourceKind::Firewall => {
            let (source_ranges, allowed) = firewall_properties(effect)?;
            validate_resource_properties(
                ResourceSpecRef::Firewall(&FirewallSpec {
                    name: effect.resource_name.clone(),
                    network_self_link: required_resource(
                        state.gcp_resources.network.as_ref(),
                        "network",
                    )?
                    .self_link
                    .clone(),
                    source_ranges,
                    target_tag: deployment_target_tag(state.deployment_uuid),
                    allowed,
                    deployment_uuid: effect.deployment_uuid,
                }),
                receipt,
            )
        }
        CoreResourceKind::Address => validate_resource_properties(
            ResourceSpecRef::Address(&AddressSpec {
                name: effect.resource_name.clone(),
                region: effect.location.clone(),
                deployment_uuid: effect.deployment_uuid,
            }),
            receipt,
        ),
        CoreResourceKind::Disk => {
            let image = gcp_image_identity(source_image.ok_or_else(|| {
                EngineError::State("approved disk effect lacks its exact source image".into())
            })?);
            validate_resource_properties(
                ResourceSpecRef::Disk(&DiskSpec {
                    name: effect.resource_name.clone(),
                    zone: effect.location.clone(),
                    size_gib: required_attribute(effect, "size_gib")?
                        .parse()
                        .map_err(|_| EngineError::Backend("disk size is invalid".into()))?,
                    disk_type: required_attribute(effect, "type")?.to_owned(),
                    source_image: image.self_link,
                    source_image_id: image.numeric_id,
                    deployment_uuid: effect.deployment_uuid,
                }),
                receipt,
            )
        }
        CoreResourceKind::Instance => validate_resource_properties(
            ResourceSpecRef::Instance(&InstanceSpec {
                name: effect.resource_name.clone(),
                zone: effect.location.clone(),
                machine_type: required_attribute(effect, "machine_type")?.to_owned(),
                subnetwork_self_link: required_resource(
                    state.gcp_resources.subnet.as_ref(),
                    "subnetwork",
                )?
                .self_link
                .clone(),
                address: public_ipv4(state)?.to_string(),
                boot_disk_self_link: required_resource(
                    state.gcp_resources.boot_disk.as_ref(),
                    "boot disk",
                )?
                .self_link
                .clone(),
                network_tags: vec![deployment_target_tag(state.deployment_uuid)],
                ssh_username: "dirextalk".into(),
                ssh_public_key: ensure_ssh_key(state)?,
                deployment_uuid: effect.deployment_uuid,
            }),
            receipt,
        ),
        CoreResourceKind::DnsRecord => {
            return Err(EngineError::Backend(
                "DNS properties use the exact DNS adapter".into(),
            ));
        }
    }
    .map_err(gcp_error)
}

fn normalized_attributes(values: &BTreeMap<String, Value>) -> Result<BTreeMap<String, String>> {
    values
        .iter()
        .map(|(key, value)| {
            let value = match value {
                Value::String(value) => value.clone(),
                value => serde_json::to_string(&value).map_err(|_| {
                    EngineError::Backend("GCP observed properties could not be normalized".into())
                })?,
            };
            Ok((key.clone(), value))
        })
        .collect()
}

fn deployment_target_tag(deployment_uuid: uuid::Uuid) -> String {
    format!("dt-{}", &deployment_uuid.simple().to_string()[..12])
}

fn firewall_properties(effect: &PendingEffect) -> Result<(Vec<String>, Vec<FirewallAllowance>)> {
    if effect.resource_name.ends_with("-web") {
        Ok((
            vec!["0.0.0.0/0".into()],
            vec![FirewallAllowance {
                protocol: "tcp".into(),
                ports: vec!["80".into(), "443".into()],
            }],
        ))
    } else if effect.resource_name.ends_with("-turn") {
        Ok((
            vec!["0.0.0.0/0".into()],
            vec![
                FirewallAllowance {
                    protocol: "tcp".into(),
                    ports: vec!["3478".into()],
                },
                FirewallAllowance {
                    protocol: "udp".into(),
                    ports: vec!["3478".into(), "49160-49200".into()],
                },
            ],
        ))
    } else {
        Ok((
            vec![required_attribute(effect, "source")?.to_owned()],
            vec![FirewallAllowance {
                protocol: "tcp".into(),
                ports: vec!["22".into()],
            }],
        ))
    }
}

fn gcp_image_identity(source: &SourceImageIdentity) -> ImageIdentity {
    ImageIdentity {
        project_id: source.project_id.clone(),
        family: "ubuntu-2404-lts-amd64".into(),
        name: source.name.clone(),
        numeric_id: source.numeric_id.to_string(),
        self_link: source.self_link.clone(),
        status: "READY".into(),
        architecture: "X86_64".into(),
    }
}

fn required_attribute<'a>(effect: &'a PendingEffect, name: &str) -> Result<&'a str> {
    effect
        .expected_attributes
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| EngineError::Backend(format!("planned effect omitted {name}")))
}

fn required_resource<'a>(resource: Option<&'a ResourceRef>, name: &str) -> Result<&'a ResourceRef> {
    resource.ok_or_else(|| EngineError::Backend(format!("{name} receipt is missing")))
}

fn ensure_ssh_key(state: &DeploymentState) -> Result<String> {
    let private = ssh_private_key_path(state)?;
    if !private.exists() {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(seed.as_mut());
        let mut key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed));
        key.set_comment(format!("dirextalk:{}", state.deployment_uuid));
        let encoded = key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|_| EngineError::State("SSH private key could not be encoded".into()))?;
        restrictive_replace(&private, encoded.as_bytes())?;
    }
    let private_bytes = Zeroizing::new(read_restrictive(&private)?);
    let private_text = std::str::from_utf8(&private_bytes)
        .map_err(|_| EngineError::State("SSH private key is invalid".into()))?;
    let key = ssh_key::PrivateKey::from_openssh(private_text)
        .map_err(|_| EngineError::State("SSH private key is invalid".into()))?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 || key.is_encrypted() {
        return Err(EngineError::State(
            "SSH private key is not an unencrypted Ed25519 key".into(),
        ));
    }
    key.public_key()
        .to_openssh()
        .map_err(|_| EngineError::State("SSH public key could not be encoded".into()))
}

fn pricing_quote(
    config: &DeploymentConfig,
    prices: &[deployer_gcp::SkuPrice],
) -> Result<PricingQuote> {
    let (cpus, memory_gib) = parse_machine_capacity(&config.machine_type)?;
    let quantities = [
        (
            select_price(prices, &["e2", "core"], "E2 CPU")?,
            checked_quantity(cpus, 730)?,
        ),
        (
            select_price_any(prices, &[&["e2", "ram"], &["e2", "memory"]], "E2 memory")?,
            checked_quantity(memory_gib, 730)?,
        ),
        (
            select_price_any(
                prices,
                &[&["balanced", "capacity"], &["balanced", "disk"]],
                "balanced persistent disk",
            )?,
            RationalQuantity {
                numerator: u64::from(config.boot_disk_size_gib),
                denominator: 1,
            },
        ),
        (
            select_price(prices, &["static", "ip"], "regional static IPv4")?,
            RationalQuantity {
                numerator: 730,
                denominator: 1,
            },
        ),
    ];
    let mut lines = BTreeSet::new();
    let mut total = 0_u64;
    for (price, usage_quantity) in quantities {
        let line = pricing_line(price, usage_quantity)?;
        total = total
            .checked_add(line.subtotal_microusd)
            .ok_or_else(|| EngineError::Backend("pricing total overflowed".into()))?;
        if !lines.insert(line) {
            return Err(EngineError::Backend(
                "pricing quote repeats a SKU expression".into(),
            ));
        }
    }
    Ok(PricingQuote {
        currency: PricingCurrency::Usd,
        lines,
        unpriced_exclusions: BTreeSet::from([
            UnpricedExclusion::NetworkEgress,
            UnpricedExclusion::CloudDnsQueries,
            UnpricedExclusion::BackupAndSnapshotStorage,
            UnpricedExclusion::Support,
            UnpricedExclusion::Taxes,
        ]),
        total_microusd: total,
    })
}

fn select_price<'a>(
    prices: &'a [deployer_gcp::SkuPrice],
    needles: &[&str],
    name: &str,
) -> Result<&'a deployer_gcp::SkuPrice> {
    let mut candidates: Vec<_> = prices
        .iter()
        .filter(|price| price.currency_code == "USD")
        .filter(|price| {
            let description = price.description.to_ascii_lowercase();
            needles.iter().all(|needle| description.contains(needle))
                && !["spot", "preemptible", "commitment"]
                    .iter()
                    .any(|excluded| description.contains(excluded))
        })
        .collect();
    candidates.sort_by(|left, right| {
        price_nanos(left)
            .unwrap_or(0)
            .cmp(&price_nanos(right).unwrap_or(0))
            .then_with(|| left.sku_id.cmp(&right.sku_id))
    });
    candidates
        .pop()
        .ok_or_else(|| EngineError::Backend(format!("{name} price is unavailable")))
}

fn select_price_any<'a>(
    prices: &'a [deployer_gcp::SkuPrice],
    alternatives: &[&[&str]],
    name: &str,
) -> Result<&'a deployer_gcp::SkuPrice> {
    alternatives
        .iter()
        .find_map(|needles| select_price(prices, needles, name).ok())
        .ok_or_else(|| EngineError::Backend(format!("{name} price is unavailable")))
}

fn pricing_line(
    price: &deployer_gcp::SkuPrice,
    usage_quantity: RationalQuantity,
) -> Result<PricingLine> {
    let [tier] = price.tiers.as_slice() else {
        return Err(EngineError::Backend(
            "multi-rate GCP pricing expressions are unsupported".into(),
        ));
    };
    let base_unit_conversion = exact_positive_f64(price.base_unit_conversion_factor)?;
    let tier_start = exact_nonnegative_f64(tier.start_usage_amount)?;
    let tier_start_base_units = multiply_to_integer(tier_start, base_unit_conversion)?;
    let mut line = PricingLine {
        sku_id: price.sku_id.clone(),
        tier_start_base_units,
        usage_unit: price.usage_unit.clone(),
        base_unit: price.base_unit.clone(),
        base_unit_conversion,
        usage_quantity,
        unit_price_nanos: price_nanos(price).ok_or_else(|| {
            EngineError::Backend("GCP pricing expression has an invalid Money value".into())
        })?,
        subtotal_microusd: 1,
    };
    line.subtotal_microusd = line.conservative_subtotal_microusd()?;
    Ok(line)
}

fn price_nanos(price: &deployer_gcp::SkuPrice) -> Option<u64> {
    let [tier] = price.tiers.as_slice() else {
        return None;
    };
    let units = u64::try_from(tier.units).ok()?;
    let nanos = u64::try_from(tier.nanos).ok()?;
    units.checked_mul(1_000_000_000)?.checked_add(nanos)
}

fn checked_quantity(value: f64, hours: u64) -> Result<RationalQuantity> {
    let value = exact_positive_f64(value)?;
    let numerator = value
        .numerator
        .checked_mul(hours)
        .ok_or_else(|| EngineError::Backend("pricing quantity overflowed".into()))?;
    let divisor = greatest_common_divisor(numerator, value.denominator);
    Ok(RationalQuantity {
        numerator: numerator / divisor,
        denominator: value.denominator / divisor,
    })
}

fn exact_positive_f64(value: f64) -> Result<RationalQuantity> {
    let rational = exact_nonnegative_f64(value)?;
    if rational.numerator == 0 {
        return Err(EngineError::Backend(
            "GCP pricing quantity is not positive".into(),
        ));
    }
    Ok(rational)
}

fn exact_nonnegative_f64(value: f64) -> Result<RationalQuantity> {
    if !value.is_finite() || value.is_sign_negative() {
        return Err(EngineError::Backend(
            "GCP pricing number is non-finite or negative".into(),
        ));
    }
    if value == 0.0 {
        return Ok(RationalQuantity {
            numerator: 0,
            denominator: 1,
        });
    }
    let bits = value.to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);
    let (mut numerator, exponent) = if exponent_bits == 0 {
        (fraction, -1022 - 52)
    } else {
        (fraction | (1_u64 << 52), exponent_bits - 1023 - 52)
    };
    if exponent >= 0 {
        numerator = numerator
            .checked_shl(exponent.cast_unsigned())
            .ok_or_else(|| EngineError::Backend("GCP pricing number exceeds exact range".into()))?;
        return Ok(RationalQuantity {
            numerator,
            denominator: 1,
        });
    }
    let negative_exponent = (-exponent).cast_unsigned();
    let removable = numerator.trailing_zeros().min(negative_exponent);
    numerator >>= removable;
    let denominator_shift = negative_exponent - removable;
    let denominator = 1_u64.checked_shl(denominator_shift).ok_or_else(|| {
        EngineError::Backend("GCP pricing number exceeds exact rational range".into())
    })?;
    Ok(RationalQuantity {
        numerator,
        denominator,
    })
}

fn multiply_to_integer(left: RationalQuantity, right: RationalQuantity) -> Result<u64> {
    let numerator = u128::from(left.numerator)
        .checked_mul(u128::from(right.numerator))
        .ok_or_else(|| EngineError::Backend("pricing tier threshold overflowed".into()))?;
    let denominator = u128::from(left.denominator)
        .checked_mul(u128::from(right.denominator))
        .ok_or_else(|| EngineError::Backend("pricing tier threshold overflowed".into()))?;
    if numerator % denominator != 0 {
        return Err(EngineError::Backend(
            "pricing tier threshold is not an exact base-unit integer".into(),
        ));
    }
    (numerator / denominator)
        .try_into()
        .map_err(|_| EngineError::Backend("pricing tier threshold overflowed".into()))
}

const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn parse_machine_capacity(machine_type: &str) -> Result<(f64, f64)> {
    let custom = machine_type.strip_prefix("e2-custom-").ok_or_else(|| {
        EngineError::Backend("only e2 custom machine pricing is supported".into())
    })?;
    let mut parts = custom.split('-');
    let cpus: f64 = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .map(f64::from)
        .ok_or_else(|| EngineError::Backend("machine CPU count is invalid".into()))?;
    let memory_mib: f64 = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .map(f64::from)
        .ok_or_else(|| EngineError::Backend("machine memory is invalid".into()))?;
    if parts.next().is_some() {
        return Err(EngineError::Backend("machine type is invalid".into()));
    }
    Ok((cpus, memory_mib / 1024.0))
}

async fn public_a_records(domain: &str) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .build()
        .map_err(|error| EngineError::Backend(format!("DNS client failed: {error}")))?;
    let mut values: Vec<_> = doh_answers(&client, domain, "A")
        .await?
        .into_iter()
        .filter(|value| value.parse::<Ipv4Addr>().is_ok())
        .collect();
    values.sort();
    values.dedup();
    Ok(values)
}

fn ipv4_set(values: Vec<String>) -> Result<std::collections::BTreeSet<Ipv4Addr>> {
    values
        .into_iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| EngineError::Backend("DNS A record value is invalid".into()))
        })
        .collect()
}

fn service_paths(state: &DeploymentState) -> Result<ServicePaths> {
    let base = BaseDirs::new()
        .ok_or_else(|| EngineError::State("current user home is unavailable".into()))?;
    ServicePaths::new(base.home_dir(), &state.service_id).map_err(connect_error)
}

fn read_product_secrets(state: &DeploymentState) -> Result<StoredProductSecrets> {
    let paths = service_paths(state)?;
    StoredProductSecrets::read(&paths.credentials, &paths.matrix_session)
}

fn validate_stored_product(
    config: &DeploymentConfig,
    secrets: &StoredProductSecrets,
) -> Result<()> {
    let origin = format!("https://{}", config.domain);
    if secrets.origin != origin
        || secrets.owner.homeserver != origin
        || secrets.agent.homeserver != origin
        || secrets.owner.user_id != format!("@owner:{}", config.domain)
        || secrets.agent.user_id != format!("@agent:{}", config.domain)
        || !secrets.agent_room_id.starts_with('!')
        || secrets.agent_room_id.starts_with("!agent:")
        || secrets.agent_node_id.is_empty()
        || secrets.initialization_code.expose_secret().len() != 8
        || secrets.agent_token.expose_secret().is_empty()
    {
        return Err(EngineError::State(
            "stored product credentials violate the deployment identity".into(),
        ));
    }
    Ok(())
}

fn render_connect_config(
    state: &DeploymentState,
    paths: &ServicePaths,
    selection: AgentSelection,
    secrets: &StoredProductSecrets,
    host_mcp: Option<&OpenClawRegistry<ProcessHostMcpExecutor>>,
) -> Result<String> {
    let work_dir = std::env::current_dir()
        .map_err(|_| EngineError::State("current working directory is unavailable".into()))?;
    let capability = resolve_capability(selection).map_err(connect_error)?;
    let (command, args) = match selection.host_runtime {
        HostRuntime::OpenClaw => {
            let registry = host_mcp.ok_or_else(|| {
                EngineError::State("OpenClaw MCP registry boundary is unavailable".into())
            })?;
            (
                Some(path_text(registry.binary())?),
                vec![
                    "--profile".to_owned(),
                    registry.profile().to_owned(),
                    "acp".to_owned(),
                    "--session".to_owned(),
                    state.service_id.clone(),
                ],
            )
        }
        HostRuntime::Direct | HostRuntime::Hermes => (None, Vec::new()),
    };
    let config = ConnectConfig {
        data_dir: path_text(&paths.data_dir)?,
        project: ProjectConfig {
            name: state.service_id.clone(),
            selection,
            work_dir: path_text(&work_dir)?,
            command,
            args,
            matrix: ConnectMatrixSession {
                homeserver: secrets.agent.homeserver.clone(),
                access_token: secrets.agent.access_token.expose_secret().to_owned(),
                user_id: secrets.agent.user_id.clone(),
                device_id: secrets.agent.device_id.clone(),
                room_id: secrets.agent_room_id.clone(),
                admin_from: secrets.owner.user_id.clone(),
            },
            mcp: (capability == AgentCapability::Session).then(|| McpInjection {
                url: format!("{}/mcp", secrets.origin),
                server_name: "dirextalk".into(),
                agent_token: secrets.agent_token.expose_secret().to_owned(),
                node_id: secrets.agent_node_id.clone(),
            }),
        },
    };
    render_matrix_config(&config).map_err(connect_error)
}

fn host_mcp_registry(
    config: &DeploymentConfig,
    state: &DeploymentState,
    secrets: &StoredProductSecrets,
) -> Result<Option<OpenClawRegistry<ProcessHostMcpExecutor>>> {
    let selection = agent_selection(&config.connect_agent)?;
    match (
        resolve_capability(selection).map_err(connect_error)?,
        selection.host_runtime,
    ) {
        (AgentCapability::Session, HostRuntime::Direct) => Ok(None),
        (AgentCapability::HostManaged, HostRuntime::OpenClaw) => {
            let binary = executable_path("openclaw").ok_or_else(|| {
                EngineError::WaitingUser(
                    "OpenClaw is not available on PATH; install it or select another connect_agent"
                        .into(),
                )
            })?;
            let base = BaseDirs::new()
                .ok_or_else(|| EngineError::State("current user home is unavailable".into()))?;
            OpenClawRegistry::new(
                ProcessHostMcpExecutor,
                binary,
                base.home_dir(),
                state.deployment_uuid,
                [
                    secrets.owner.access_token.expose_secret().to_owned(),
                    secrets.agent.access_token.expose_secret().to_owned(),
                    secrets.agent_token.expose_secret().to_owned(),
                    secrets.initialization_code.expose_secret().to_owned(),
                ],
            )
            .map(Some)
        }
        (AgentCapability::HostManaged, HostRuntime::Hermes) => Err(EngineError::WaitingUser(
            "Hermes has no frozen unattended MCP registry contract; configure and confirm its dedicated workspace manually"
                .into(),
        )),
        (AgentCapability::HostManaged, HostRuntime::Direct) => Err(EngineError::WaitingUser(
            "the selected host-managed Agent requires an operator-confirmed dedicated workspace MCP configuration"
                .into(),
        )),
        (AgentCapability::Unsupported, _) => Err(EngineError::WaitingUser(
            "the selected local Agent does not support the required bridge".into(),
        )),
        _ => Err(EngineError::State(
            "local Agent capability and host runtime disagree".into(),
        )),
    }
}

fn connect_controller(
    config: &DeploymentConfig,
    state: &DeploymentState,
    secrets: &StoredProductSecrets,
) -> Result<(
    DaemonController<ProcessExecutor>,
    AgentCapability,
    ServicePaths,
)> {
    let paths = service_paths(state)?;
    let selection = agent_selection(&config.connect_agent)?;
    let capability = resolve_capability(selection).map_err(connect_error)?;
    let redactor = Redactor::new([
        secrets.owner.access_token.expose_secret().to_owned(),
        secrets.agent.access_token.expose_secret().to_owned(),
        secrets.agent_token.expose_secret().to_owned(),
        secrets.initialization_code.expose_secret().to_owned(),
    ]);
    let controller = DaemonController::new(
        ProcessExecutor,
        &paths.binary,
        &paths.config,
        &state.service_id,
        redactor,
    )
    .map_err(connect_error)?;
    Ok((controller, capability, paths))
}

fn agent_selection(configured: &str) -> Result<AgentSelection> {
    if configured == "openclaw" {
        return Ok(AgentSelection {
            connect_agent: ConnectAgent::Acp,
            host_runtime: HostRuntime::OpenClaw,
        });
    }
    if configured == "hermes" {
        return Ok(AgentSelection {
            connect_agent: ConnectAgent::Acp,
            host_runtime: HostRuntime::Hermes,
        });
    }
    let connect_agent = if configured == "auto" {
        let path = std::env::var_os("PATH").ok_or_else(|| {
            EngineError::WaitingUser("PATH is unavailable; select connect_agent".into())
        })?;
        let candidates = [
            ("codex", ConnectAgent::Codex, HostRuntime::Direct),
            ("claude", ConnectAgent::ClaudeCode, HostRuntime::Direct),
            ("copilot", ConnectAgent::Copilot, HostRuntime::Direct),
            ("gemini", ConnectAgent::Gemini, HostRuntime::Direct),
            ("kimi", ConnectAgent::Kimi, HostRuntime::Direct),
            ("opencode", ConnectAgent::OpenCode, HostRuntime::Direct),
            ("cursor", ConnectAgent::Cursor, HostRuntime::Direct),
            ("openclaw", ConnectAgent::Acp, HostRuntime::OpenClaw),
            ("hermes", ConnectAgent::Acp, HostRuntime::Hermes),
        ];
        let found: Vec<_> = candidates
            .into_iter()
            .filter(|(binary, _, _)| executable_path_in(&path, binary).is_some())
            .map(|(_, agent, runtime)| AgentSelection {
                connect_agent: agent,
                host_runtime: runtime,
            })
            .collect();
        match found.as_slice() {
            [selection] => return Ok(*selection),
            [] => {
                return Err(EngineError::WaitingUser(
                    "no supported local Agent was detected; set connect_agent explicitly".into(),
                ));
            }
            _ => {
                return Err(EngineError::WaitingUser(
                    "multiple local Agents were detected; set connect_agent explicitly".into(),
                ));
            }
        }
    } else {
        ConnectAgent::parse(configured).map_err(connect_error)?
    };
    Ok(AgentSelection {
        connect_agent,
        host_runtime: HostRuntime::Direct,
    })
}

fn executable_path(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| executable_path_in(&path, binary))
}

fn executable_path_in(path: &std::ffi::OsStr, binary: &str) -> Option<PathBuf> {
    std::env::split_paths(path).find_map(|directory| {
        let candidate = directory.join(binary);
        let candidate = if candidate.is_file() {
            candidate
        } else if cfg!(windows) {
            let executable = directory.join(format!("{binary}.exe"));
            if !executable.is_file() {
                return None;
            }
            executable
        } else {
            return None;
        };
        std::fs::canonicalize(candidate).ok()
    })
}

async fn verify_mcp(secrets: &StoredProductSecrets) -> Result<()> {
    let transport = HttpMcpTransport::new(
        &format!("{}/mcp", secrets.origin),
        secrets.agent_token.expose_secret().to_owned(),
    )
    .map_err(mcp_error)?;
    let client = McpClient::new(transport);
    let mut arguments = serde_json::Map::new();
    arguments.insert(
        "room_id".into(),
        Value::String(secrets.agent_room_id.clone()),
    );
    client
        .verify_read_only(&ReadOnlySmoke {
            tool_name: "dirextalk_messages_list".into(),
            arguments,
        })
        .await
        .map_err(mcp_error)?;
    Ok(())
}

async fn verify_http_product(
    config: &DeploymentConfig,
    secrets: &StoredProductSecrets,
    public_ipv4: Ipv4Addr,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .build()
        .map_err(|error| EngineError::Backend(format!("HTTPS client failed: {error}")))?;
    let origin = format!("https://{}", config.domain);
    for path in ["/_p2p/health", "/_matrix/client/versions"] {
        require_http_success(client.get(format!("{origin}{path}")), path).await?;
    }
    let well_known: Value = require_http_json(
        client.get(format!("{origin}/.well-known/matrix/server")),
        "Matrix well-known",
    )
    .await?;
    if well_known.get("m.server").and_then(Value::as_str)
        != Some(format!("{}:443", config.domain).as_str())
    {
        return Err(EngineError::Backend(
            "Matrix federation well-known is not canonical".into(),
        ));
    }
    let owner_response = client
        .get(format!("{origin}/.well-known/portal/owner.json"))
        .header(reqwest::header::ORIGIN, "http://127.0.0.1:51820")
        .send()
        .await
        .map_err(|_| EngineError::Backend("portal owner discovery failed".into()))?;
    if !owner_response.status().is_success()
        || !owner_response
            .headers()
            .get(reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "*" || value == "http://127.0.0.1:51820")
    {
        return Err(EngineError::Backend(
            "portal owner discovery or CORS validation failed".into(),
        ));
    }
    let turn: TurnCredentials = require_http_json(
        client
            .get(format!("{origin}/_matrix/client/v3/voip/turnServer"))
            .bearer_auth(secrets.owner.access_token.expose_secret()),
        "TURN credentials",
    )
    .await?;
    let expected_uris = BTreeSet::from([
        format!("turn:{}:3478?transport=tcp", config.domain),
        format!("turn:{}:3478?transport=udp", config.domain),
    ]);
    if turn.uris.len() != expected_uris.len()
        || turn.uris.iter().collect::<BTreeSet<_>>()
            != expected_uris.iter().collect::<BTreeSet<_>>()
        || turn.username.expose_secret().is_empty()
        || turn.password.expose_secret().is_empty()
        || turn.ttl == 0
    {
        return Err(EngineError::Backend(
            "Matrix TURN credentials do not match the canonical 3478 contract".into(),
        ));
    }
    verify_turn_public_path(public_ipv4).await?;
    Ok(())
}

const TURN_PORT: u16 = 3478;
const TURN_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

async fn verify_turn_public_path(public_ipv4: Ipv4Addr) -> Result<()> {
    let target = SocketAddr::new(IpAddr::V4(public_ipv4), TURN_PORT);
    timeout(TURN_PROBE_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| EngineError::Backend("TURN TCP public-path probe timed out".into()))?
        .map_err(|_| EngineError::Backend("TURN TCP public-path probe failed".into()))?;

    let mut transaction_id = [0_u8; 12];
    rand::rng().fill_bytes(&mut transaction_id);
    let request = stun_binding_request(transaction_id);
    let response = timeout(TURN_PROBE_TIMEOUT, async {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.connect(target).await?;
        socket.send(&request).await?;
        let mut response = [0_u8; 1024];
        let length = socket.recv(&mut response).await?;
        Ok::<_, std::io::Error>((response, length))
    })
    .await
    .map_err(|_| EngineError::Backend("TURN UDP STUN public-path probe timed out".into()))?
    .map_err(|_| EngineError::Backend("TURN UDP STUN public-path probe failed".into()))?;
    validate_stun_binding_response(&response.0[..response.1], transaction_id)
}

fn stun_binding_request(transaction_id: [u8; 12]) -> [u8; 20] {
    let mut request = [0_u8; 20];
    request[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..].copy_from_slice(&transaction_id);
    request
}

fn validate_stun_binding_response(response: &[u8], transaction_id: [u8; 12]) -> Result<()> {
    if response.len() < 20
        || u16::from_be_bytes([response[0], response[1]]) != STUN_BINDING_SUCCESS
        || u32::from_be_bytes([response[4], response[5], response[6], response[7]])
            != STUN_MAGIC_COOKIE
        || response[8..20] != transaction_id
    {
        return Err(EngineError::Backend(
            "TURN UDP public-path probe returned an invalid STUN response".into(),
        ));
    }
    let message_length = usize::from(u16::from_be_bytes([response[2], response[3]]));
    if message_length % 4 != 0 || response.len() != 20 + message_length {
        return Err(EngineError::Backend(
            "TURN UDP public-path probe returned an invalid STUN response".into(),
        ));
    }
    let mut offset = 20;
    let mut has_mapped_address = false;
    while offset < response.len() {
        if response.len() - offset < 4 {
            return Err(EngineError::Backend(
                "TURN UDP public-path probe returned an invalid STUN response".into(),
            ));
        }
        let attribute_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attribute_length = usize::from(u16::from_be_bytes([
            response[offset + 2],
            response[offset + 3],
        ]));
        let padded_length = attribute_length
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or_else(|| {
                EngineError::Backend(
                    "TURN UDP public-path probe returned an invalid STUN response".into(),
                )
            })?;
        offset = offset
            .checked_add(4 + padded_length)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| {
                EngineError::Backend(
                    "TURN UDP public-path probe returned an invalid STUN response".into(),
                )
            })?;
        if matches!(attribute_type, 0x0001 | 0x0020) && attribute_length >= 8 {
            has_mapped_address = true;
        }
    }
    if !has_mapped_address {
        return Err(EngineError::Backend(
            "TURN UDP public-path probe returned no mapped address".into(),
        ));
    }
    Ok(())
}

async fn require_http_success(request: reqwest::RequestBuilder, name: &str) -> Result<()> {
    let response = request
        .send()
        .await
        .map_err(|_| EngineError::Backend(format!("{name} request failed")))?;
    if !response.status().is_success() {
        return Err(EngineError::Backend(format!(
            "{name} returned HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

async fn require_http_json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
    name: &str,
) -> Result<T> {
    let response = request
        .send()
        .await
        .map_err(|_| EngineError::Backend(format!("{name} request failed")))?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > 1024 * 1024)
    {
        return Err(EngineError::Backend(format!(
            "{name} returned an invalid HTTP response"
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| EngineError::Backend(format!("{name} response could not be read")))?;
    if bytes.len() > 1024 * 1024 {
        return Err(EngineError::Backend(format!(
            "{name} response exceeded its size limit"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| EngineError::Backend(format!("{name} response is invalid")))
}

async fn prove_server_dns(
    transport: &mut SshClient,
    config: &DeploymentConfig,
    state: &DeploymentState,
) -> Result<()> {
    let authoritative_server = authoritative_server(&config.domain).await?;
    let request = DnsProofRequest {
        name: DnsName::parse(&config.domain).map_err(transport_error)?,
        expected_ipv4: public_ipv4(state)?,
        authoritative_server,
        public_recursive_resolver: "8.8.8.8".parse().expect("fixed public recursive resolver"),
    };
    transport.prove_dns(&request).map_err(transport_error)?;
    Ok(())
}

async fn authoritative_server(domain: &str) -> Result<IpAddr> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .build()
        .map_err(|error| EngineError::Backend(format!("DNS client failed: {error}")))?;
    let labels: Vec<_> = domain.split('.').collect();
    for offset in 0..labels.len().saturating_sub(1) {
        let candidate = labels[offset..].join(".");
        let ns = doh_answers(&client, &candidate, "NS").await?;
        if let Some(name) = ns.first() {
            let addresses = doh_answers(&client, name.trim_end_matches('.'), "A").await?;
            if let Some(address) = addresses
                .into_iter()
                .find_map(|value| value.parse::<Ipv4Addr>().ok())
            {
                return Ok(IpAddr::V4(address));
            }
        }
    }
    Err(EngineError::Backend(
        "public authoritative DNS server could not be resolved".into(),
    ))
}

async fn doh_answers(client: &reqwest::Client, name: &str, kind: &str) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct DnsResponse {
        #[serde(rename = "Status")]
        status: u32,
        #[serde(default, rename = "Answer")]
        answer: Vec<DnsAnswer>,
    }
    #[derive(Deserialize)]
    struct DnsAnswer {
        data: String,
    }
    let response: DnsResponse = client
        .get("https://dns.google/resolve")
        .query(&[("name", name), ("type", kind)])
        .send()
        .await
        .map_err(|_| EngineError::Backend("public DNS lookup failed".into()))?
        .error_for_status()
        .map_err(|error| EngineError::Backend(format!("public DNS lookup returned {error}")))?
        .json()
        .await
        .map_err(|_| EngineError::Backend("public DNS response is invalid".into()))?;
    if response.status != 0 && response.status != 3 {
        return Err(EngineError::Backend(format!(
            "public DNS lookup returned status {}",
            response.status
        )));
    }
    Ok(response
        .answer
        .into_iter()
        .map(|answer| answer.data)
        .collect())
}

fn require_remote_success(
    transport: &mut SshClient,
    command: &FixedRemoteCommand,
    name: &str,
) -> Result<()> {
    let output = transport.execute(command).map_err(transport_error)?;
    if output.exit_status != 0 {
        return Err(EngineError::Backend(format!(
            "remote {name} verification exited with status {}",
            output.exit_status
        )));
    }
    Ok(())
}

fn public_ipv4(state: &DeploymentState) -> Result<Ipv4Addr> {
    state
        .gcp_resources
        .address
        .as_ref()
        .and_then(|address| address.observed_attributes.get("address"))
        .ok_or_else(|| EngineError::Backend("static address receipt is incomplete".into()))?
        .parse()
        .map_err(|_| EngineError::Backend("static address receipt is invalid".into()))
}

fn ssh_private_key_path(state: &DeploymentState) -> Result<PathBuf> {
    Ok(service_paths(state)?.root.join("ssh-ed25519"))
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| EngineError::State("local path is not valid Unicode".into()))
}

fn now_unix_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EngineError::State("system clock is before the Unix epoch".into()))?
        .as_millis();
    u64::try_from(millis).map_err(|_| EngineError::State("system clock overflowed".into()))
}

fn account_generation(deployment_uuid: uuid::Uuid) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&deployment_uuid.as_bytes()[..8]);
    (u64::from_be_bytes(bytes) & i64::MAX as u64).max(1)
}

fn core_host_key_algorithm(algorithm: HostKeyAlgorithm) -> Result<SshHostKeyAlgorithm> {
    match algorithm {
        HostKeyAlgorithm::Rsa => Ok(SshHostKeyAlgorithm::Rsa),
        HostKeyAlgorithm::Ecdsa256 => Ok(SshHostKeyAlgorithm::Ecdsa256),
        HostKeyAlgorithm::Ecdsa384 => Ok(SshHostKeyAlgorithm::Ecdsa384),
        HostKeyAlgorithm::Ecdsa521 => Ok(SshHostKeyAlgorithm::Ecdsa521),
        HostKeyAlgorithm::Ed25519 => Ok(SshHostKeyAlgorithm::Ed25519),
        HostKeyAlgorithm::Dss | HostKeyAlgorithm::Unknown => Err(EngineError::Backend(
            "observed SSH host key algorithm is unsupported".into(),
        )),
    }
}

fn ssh_identity(address: Ipv4Addr, pin: &HostKeyPin) -> Result<deployer_core::SshHostIdentity> {
    Ok(deployer_core::SshHostIdentity {
        address,
        algorithm: core_host_key_algorithm(pin.algorithm)?,
        fingerprint_sha256: SshSha256Fingerprint::parse(format!("SHA256:{}", pin.sha256))?,
    })
}

fn host_pin(identity: &deployer_core::SshHostIdentity, address: Ipv4Addr) -> Result<HostKeyPin> {
    if identity.address != address {
        return Err(EngineError::State(
            "persisted SSH host pin address changed".into(),
        ));
    }
    Ok(HostKeyPin {
        algorithm: transport_host_key_algorithm(identity.algorithm),
        sha256: Sha256Digest::parse(
            identity
                .fingerprint_sha256
                .as_str()
                .strip_prefix("SHA256:")
                .ok_or_else(|| EngineError::State("SSH host pin is invalid".into()))?,
        )
        .map_err(transport_error)?,
    })
}

const fn transport_host_key_algorithm(value: SshHostKeyAlgorithm) -> HostKeyAlgorithm {
    match value {
        SshHostKeyAlgorithm::Rsa => HostKeyAlgorithm::Rsa,
        SshHostKeyAlgorithm::Ecdsa256 => HostKeyAlgorithm::Ecdsa256,
        SshHostKeyAlgorithm::Ecdsa384 => HostKeyAlgorithm::Ecdsa384,
        SshHostKeyAlgorithm::Ecdsa521 => HostKeyAlgorithm::Ecdsa521,
        SshHostKeyAlgorithm::Ed25519 => HostKeyAlgorithm::Ed25519,
    }
}

const fn daemon_name(state: DaemonState) -> &'static str {
    match state {
        DaemonState::Running => "running",
        DaemonState::Stopped => "stopped",
        DaemonState::NotInstalled => "not_installed",
        DaemonState::Failed => "failed",
    }
}

struct InteractivePassphraseProvider;

impl PassphraseProvider for InteractivePassphraseProvider {
    fn passphrase(&self) -> deployer_gcp::Result<SecretString> {
        if let Ok(passphrase) = std::env::var("DIREXTALK_GCP_CREDENTIAL_PASSPHRASE") {
            return Ok(SecretString::from(passphrase));
        }
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(deployer_gcp::GcpError::CredentialStorage(
                "encrypted OAuth fallback needs a hidden terminal passphrase prompt".into(),
            ));
        }
        let passphrase = rpassword::prompt_password(
            "Encrypted OAuth fallback passphrase (minimum 16 characters): ",
        )
        .map_err(|_| {
            deployer_gcp::GcpError::CredentialStorage(
                "hidden OAuth fallback passphrase prompt failed".into(),
            )
        })?;
        Ok(SecretString::from(passphrase))
    }
}

#[allow(clippy::needless_pass_by_value)]
fn gcp_error(error: deployer_gcp::GcpError) -> EngineError {
    if matches!(error, deployer_gcp::GcpError::CredentialStorage(_))
        && error.to_string().contains("passphrase")
    {
        EngineError::WaitingUser(error.to_string())
    } else {
        EngineError::Backend(error.to_string())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn host_error(error: deployer_host::InstallError) -> EngineError {
    EngineError::Backend(format!("host install contract failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
fn transport_error(error: deployer_transport::TransportError) -> EngineError {
    EngineError::Backend(format!("verified host transport failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
fn connect_error(error: deployer_connect::ConnectError) -> EngineError {
    EngineError::Backend(format!("local bridge failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
fn release_error(error: deployer_connect::ReleaseError) -> EngineError {
    EngineError::Backend(format!("connect release failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
fn mcp_error(error: deployer_connect::McpError) -> EngineError {
    EngineError::Backend(format!("read-only MCP verification failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_success(transaction_id: [u8; 12]) -> Vec<u8> {
        let mut response = vec![0_u8; 32];
        response[..2].copy_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
        response[22..24].copy_from_slice(&8_u16.to_be_bytes());
        response[25] = 1;
        response
    }

    #[test]
    fn stun_request_binds_the_transaction_to_rfc_5389() {
        let transaction_id = [7_u8; 12];
        let request = stun_binding_request(transaction_id);

        assert_eq!(&request[..2], &STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[2..4], &[0, 0]);
        assert_eq!(&request[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request[8..], &transaction_id);
    }

    #[test]
    fn stun_response_requires_success_transaction_and_mapped_address() {
        let transaction_id = [9_u8; 12];
        assert!(
            validate_stun_binding_response(&binding_success(transaction_id), transaction_id)
                .is_ok()
        );

        let wrong_transaction = [8_u8; 12];
        assert!(
            validate_stun_binding_response(&binding_success(wrong_transaction), transaction_id)
                .is_err()
        );

        let mut no_mapped_address = binding_success(transaction_id);
        no_mapped_address[20..22].copy_from_slice(&0x8022_u16.to_be_bytes());
        assert!(validate_stun_binding_response(&no_mapped_address, transaction_id).is_err());
    }

    #[test]
    fn explicit_host_runtimes_use_acp_and_unknown_agents_fail_closed() {
        assert_eq!(
            agent_selection("openclaw").unwrap(),
            AgentSelection {
                connect_agent: ConnectAgent::Acp,
                host_runtime: HostRuntime::OpenClaw,
            }
        );
        assert_eq!(
            agent_selection("hermes").unwrap(),
            AgentSelection {
                connect_agent: ConnectAgent::Acp,
                host_runtime: HostRuntime::Hermes,
            }
        );
        assert!(agent_selection("unknown-agent").is_err());
    }
}
