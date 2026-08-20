#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use deployer_core::{DeploymentConfig, DeploymentPlan, StateStore, service_id};
use directories::BaseDirs;

use crate::application::StoreFactory;
use crate::engine::{EngineError, Result};

#[derive(Clone, Debug)]
pub struct FilesystemStores {
    nodes_root: PathBuf,
}

impl FilesystemStores {
    pub fn for_current_user() -> Result<Self> {
        let base = BaseDirs::new()
            .ok_or_else(|| EngineError::State("current user home is unavailable".into()))?;
        Ok(Self::new(base.home_dir().join(".dirextalk/nodes")))
    }

    pub fn new(nodes_root: impl Into<PathBuf>) -> Self {
        Self {
            nodes_root: nodes_root.into(),
        }
    }

    #[must_use]
    pub fn nodes_root(&self) -> &Path {
        &self.nodes_root
    }
}

impl StoreFactory for FilesystemStores {
    type Store = StateStore;

    fn open_for_plan(&self, plan: &DeploymentPlan) -> Result<Self::Store> {
        let id = service_id(
            &plan.spec.deployment_name,
            plan.project_identity.project_number,
        )?;
        StateStore::open(&self.nodes_root, &id).map_err(EngineError::from)
    }

    fn open_for_config(&self, config: &DeploymentConfig) -> Result<Self::Store> {
        self.find_for_config(config)?
            .ok_or(EngineError::MissingState)
    }

    fn find_for_config(&self, config: &DeploymentConfig) -> Result<Option<Self::Store>> {
        let entries = match std::fs::read_dir(&self.nodes_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(EngineError::State(
                    "deployment nodes directory could not be read".into(),
                ));
            }
        };
        let prefix = format!("{}-", config.deployment_name);
        let mut match_id = None;
        for entry in entries {
            let entry = entry
                .map_err(|_| EngineError::State("deployment node could not be inspected".into()))?;
            let file_type = entry
                .file_type()
                .map_err(|_| EngineError::State("deployment node type could not be read".into()))?;
            let Some(candidate) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !file_type.is_dir() || !candidate.starts_with(&prefix) {
                continue;
            }
            let store = StateStore::open(&self.nodes_root, &candidate)?;
            let Some(state) = store.read()? else { continue };
            if state.project_identity.project_id == config.project_id
                && match_id.replace(candidate).is_some()
            {
                return Err(EngineError::State(
                    "multiple deployment states match this configuration".into(),
                ));
            }
        }
        match match_id {
            Some(id) => StateStore::open(&self.nodes_root, &id)
                .map(Some)
                .map_err(EngineError::from),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use deployer_core::{
        DeploymentPhase, DeploymentState, GcpResources, LocalWiringStatus, ProjectIdentity,
        canonical_plan_digest,
    };
    use uuid::Uuid;

    use super::*;

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

    #[test]
    fn finds_state_without_cloud_access() {
        let temporary = tempfile::tempdir().expect("temporary");
        let factory = FilesystemStores::new(temporary.path());
        let id = service_id("production", 42).expect("service id");
        let store = StateStore::open(temporary.path(), &id).expect("store");
        let approved = canonical_plan_digest(&serde_json::json!({"plan": "test"})).expect("digest");
        store
            .write(&DeploymentState {
                schema_version: 1,
                deployment_uuid: Uuid::new_v4(),
                service_id: id,
                project_identity: ProjectIdentity {
                    project_id: "dirextalk-prod".into(),
                    project_number: 42,
                    oauth_principal: deployer_core::GoogleSubject::parse("operator-123")
                        .expect("subject"),
                },
                approved_plan_digest: Some(approved),
                phase: DeploymentPhase::Failed,
                pending_effect: None,
                active_destroy: None,
                release_identity: Some(test_release_identity()),
                gcp_resources: GcpResources::default(),
                ssh_host_identity: None,
                host_receipt: None,
                local_wiring: LocalWiringStatus::default(),
                integrity_digest: String::new(),
            })
            .expect("write");
        drop(store);

        let reopened = factory.open_for_config(&config()).expect("found");
        assert_eq!(
            reopened
                .read()
                .expect("read")
                .expect("state")
                .project_identity
                .project_number,
            42
        );
    }

    fn test_release_identity() -> deployer_core::ExactReleaseIdentity {
        let sha = |character: char| {
            deployer_core::Sha256Digest::parse(character.to_string().repeat(64)).unwrap()
        };
        let revision = |character: char| {
            deployer_core::SourceRevision::parse(character.to_string().repeat(40)).unwrap()
        };
        deployer_core::ExactReleaseIdentity {
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
}
