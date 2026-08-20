//! Strict, one-shot host installation protocol and Linux implementation.
#![allow(clippy::missing_errors_doc)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const REQUEST_PATH: &str = "/var/tmp/dirextalk-install-request.json";
pub const BUNDLE_PATH: &str = "/var/tmp/dirextalk-release-bundle.tar";
pub const RECEIPT_KEY_PATH: &str = "/var/tmp/dirextalk-receipt.key";
pub const RECEIPT_PATH: &str = "/var/lib/dirextalk/install-receipt.json";
pub const POSTGRES_UTILITY_DIGEST: &str =
    "691673308c99d2161ba298736f3147f1f22d79de2fb7ec93ae9b4afcab870b62";
pub const CADDY_DIGEST: &str = "844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9";
pub const COTURN_DIGEST: &str = "e2bca2f79a4269d7240de5872ab60a9305013ad37296d2acf14f9510874346be";

pub const MAX_RELEASE_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_INSTALL_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RECEIPT_KEY_BYTES: usize = 4 * 1024;
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const RUNTIME_ROOT: &str = "/var/dirextalk-message-server";
const COMPOSE_PATH: &str = "/var/dirextalk-message-server/docker-compose.yml";
const COMPOSE_PROJECT: &str = "dirextalk-p2p";
const UPDATER_CONFIG: &[u8] = br#"{"schema_version":1,"state_dir":"/var/lib/dirextalk-updater","socket_path":"/run/dirextalk-updater/http.sock","control_token_file":"/etc/dirextalk-updater/control-token","caddy_mode":"compose","compose_project":"dirextalk-p2p","watchdog_enabled":false}"#;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub schema_version: u32,
    pub deployment_uuid: Uuid,
    pub service_id: String,
    pub release: String,
    pub target: HostTarget,
    pub bundle_sha256: DigestHex,
    pub manifest_sha256: DigestHex,
    pub release_signing_public_key: PublicKeyHex,
    pub receipt_key_sha256: DigestHex,
    pub domain: String,
    pub public_ipv4: Ipv4Addr,
    pub region: String,
    pub release_catalog_origin: String,
    pub account_generation: u64,
    pub authoritative_dns_ipv4: Ipv4Addr,
    pub public_recursive_dns_ipv4: Ipv4Addr,
    pub updater: UpdaterIdentity,
}

impl InstallRequest {
    pub fn validate(&self) -> Result<(), InstallError> {
        if self.schema_version != 1 {
            return Err(InstallError::InvalidRequest("schema_version must be 1"));
        }
        validate_slug(&self.service_id, "service_id")?;
        validate_release(&self.release)?;
        if self.target != HostTarget::LinuxAmd64 {
            return Err(InstallError::InvalidRequest("target must be linux_amd64"));
        }
        validate_dns_name(&self.domain)?;
        if !is_public_ipv4(self.public_ipv4) {
            return Err(InstallError::InvalidRequest("public_ipv4"));
        }
        validate_region(&self.region)?;
        validate_https_origin(&self.release_catalog_origin)?;
        if self.account_generation == 0 || self.account_generation > i64::MAX as u64 {
            return Err(InstallError::InvalidRequest("account_generation"));
        }
        if self.authoritative_dns_ipv4 == self.public_recursive_dns_ipv4
            || !is_public_ipv4(self.authoritative_dns_ipv4)
            || !is_public_ipv4(self.public_recursive_dns_ipv4)
        {
            return Err(InstallError::InvalidRequest("dns proof policy"));
        }
        self.updater.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTarget {
    LinuxAmd64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DigestHex(String);

impl DigestHex {
    pub fn parse(value: impl Into<String>) -> Result<Self, InstallError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InstallError::InvalidDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn calculate(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for DigestHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DigestHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyHex(String);

impl PublicKeyHex {
    pub fn parse(value: impl Into<String>) -> Result<Self, InstallError> {
        let value = value.into();
        decode_hex_array::<32>(&value).map(|_| Self(value))
    }

    #[must_use]
    pub fn from_key(key: &VerifyingKey) -> Self {
        Self(hex::encode(key.as_bytes()))
    }

    fn key(&self) -> Result<VerifyingKey, InstallError> {
        VerifyingKey::from_bytes(&decode_hex_array(&self.0)?)
            .map_err(|_| InstallError::InvalidReleasePublicKey)
    }
}

impl Serialize for PublicKeyHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PublicKeyHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureHex(String);

impl SignatureHex {
    fn parse(value: impl Into<String>) -> Result<Self, InstallError> {
        let value = value.into();
        decode_hex_array::<64>(&value).map(|_| Self(value))
    }

    fn signature(&self) -> Result<Signature, InstallError> {
        Ok(Signature::from_bytes(&decode_hex_array(&self.0)?))
    }
}

impl Serialize for SignatureHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBundleManifest {
    pub manifest: BundleManifest,
    pub ed25519_signature: SignatureHex,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub release: String,
    pub target: HostTarget,
    pub images: Vec<ImageReference>,
    pub updater: UpdaterIdentity,
    pub files: Vec<BundleFile>,
}

impl BundleManifest {
    fn validate(&self, request: &InstallRequest) -> Result<(), InstallError> {
        if self.schema_version != 1
            || self.release != request.release
            || self.target != request.target
        {
            return Err(InstallError::ManifestMismatch);
        }
        let expected = BundleRole::required();
        if self.files.len() != expected.len()
            || self
                .files
                .iter()
                .zip(expected)
                .any(|(file, role)| file.role != *role || file.mode != role.mode())
        {
            return Err(InstallError::NonCanonicalTopology);
        }
        let updater_file = self
            .files
            .iter()
            .find(|file| file.role == BundleRole::UpdaterBinary)
            .ok_or(InstallError::NonCanonicalTopology)?;
        self.updater.validate()?;
        if self.updater != request.updater {
            return Err(InstallError::UpdaterIdentityMismatch);
        }
        if updater_file.sha256 != self.updater.sha256 {
            return Err(InstallError::UpdaterIdentityMismatch);
        }
        let expected_images = ImageRole::required();
        if self.images.len() != expected_images.len()
            || self
                .images
                .iter()
                .zip(expected_images)
                .any(|(image, role)| image.role != *role || image.validate(&self.release).is_err())
        {
            return Err(InstallError::NonCanonicalImages);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdaterIdentity {
    pub version: String,
    pub source_url: String,
    pub sha256: DigestHex,
}

impl UpdaterIdentity {
    fn validate(&self) -> Result<(), InstallError> {
        if !valid_product_version(&self.version)
            || self.source_url.len() > 2048
            || !self.source_url.starts_with("https://")
            || self.source_url.contains('@')
            || self.source_url.chars().any(char::is_whitespace)
        {
            return Err(InstallError::InvalidUpdaterIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub role: BundleRole,
    pub sha256: DigestHex,
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleRole {
    ComposeFile,
    Caddyfile,
    MessageServerInitializer,
    AgentSecretMaterializer,
    MessageServerEntrypoint,
    CapabilityCaInitializer,
    PostgresEntrypoint,
    PostgresInitializer,
    UpdaterBinary,
    UpdaterUnit,
}

impl BundleRole {
    const REQUIRED: [Self; 10] = [
        Self::ComposeFile,
        Self::Caddyfile,
        Self::MessageServerInitializer,
        Self::AgentSecretMaterializer,
        Self::MessageServerEntrypoint,
        Self::CapabilityCaInitializer,
        Self::PostgresEntrypoint,
        Self::PostgresInitializer,
        Self::UpdaterBinary,
        Self::UpdaterUnit,
    ];

    #[must_use]
    pub const fn required() -> &'static [Self] {
        &Self::REQUIRED
    }

    #[must_use]
    pub const fn archive_path(self) -> &'static str {
        match self {
            Self::ComposeFile => "runtime/docker-compose.yml",
            Self::Caddyfile => "runtime/Caddyfile",
            Self::MessageServerInitializer => "runtime/initialize-message-server.sh",
            Self::AgentSecretMaterializer => "runtime/materialize-agent-secrets.sh",
            Self::MessageServerEntrypoint => "runtime/message-server-entrypoint.sh",
            Self::CapabilityCaInitializer => "runtime/initialize-capability-ca.sh",
            Self::PostgresEntrypoint => "runtime/postgres-entrypoint.sh",
            Self::PostgresInitializer => "runtime/initialize-postgres.sh",
            Self::UpdaterBinary => "updater/dirextalk-updater",
            Self::UpdaterUnit => "updater/dirextalk-updater.service",
        }
    }

    const fn mode(self) -> u32 {
        match self {
            Self::UpdaterBinary => 0o755,
            Self::MessageServerInitializer
            | Self::AgentSecretMaterializer
            | Self::MessageServerEntrypoint
            | Self::CapabilityCaInitializer
            | Self::PostgresEntrypoint
            | Self::PostgresInitializer => 0o555,
            Self::Caddyfile => 0o444,
            _ => 0o644,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRole {
    Postgres,
    Utility,
    MessageServer,
    Agent,
    Caddy,
    Coturn,
}

impl ImageRole {
    const REQUIRED: [Self; 6] = [
        Self::Postgres,
        Self::Utility,
        Self::MessageServer,
        Self::Agent,
        Self::Caddy,
        Self::Coturn,
    ];

    #[must_use]
    pub const fn required() -> &'static [Self] {
        &Self::REQUIRED
    }

    #[must_use]
    pub const fn allowed_repository(self) -> &'static str {
        match self {
            Self::Postgres | Self::Utility => "docker.io/pgvector/pgvector",
            Self::MessageServer => "docker.io/dirextalk/message-server",
            Self::Agent => "docker.io/dirextalk/agent",
            Self::Caddy => "docker.io/library/caddy",
            Self::Coturn => "docker.io/coturn/coturn",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageReference {
    pub role: ImageRole,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: DigestHex,
    pub source_revision: Option<String>,
}

impl ImageReference {
    fn validate(&self, _release: &str) -> Result<(), InstallError> {
        self.validate_repository_and_tag()
    }

    fn digest_reference(&self) -> String {
        self.tag.as_ref().map_or_else(
            || format!("{}@sha256:{}", self.repository, self.digest.as_str()),
            |tag| {
                format!(
                    "{}:{}@sha256:{}",
                    self.repository,
                    tag,
                    self.digest.as_str()
                )
            },
        )
    }

    fn validate_repository_and_tag(&self) -> Result<(), InstallError> {
        if self.repository != self.role.allowed_repository() {
            return Err(InstallError::InvalidImageReference(self.role));
        }
        match self.role {
            ImageRole::MessageServer | ImageRole::Agent => {
                if !self.tag.as_deref().is_some_and(valid_product_version)
                    || !self
                        .source_revision
                        .as_deref()
                        .is_some_and(valid_source_revision)
                {
                    return Err(InstallError::InvalidImageReference(self.role));
                }
            }
            ImageRole::Postgres | ImageRole::Utility => {
                if self.source_revision.is_some()
                    || self.tag.as_deref() != Some("pg18")
                    || self.digest.as_str() != POSTGRES_UTILITY_DIGEST
                {
                    return Err(InstallError::ThirdPartyImagePinMismatch(self.role));
                }
            }
            ImageRole::Caddy => {
                if self.source_revision.is_some()
                    || self.tag.is_some()
                    || self.digest.as_str() != CADDY_DIGEST
                {
                    return Err(InstallError::ThirdPartyImagePinMismatch(self.role));
                }
            }
            ImageRole::Coturn => {
                if self.source_revision.is_some()
                    || self.tag.as_deref() != Some("4.6.3-alpine")
                    || self.digest.as_str() != COTURN_DIGEST
                {
                    return Err(InstallError::ThirdPartyImagePinMismatch(self.role));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformInfo {
    pub os_id: String,
    pub version_id: String,
    pub architecture: String,
    pub systemd_version: u32,
}

impl PlatformInfo {
    fn validate(&self) -> Result<(), InstallError> {
        if self.os_id != "ubuntu"
            || self.version_id != "24.04"
            || self.architecture != "x86_64"
            || self.systemd_version < 254
        {
            return Err(InstallError::UnsupportedPlatform(self.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedStep {
    InstallDocker,
    PullPostgresImage,
    PullUtilityImage,
    PullMessageServerImage,
    PullAgentImage,
    PullCaddyImage,
    PullCoturnImage,
    InstallComposeFile,
    InstallCaddyfile,
    InstallMessageServerInitializer,
    InstallAgentSecretMaterializer,
    InstallMessageServerEntrypoint,
    InstallCapabilityCaInitializer,
    InstallPostgresEntrypoint,
    InstallPostgresInitializer,
    InstallUpdaterBinary,
    InstallUpdaterConfig,
    InstallUpdaterControlToken,
    InstallUpdaterUnit,
    MaterializeRuntime,
    ValidateCompose,
    StartMessageServer,
    RefreshAgentToken,
    StartAgent,
    VerifyDns,
    StartCaddy,
    VerifyRuntime,
    VerifyHttps,
    VerifyTurn,
    VerifyUpdater,
}

impl FixedStep {
    const ALL: [Self; 30] = [
        Self::InstallDocker,
        Self::PullPostgresImage,
        Self::PullUtilityImage,
        Self::PullMessageServerImage,
        Self::PullAgentImage,
        Self::PullCaddyImage,
        Self::PullCoturnImage,
        Self::InstallComposeFile,
        Self::InstallCaddyfile,
        Self::InstallMessageServerInitializer,
        Self::InstallAgentSecretMaterializer,
        Self::InstallMessageServerEntrypoint,
        Self::InstallCapabilityCaInitializer,
        Self::InstallPostgresEntrypoint,
        Self::InstallPostgresInitializer,
        Self::InstallUpdaterBinary,
        Self::InstallUpdaterConfig,
        Self::InstallUpdaterControlToken,
        Self::InstallUpdaterUnit,
        Self::MaterializeRuntime,
        Self::ValidateCompose,
        Self::StartMessageServer,
        Self::RefreshAgentToken,
        Self::StartAgent,
        Self::VerifyDns,
        Self::StartCaddy,
        Self::VerifyRuntime,
        Self::VerifyHttps,
        Self::VerifyTurn,
        Self::VerifyUpdater,
    ];

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &Self::ALL
    }

    const fn bundle_role(self) -> Option<BundleRole> {
        match self {
            Self::InstallComposeFile => Some(BundleRole::ComposeFile),
            Self::InstallCaddyfile => Some(BundleRole::Caddyfile),
            Self::InstallMessageServerInitializer => Some(BundleRole::MessageServerInitializer),
            Self::InstallAgentSecretMaterializer => Some(BundleRole::AgentSecretMaterializer),
            Self::InstallMessageServerEntrypoint => Some(BundleRole::MessageServerEntrypoint),
            Self::InstallCapabilityCaInitializer => Some(BundleRole::CapabilityCaInitializer),
            Self::InstallPostgresEntrypoint => Some(BundleRole::PostgresEntrypoint),
            Self::InstallPostgresInitializer => Some(BundleRole::PostgresInitializer),
            Self::InstallUpdaterBinary => Some(BundleRole::UpdaterBinary),
            Self::InstallUpdaterUnit => Some(BundleRole::UpdaterUnit),
            _ => None,
        }
    }

    const fn image_role(self) -> Option<ImageRole> {
        match self {
            Self::PullPostgresImage => Some(ImageRole::Postgres),
            Self::PullUtilityImage => Some(ImageRole::Utility),
            Self::PullMessageServerImage => Some(ImageRole::MessageServer),
            Self::PullAgentImage => Some(ImageRole::Agent),
            Self::PullCaddyImage => Some(ImageRole::Caddy),
            Self::PullCoturnImage => Some(ImageRole::Coturn),
            _ => None,
        }
    }

    const fn uses_runtime(self) -> bool {
        matches!(
            self,
            Self::MaterializeRuntime
                | Self::ValidateCompose
                | Self::StartMessageServer
                | Self::RefreshAgentToken
                | Self::StartAgent
                | Self::VerifyDns
                | Self::StartCaddy
                | Self::VerifyRuntime
                | Self::VerifyHttps
                | Self::VerifyTurn
                | Self::VerifyUpdater
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StepInput<'a> {
    None,
    Artifact(&'a [u8]),
    Image(&'a ImageReference),
    Runtime(RuntimeSpec<'a>),
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimeSpec<'a> {
    pub request: &'a InstallRequest,
    pub images: &'a BTreeMap<ImageRole, ImageReference>,
}

impl<'a> StepInput<'a> {
    fn artifact(self) -> Result<&'a [u8], BackendError> {
        match self {
            Self::Artifact(bytes) => Ok(bytes),
            _ => Err(BackendError::Infrastructure(
                "fixed step received the wrong input type".into(),
            )),
        }
    }

    fn image(self) -> Result<&'a ImageReference, BackendError> {
        match self {
            Self::Image(image) => Ok(image),
            _ => Err(BackendError::Infrastructure(
                "fixed step received the wrong input type".into(),
            )),
        }
    }

    fn runtime(self) -> Result<RuntimeSpec<'a>, BackendError> {
        match self {
            Self::Runtime(runtime) => Ok(runtime),
            _ => Err(BackendError::Infrastructure(
                "fixed step received the wrong input type".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudWorkerStatus {
    DisabledByProductScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReceipt {
    pub schema_version: u32,
    pub deployment_uuid: Uuid,
    pub service_id: String,
    pub release: String,
    pub request_sha256: DigestHex,
    pub bundle_sha256: DigestHex,
    pub manifest_sha256: DigestHex,
    pub domain: String,
    pub public_ipv4: Ipv4Addr,
    pub region: String,
    pub account_generation: u64,
    pub updater: UpdaterIdentity,
    pub platform: PlatformInfo,
    pub completed_steps: Vec<FixedStep>,
    pub cloud_worker: CloudWorkerStatus,
    pub runtime_status: RuntimeStatus,
    pub completed_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    RuntimeHealthy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub receipt: InstallReceipt,
    pub hmac_sha256: DigestHex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum InstallOutcome {
    Success(SignedReceipt),
    WaitingUser { reason: String },
    Failure { error: InstallFailure },
}

impl InstallOutcome {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Success(_) => 0,
            Self::WaitingUser { .. } => 2,
            Self::Failure { .. } => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallFailure {
    pub kind: FailureKind,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Contract,
    Infrastructure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendError {
    WaitingUser(String),
    Infrastructure(String),
}

pub trait InstallBackend {
    fn platform(&mut self) -> Result<PlatformInfo, BackendError>;
    fn read_receipt(&mut self) -> Result<Option<Vec<u8>>, BackendError>;
    fn apply_step(&mut self, step: FixedStep, input: StepInput<'_>) -> Result<(), BackendError>;
    fn write_receipt(&mut self, canonical_receipt: &[u8]) -> Result<(), BackendError>;
}

/// A deterministic, non-mutating backend for plans and caller-owned tests.
#[derive(Clone, Debug)]
pub struct RecordingBackend {
    pub platform: PlatformInfo,
    pub existing_receipt: Option<Vec<u8>>,
    pub recorded_steps: Vec<FixedStep>,
    pub written_receipt: Option<Vec<u8>>,
    pub next_error: Option<BackendError>,
}

impl RecordingBackend {
    #[must_use]
    pub fn supported() -> Self {
        Self {
            platform: PlatformInfo {
                os_id: "ubuntu".into(),
                version_id: "24.04".into(),
                architecture: "x86_64".into(),
                systemd_version: 254,
            },
            existing_receipt: None,
            recorded_steps: Vec::new(),
            written_receipt: None,
            next_error: None,
        }
    }

    fn take_error(&mut self) -> Result<(), BackendError> {
        self.next_error.take().map_or(Ok(()), Err)
    }
}

impl InstallBackend for RecordingBackend {
    fn platform(&mut self) -> Result<PlatformInfo, BackendError> {
        self.take_error()?;
        Ok(self.platform.clone())
    }

    fn read_receipt(&mut self) -> Result<Option<Vec<u8>>, BackendError> {
        self.take_error()?;
        Ok(self.existing_receipt.clone())
    }

    fn apply_step(&mut self, step: FixedStep, _input: StepInput<'_>) -> Result<(), BackendError> {
        self.take_error()?;
        self.recorded_steps.push(step);
        Ok(())
    }

    fn write_receipt(&mut self, canonical_receipt: &[u8]) -> Result<(), BackendError> {
        self.take_error()?;
        self.written_receipt = Some(canonical_receipt.to_vec());
        Ok(())
    }
}

pub struct Installer<B> {
    backend: B,
}

impl<B: InstallBackend> Installer<B> {
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn install(
        &mut self,
        expected_request_sha256: &DigestHex,
        request_bytes: &[u8],
        bundle_bytes: &[u8],
        receipt_key: &[u8],
    ) -> InstallOutcome {
        match self.install_inner(
            expected_request_sha256,
            request_bytes,
            bundle_bytes,
            receipt_key,
        ) {
            Ok(receipt) => InstallOutcome::Success(receipt),
            Err(InstallError::Backend(BackendError::WaitingUser(reason))) => {
                InstallOutcome::WaitingUser { reason }
            }
            Err(InstallError::Backend(BackendError::Infrastructure(message))) => {
                InstallOutcome::Failure {
                    error: InstallFailure {
                        kind: FailureKind::Infrastructure,
                        message,
                    },
                }
            }
            Err(error) => InstallOutcome::Failure {
                error: InstallFailure {
                    kind: FailureKind::Contract,
                    message: error.to_string(),
                },
            },
        }
    }

    fn install_inner(
        &mut self,
        expected_request_sha256: &DigestHex,
        request_bytes: &[u8],
        bundle_bytes: &[u8],
        receipt_key: &[u8],
    ) -> Result<SignedReceipt, InstallError> {
        if &DigestHex::calculate(request_bytes) != expected_request_sha256 {
            return Err(InstallError::RequestDigestMismatch);
        }
        let request: InstallRequest = parse_canonical_json(request_bytes)?;
        request.validate()?;
        if DigestHex::calculate(bundle_bytes) != request.bundle_sha256 {
            return Err(InstallError::BundleDigestMismatch);
        }
        if DigestHex::calculate(receipt_key) != request.receipt_key_sha256 {
            return Err(InstallError::ReceiptKeyMismatch);
        }

        if let Some(existing_bytes) = self.backend.read_receipt().map_err(InstallError::Backend)? {
            let existing: SignedReceipt = parse_canonical_json(&existing_bytes)?;
            verify_receipt(&existing, receipt_key)?;
            if existing.receipt.matches(&request, expected_request_sha256) {
                return Ok(existing);
            }
            return Err(InstallError::ExistingReceiptConflict);
        }

        let platform = self.backend.platform().map_err(InstallError::Backend)?;
        platform.validate()?;
        let bundle = VerifiedBundle::read(bundle_bytes, &request)?;
        let updater_token = derive_updater_control_token(receipt_key)?;
        for step in FixedStep::all() {
            let input = match step {
                FixedStep::InstallUpdaterConfig => StepInput::Artifact(UPDATER_CONFIG),
                FixedStep::InstallUpdaterControlToken => {
                    StepInput::Artifact(updater_token.as_bytes())
                }
                _ if step.bundle_role().is_some() => {
                    let role = step.bundle_role().expect("checked bundle role");
                    StepInput::Artifact(
                        bundle
                            .files
                            .get(&role)
                            .expect("verified canonical bundle contains every role")
                            .as_slice(),
                    )
                }
                _ if step.image_role().is_some() => {
                    let role = step.image_role().expect("checked image role");
                    StepInput::Image(
                        bundle
                            .images
                            .get(&role)
                            .expect("verified canonical manifest contains every image"),
                    )
                }
                _ if step.uses_runtime() => StepInput::Runtime(RuntimeSpec {
                    request: &request,
                    images: &bundle.images,
                }),
                _ => StepInput::None,
            };
            self.backend
                .apply_step(*step, input)
                .map_err(InstallError::Backend)?;
        }
        let receipt = InstallReceipt {
            schema_version: 1,
            deployment_uuid: request.deployment_uuid,
            service_id: request.service_id,
            release: request.release,
            request_sha256: expected_request_sha256.clone(),
            bundle_sha256: request.bundle_sha256,
            manifest_sha256: request.manifest_sha256,
            domain: request.domain,
            public_ipv4: request.public_ipv4,
            region: request.region,
            account_generation: request.account_generation,
            updater: request.updater,
            platform,
            completed_steps: FixedStep::all().to_vec(),
            cloud_worker: CloudWorkerStatus::DisabledByProductScope,
            runtime_status: RuntimeStatus::RuntimeHealthy,
            completed_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| InstallError::Clock)?
                .as_secs(),
        };
        let signed = sign_receipt(receipt, receipt_key)?;
        let bytes = canonical_json(&signed)?;
        self.backend
            .write_receipt(&bytes)
            .map_err(InstallError::Backend)?;
        Ok(signed)
    }

    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl InstallReceipt {
    fn matches(&self, request: &InstallRequest, request_sha256: &DigestHex) -> bool {
        self.schema_version == 1
            && self.request_sha256 == *request_sha256
            && self.bundle_sha256 == request.bundle_sha256
            && self.manifest_sha256 == request.manifest_sha256
            && self.deployment_uuid == request.deployment_uuid
            && self.service_id == request.service_id
            && self.release == request.release
            && self.domain == request.domain
            && self.public_ipv4 == request.public_ipv4
            && self.region == request.region
            && self.account_generation == request.account_generation
            && self.updater == request.updater
            && self.completed_steps == FixedStep::all()
            && self.cloud_worker == CloudWorkerStatus::DisabledByProductScope
            && self.runtime_status == RuntimeStatus::RuntimeHealthy
            && self.platform.validate().is_ok()
    }
}

struct VerifiedBundle {
    files: BTreeMap<BundleRole, Vec<u8>>,
    images: BTreeMap<ImageRole, ImageReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleAssets {
    pub compose_file: Vec<u8>,
    pub caddyfile: Vec<u8>,
    pub message_server_initializer: Vec<u8>,
    pub agent_secret_materializer: Vec<u8>,
    pub message_server_entrypoint: Vec<u8>,
    pub capability_ca_initializer: Vec<u8>,
    pub postgres_entrypoint: Vec<u8>,
    pub postgres_initializer: Vec<u8>,
    pub updater_binary: Vec<u8>,
    pub updater_unit: Vec<u8>,
    pub updater_version: String,
    pub updater_source_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltBundle {
    pub bytes: Vec<u8>,
    pub bundle_sha256: DigestHex,
    pub manifest_sha256: DigestHex,
    pub release_signing_public_key: PublicKeyHex,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleBuildRequest {
    pub schema_version: u32,
    pub release: String,
    pub images: Vec<ImageReference>,
    pub compose_path: PathBuf,
    pub caddyfile_path: PathBuf,
    pub message_server_initializer_path: PathBuf,
    pub agent_secret_materializer_path: PathBuf,
    pub message_server_entrypoint_path: PathBuf,
    pub capability_ca_initializer_path: PathBuf,
    pub postgres_entrypoint_path: PathBuf,
    pub postgres_initializer_path: PathBuf,
    pub updater_binary_path: PathBuf,
    pub updater_unit_path: PathBuf,
    pub updater_version: String,
    pub updater_source_url: String,
    pub updater_sha256: DigestHex,
    pub output_bundle_path: PathBuf,
}

pub fn build_bundle(
    release: &str,
    images: Vec<ImageReference>,
    assets: BundleAssets,
    signing_key: &[u8; 32],
) -> Result<BuiltBundle, InstallError> {
    validate_release(release)?;
    let expected_images = ImageRole::required();
    if images.len() != expected_images.len()
        || images
            .iter()
            .zip(expected_images)
            .any(|(image, role)| image.role != *role || image.validate(release).is_err())
    {
        return Err(InstallError::NonCanonicalImages);
    }
    let artifacts = [
        (BundleRole::ComposeFile, assets.compose_file),
        (BundleRole::Caddyfile, assets.caddyfile),
        (
            BundleRole::MessageServerInitializer,
            assets.message_server_initializer,
        ),
        (
            BundleRole::AgentSecretMaterializer,
            assets.agent_secret_materializer,
        ),
        (
            BundleRole::MessageServerEntrypoint,
            assets.message_server_entrypoint,
        ),
        (
            BundleRole::CapabilityCaInitializer,
            assets.capability_ca_initializer,
        ),
        (BundleRole::PostgresEntrypoint, assets.postgres_entrypoint),
        (BundleRole::PostgresInitializer, assets.postgres_initializer),
        (BundleRole::UpdaterBinary, assets.updater_binary),
        (BundleRole::UpdaterUnit, assets.updater_unit),
    ];
    if artifacts
        .iter()
        .any(|(_, bytes)| bytes.is_empty() || bytes.len() > MAX_FILE_BYTES)
    {
        return Err(InstallError::BundleTooLarge);
    }
    let files: Vec<_> = artifacts
        .iter()
        .map(|(role, bytes)| BundleFile {
            role: *role,
            sha256: DigestHex::calculate(bytes),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            mode: role.mode(),
        })
        .collect();
    let updater_sha256 = files
        .iter()
        .find(|file| file.role == BundleRole::UpdaterBinary)
        .ok_or(InstallError::NonCanonicalTopology)?
        .sha256
        .clone();
    let updater = UpdaterIdentity {
        version: assets.updater_version,
        source_url: assets.updater_source_url,
        sha256: updater_sha256,
    };
    updater.validate()?;
    let manifest = BundleManifest {
        schema_version: 1,
        release: release.to_owned(),
        target: HostTarget::LinuxAmd64,
        images,
        updater,
        files,
    };
    let signing_key = SigningKey::from_bytes(signing_key);
    let manifest_bytes = canonical_json(&manifest)?;
    let signed = SignedBundleManifest {
        manifest,
        ed25519_signature: SignatureHex::parse(hex::encode(
            signing_key.sign(&manifest_bytes).to_bytes(),
        ))?,
    };
    let signed_bytes = canonical_json(&signed)?;
    let manifest_sha256 = DigestHex::calculate(&signed_bytes);
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        append_bundle_entry(&mut builder, "manifest.json", &signed_bytes, 0o644)?;
        for (role, content) in artifacts {
            append_bundle_entry(&mut builder, role.archive_path(), &content, role.mode())?;
        }
        builder.finish().map_err(InstallError::Io)?;
    }
    if bytes.len() > MAX_RELEASE_BUNDLE_BYTES {
        return Err(InstallError::BundleTooLarge);
    }
    Ok(BuiltBundle {
        bundle_sha256: DigestHex::calculate(&bytes),
        bytes,
        manifest_sha256,
        release_signing_public_key: PublicKeyHex::from_key(&signing_key.verifying_key()),
    })
}

fn append_bundle_entry(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    path: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), InstallError> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).map_err(InstallError::Io)?;
    header.set_size(u64::try_from(bytes.len()).map_err(|_| InstallError::BundleTooLarge)?);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append(&header, bytes).map_err(InstallError::Io)
}

impl VerifiedBundle {
    fn read(bytes: &[u8], request: &InstallRequest) -> Result<Self, InstallError> {
        if bytes.len() > MAX_RELEASE_BUNDLE_BYTES {
            return Err(InstallError::BundleTooLarge);
        }
        let mut archive = tar::Archive::new(Cursor::new(bytes));
        let mut manifest_bytes = None;
        let mut raw_files = BTreeMap::new();
        let allowed_paths: BTreeSet<_> = BundleRole::required()
            .iter()
            .map(|role| role.archive_path())
            .collect();
        for entry in archive.entries().map_err(InstallError::Io)? {
            let mut entry = entry.map_err(InstallError::Io)?;
            if !entry.header().entry_type().is_file() {
                return Err(InstallError::UnsafeBundleEntry);
            }
            let path = entry
                .path()
                .map_err(InstallError::Io)?
                .to_str()
                .ok_or(InstallError::UnsafeBundleEntry)?
                .to_owned();
            if path != "manifest.json" && !allowed_paths.contains(path.as_str()) {
                return Err(InstallError::UnexpectedBundleEntry(path));
            }
            let declared_size =
                usize::try_from(entry.size()).map_err(|_| InstallError::BundleTooLarge)?;
            if declared_size > MAX_FILE_BYTES {
                return Err(InstallError::BundleTooLarge);
            }
            let mut content = Vec::with_capacity(declared_size);
            entry.read_to_end(&mut content).map_err(InstallError::Io)?;
            if content.len() != declared_size {
                return Err(InstallError::FileSizeMismatch(path));
            }
            if path == "manifest.json" {
                if manifest_bytes.replace(content).is_some() {
                    return Err(InstallError::DuplicateBundleEntry);
                }
            } else if raw_files.insert(path, content).is_some() {
                return Err(InstallError::DuplicateBundleEntry);
            }
        }
        let manifest_bytes = manifest_bytes.ok_or(InstallError::MissingManifest)?;
        if DigestHex::calculate(&manifest_bytes) != request.manifest_sha256 {
            return Err(InstallError::ManifestDigestMismatch);
        }
        let signed: SignedBundleManifest = parse_canonical_json(&manifest_bytes)?;
        let signed_bytes = canonical_json(&signed.manifest)?;
        request
            .release_signing_public_key
            .key()?
            .verify(&signed_bytes, &signed.ed25519_signature.signature()?)
            .map_err(|_| InstallError::ManifestSignatureMismatch)?;
        signed.manifest.validate(request)?;
        let mut files = BTreeMap::new();
        for file in signed.manifest.files {
            let content = raw_files
                .remove(file.role.archive_path())
                .ok_or(InstallError::MissingBundleFile(file.role))?;
            if u64::try_from(content.len()).ok() != Some(file.size) {
                return Err(InstallError::FileSizeMismatch(
                    file.role.archive_path().to_owned(),
                ));
            }
            if DigestHex::calculate(&content) != file.sha256 {
                return Err(InstallError::FileDigestMismatch(file.role));
            }
            files.insert(file.role, content);
        }
        if !raw_files.is_empty() {
            return Err(InstallError::UnexpectedBundleEntry(
                raw_files.into_keys().next().expect("not empty"),
            ));
        }
        let images = signed
            .manifest
            .images
            .into_iter()
            .map(|image| (image.role, image))
            .collect();
        Ok(Self { files, images })
    }
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, InstallError> {
    serde_json::to_vec(value).map_err(InstallError::Json)
}

pub fn parse_canonical_json<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, InstallError> {
    let value: T = serde_json::from_slice(bytes).map_err(InstallError::Json)?;
    if canonical_json(&value)? != bytes {
        return Err(InstallError::NonCanonicalJson);
    }
    Ok(value)
}

pub fn sign_receipt(
    receipt: InstallReceipt,
    receipt_key: &[u8],
) -> Result<SignedReceipt, InstallError> {
    if receipt_key.len() < 32 {
        return Err(InstallError::WeakReceiptKey);
    }
    let bytes = canonical_json(&receipt)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(receipt_key).map_err(|_| InstallError::WeakReceiptKey)?;
    mac.update(&bytes);
    let signature = DigestHex::parse(hex::encode(mac.finalize().into_bytes()))?;
    Ok(SignedReceipt {
        receipt,
        hmac_sha256: signature,
    })
}

pub fn verify_receipt(receipt: &SignedReceipt, receipt_key: &[u8]) -> Result<(), InstallError> {
    let bytes = canonical_json(&receipt.receipt)?;
    let signature =
        hex::decode(receipt.hmac_sha256.as_str()).map_err(|_| InstallError::InvalidDigest)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(receipt_key).map_err(|_| InstallError::WeakReceiptKey)?;
    mac.update(&bytes);
    mac.verify_slice(&signature)
        .map_err(|_| InstallError::ReceiptSignatureMismatch)
}

pub fn derive_updater_control_token(receipt_key: &[u8]) -> Result<Zeroizing<String>, InstallError> {
    if receipt_key.len() < 32 {
        return Err(InstallError::WeakReceiptKey);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(receipt_key).map_err(|_| InstallError::WeakReceiptKey)?;
    mac.update(b"dirextalk-updater-control-token-v1");
    Ok(Zeroizing::new(hex::encode(mac.finalize().into_bytes())))
}

#[derive(Debug, Default)]
pub struct LinuxBackend;

impl InstallBackend for LinuxBackend {
    fn platform(&mut self) -> Result<PlatformInfo, BackendError> {
        let os_release = fs::read_to_string("/etc/os-release")
            .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
        let fields = parse_os_release(&os_release);
        let output = run_program("/usr/bin/systemctl", &["--version"])?;
        let first_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        let systemd_version = first_line
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| BackendError::Infrastructure("invalid systemd version output".into()))?;
        Ok(PlatformInfo {
            os_id: fields.get("ID").cloned().unwrap_or_default(),
            version_id: fields.get("VERSION_ID").cloned().unwrap_or_default(),
            architecture: std::env::consts::ARCH.to_owned(),
            systemd_version,
        })
    }

    fn read_receipt(&mut self) -> Result<Option<Vec<u8>>, BackendError> {
        match read_stable_regular(Path::new(RECEIPT_PATH), Some(0), Some(0o600), 1024 * 1024) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(BackendError::Infrastructure(error.to_string())),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_step(&mut self, step: FixedStep, input: StepInput<'_>) -> Result<(), BackendError> {
        match step {
            FixedStep::InstallDocker => {
                run_program("/usr/bin/apt-get", &["update"])?;
                run_program(
                    "/usr/bin/apt-get",
                    &[
                        "install",
                        "--yes",
                        "--no-install-recommends",
                        "docker.io",
                        "docker-compose-v2",
                        "curl",
                        "dnsutils",
                    ],
                )?;
                run_program("/usr/bin/systemctl", &["enable", "--now", "docker.service"])?;
            }
            step if step.image_role().is_some() => {
                let expected = step.image_role().expect("checked image role");
                let image = input.image()?;
                image
                    .validate_repository_and_tag()
                    .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
                if image.role != expected {
                    return Err(BackendError::Infrastructure(
                        "fixed image step received the wrong image role".into(),
                    ));
                }
                let digest_reference = image.digest_reference();
                run_program("/usr/bin/docker", &["pull", &digest_reference])?;
            }
            FixedStep::InstallComposeFile => {
                install_file(
                    input.artifact()?,
                    "/var/dirextalk-message-server/docker-compose.yml",
                    0o600,
                )?;
            }
            FixedStep::InstallCaddyfile => {
                install_file(
                    input.artifact()?,
                    "/var/dirextalk-message-server/runtime/Caddyfile",
                    0o444,
                )?;
            }
            step @ (FixedStep::InstallMessageServerInitializer
            | FixedStep::InstallAgentSecretMaterializer
            | FixedStep::InstallMessageServerEntrypoint
            | FixedStep::InstallCapabilityCaInitializer
            | FixedStep::InstallPostgresEntrypoint
            | FixedStep::InstallPostgresInitializer) => {
                let destination = match step {
                    FixedStep::InstallMessageServerInitializer => {
                        "/var/dirextalk-message-server/runtime/initialize-message-server.sh"
                    }
                    FixedStep::InstallAgentSecretMaterializer => {
                        "/var/dirextalk-message-server/runtime/materialize-agent-secrets.sh"
                    }
                    FixedStep::InstallMessageServerEntrypoint => {
                        "/var/dirextalk-message-server/runtime/message-server-entrypoint.sh"
                    }
                    FixedStep::InstallCapabilityCaInitializer => {
                        "/var/dirextalk-message-server/runtime/initialize-capability-ca.sh"
                    }
                    FixedStep::InstallPostgresEntrypoint => {
                        "/var/dirextalk-message-server/runtime/postgres-entrypoint.sh"
                    }
                    FixedStep::InstallPostgresInitializer => {
                        "/var/dirextalk-message-server/runtime/initialize-postgres.sh"
                    }
                    _ => unreachable!("guard restricts fixed helper step"),
                };
                install_file(input.artifact()?, destination, 0o555)?;
            }
            FixedStep::InstallUpdaterBinary => {
                install_file(input.artifact()?, "/usr/local/bin/dirextalk-updater", 0o755)?;
            }
            FixedStep::InstallUpdaterConfig => {
                install_file(
                    input.artifact()?,
                    "/etc/dirextalk-updater/config.json",
                    0o600,
                )?;
            }
            FixedStep::InstallUpdaterControlToken => {
                install_file(
                    input.artifact()?,
                    "/etc/dirextalk-updater/control-token",
                    0o600,
                )?;
            }
            FixedStep::InstallUpdaterUnit => {
                install_file(
                    input.artifact()?,
                    "/etc/systemd/system/dirextalk-updater.service",
                    0o644,
                )?;
                run_program("/usr/bin/systemctl", &["daemon-reload"])?;
                run_program(
                    "/usr/bin/systemctl",
                    &["enable", "--now", "dirextalk-updater.service"],
                )?;
            }
            FixedStep::MaterializeRuntime => materialize_runtime(input.runtime()?)?,
            FixedStep::ValidateCompose => {
                let runtime = input.runtime()?;
                run_compose(&["config", "--quiet"])?;
                verify_updater_binary(&runtime.request.updater)?;
            }
            FixedStep::StartMessageServer => {
                run_compose(&[
                    "up",
                    "--detach",
                    "--no-build",
                    "--pull",
                    "never",
                    "--wait",
                    "message-server",
                ])?;
            }
            FixedStep::RefreshAgentToken => refresh_agent_token()?,
            FixedStep::StartAgent => {
                run_compose(&[
                    "up",
                    "--detach",
                    "--no-build",
                    "--pull",
                    "never",
                    "--wait",
                    "agent",
                ])?;
            }
            FixedStep::VerifyDns => verify_dns(input.runtime()?.request)?,
            FixedStep::StartCaddy => {
                run_compose(&[
                    "up",
                    "--detach",
                    "--no-build",
                    "--pull",
                    "never",
                    "--wait",
                    "caddy",
                ])?;
            }
            FixedStep::VerifyRuntime => verify_runtime_services()?,
            FixedStep::VerifyHttps => verify_https(input.runtime()?)?,
            FixedStep::VerifyTurn => verify_turn_acceptance(input.runtime()?.request)?,
            FixedStep::VerifyUpdater => {
                let runtime = input.runtime()?;
                verify_updater_binary(&runtime.request.updater)?;
                let output = run_program(
                    "/usr/bin/systemctl",
                    &["is-active", "dirextalk-updater.service"],
                )?;
                if output.stdout != b"active\n" {
                    return Err(BackendError::Infrastructure(
                        "pinned updater is not active".into(),
                    ));
                }
            }
            _ => return Err(BackendError::Infrastructure("invalid fixed step".into())),
        }
        Ok(())
    }

    fn write_receipt(&mut self, canonical_receipt: &[u8]) -> Result<(), BackendError> {
        atomic_write(Path::new(RECEIPT_PATH), canonical_receipt, 0o600)
    }
}

fn materialize_runtime(runtime: RuntimeSpec<'_>) -> Result<(), BackendError> {
    ensure_secure_directory(Path::new(RUNTIME_ROOT), 0o700)?;
    ensure_secure_directory(Path::new("/var/dirextalk-message-server/runtime"), 0o700)?;
    ensure_secure_directory(Path::new("/var/dirextalk-message-server/secrets"), 0o700)?;

    let postgres_admin = read_or_create_hex_secret("postgres_admin_password", 24)?;
    let message_password = read_or_create_hex_secret("message_postgres_password", 24)?;
    let agent_password = read_or_create_hex_secret("agent_postgres_password", 24)?;
    let registration = read_or_create_hex_secret("message_registration_shared_secret", 32)?;
    let turn = read_or_create_hex_secret("turn_shared_secret", 32)?;
    let portal = read_or_create_hex_secret("message_portal_password", 16)?;
    let master = read_or_create_raw_secret("core_secret_master_key", 32)?;
    let mcp_path = runtime_secret_path("message_mcp_token");
    if mcp_path.exists() {
        read_runtime_secret(&mcp_path, 4096)?;
    } else {
        create_secret_noclobber(&mcp_path, b"")?;
    }

    let message_database = Zeroizing::new(format!(
        "postgresql://dirextalk_message_server:{}@message-postgres:5432/dirextalk_message_server?sslmode=disable",
        String::from_utf8_lossy(&message_password)
    ));
    let agent_database = Zeroizing::new(format!(
        "postgresql://dirextalk_agent:{}@agent-postgres:5432/dirextalk_agent?sslmode=disable",
        String::from_utf8_lossy(&agent_password)
    ));
    atomic_write(
        &runtime_secret_path("message_database_url"),
        message_database.as_bytes(),
        0o600,
    )?;
    atomic_write(
        &runtime_secret_path("agent_database_url"),
        agent_database.as_bytes(),
        0o600,
    )?;

    let turn_config = Zeroizing::new(render_turn_config(runtime.request, &turn));
    atomic_write(
        &runtime_secret_path("turnserver.conf"),
        turn_config.as_bytes(),
        0o600,
    )?;

    let message_instance = derived_instance_id(runtime.request.deployment_uuid, b"message-server");
    let agent_instance = derived_instance_id(runtime.request.deployment_uuid, b"agent");
    let env = render_runtime_env(runtime, message_instance, agent_instance)?;
    atomic_write(
        Path::new("/var/dirextalk-message-server/.env"),
        env.as_bytes(),
        0o600,
    )?;
    let agent_config = render_agent_config(runtime.request, agent_instance);
    atomic_write(
        Path::new("/var/dirextalk-message-server/agent-config.yaml"),
        agent_config.as_bytes(),
        0o600,
    )?;

    drop((postgres_admin, registration, portal, master));
    Ok(())
}

fn render_turn_config(request: &InstallRequest, shared_secret: &[u8]) -> String {
    format!(
        "listening-port=3478\nmin-port=49160\nmax-port=49200\nrealm={}\nexternal-ip={}\nfingerprint\nuse-auth-secret\nstatic-auth-secret={}\nstale-nonce=600\nno-cli\nno-multicast-peers\nno-tls\nno-dtls\npidfile=/tmp/turnserver.pid\n",
        request.domain,
        request.public_ipv4,
        String::from_utf8_lossy(shared_secret)
    )
}

fn render_runtime_env(
    runtime: RuntimeSpec<'_>,
    message_instance: Uuid,
    agent_instance: Uuid,
) -> Result<String, BackendError> {
    let image = |role| {
        runtime
            .images
            .get(&role)
            .map(ImageReference::digest_reference)
            .ok_or_else(|| BackendError::Infrastructure("signed runtime image is missing".into()))
    };
    Ok(format!(
        "POSTGRES_IMAGE={}\nUTILITY_IMAGE={}\nMESSAGE_SERVER_IMAGE={}\nAGENT_IMAGE={}\nCADDY_IMAGE={}\nCOTURN_IMAGE={}\nDOMAIN={}\nMESSAGE_SERVER_INSTANCE_ID={}\nAGENT_INSTANCE_ID={}\nACCOUNT_GENERATION={}\nRELEASE_CATALOG_ORIGIN={}\n",
        image(ImageRole::Postgres)?,
        image(ImageRole::Utility)?,
        image(ImageRole::MessageServer)?,
        image(ImageRole::Agent)?,
        image(ImageRole::Caddy)?,
        image(ImageRole::Coturn)?,
        runtime.request.domain,
        message_instance,
        agent_instance,
        runtime.request.account_generation,
        runtime.request.release_catalog_origin,
    ))
}

fn render_agent_config(request: &InstallRequest, agent_instance: Uuid) -> String {
    format!(
        "instance_id: {agent_instance}\ndatabase_url_file: /run/secrets/database_url\ngrpc_listen: \":9443\"\nagent_http_enabled: true\nagent_http_listen: 0.0.0.0:8082\ntls_cert_file: /run/secrets/tls_cert\ntls_key_file: /run/secrets/tls_key\nservice_token_file: /run/secrets/service_token\ncore_voice_callback_relay_token_file: /run/secrets/voice_relay_token\nenable_health_service: true\nenable_reflection: false\ncapability_grant_public_key_file: /run/secrets/grant_public_key\ncapability_account_generation: {}\nproduct_capability_enabled: true\nproduct_capability_address: message-server:50053\nproduct_capability_ca_cert_file: /run/secrets/product_ca\nproduct_capability_tls_cert_file: /run/secrets/product_tls_cert\nproduct_capability_tls_key_file: /run/secrets/product_tls_key\nproduct_capability_token_file: /run/secrets/agent_to_ms_token\nproduct_capability_server_name: dirextalk-message-server\nproduct_capability_instance_id: {agent_instance}\nproduct_capability_account_generation: {}\ncore_task_max_concurrency: 4\ncore_task_lease_ttl: 30s\ncore_schedule_sweep_interval: 1s\ncore_shutdown_grace: 30s\ncore_extension_enabled: false\ncore_message_mcp_enabled: true\ncore_message_mcp_endpoint: http://message-server:8008/mcp\ncore_message_mcp_token_file: /run/secrets/message_mcp_token\ncore_static_sites_enabled: false\ncore_workload_enabled: false\ncore_secret_master_key_file: /run/secrets/core_secret_master_key\ncore_secret_master_key_version: 1\ncore_knowledge_enabled: false\n",
        request.account_generation, request.account_generation
    )
}

fn runtime_secret_path(name: &str) -> PathBuf {
    Path::new("/var/dirextalk-message-server/secrets").join(name)
}

fn read_or_create_hex_secret(
    name: &str,
    random_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let path = runtime_secret_path(name);
    if path.exists() {
        let bytes = Zeroizing::new(read_runtime_secret(&path, random_bytes * 2)?);
        if bytes.len() != random_bytes * 2
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(BackendError::Infrastructure(format!(
                "{name} has invalid protected state"
            )));
        }
        return Ok(bytes);
    }
    let mut random = Zeroizing::new(vec![0_u8; random_bytes]);
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|error| BackendError::Infrastructure(format!("read OS RNG: {error}")))?;
    let encoded = Zeroizing::new(hex::encode(&*random).into_bytes());
    create_secret_noclobber(&path, &encoded)?;
    Ok(encoded)
}

fn read_or_create_raw_secret(name: &str, size: usize) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let path = runtime_secret_path(name);
    if path.exists() {
        let bytes = Zeroizing::new(read_runtime_secret(&path, size)?);
        if bytes.len() != size {
            return Err(BackendError::Infrastructure(format!(
                "{name} has invalid protected state"
            )));
        }
        return Ok(bytes);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; size]);
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| BackendError::Infrastructure(format!("read OS RNG: {error}")))?;
    create_secret_noclobber(&path, &bytes)?;
    Ok(bytes)
}

fn read_runtime_secret(path: &Path, maximum: usize) -> Result<Vec<u8>, BackendError> {
    read_stable_regular(path, Some(0), Some(0o600), maximum).map_err(|error| {
        BackendError::Infrastructure(format!("read protected runtime state: {error}"))
    })
}

fn create_secret_noclobber(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    let parent = path
        .parent()
        .ok_or_else(|| BackendError::Infrastructure("secret has no parent".into()))?;
    let temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    temporary
        .as_file()
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    temporary.persist_noclobber(path).map_err(|error| {
        BackendError::Infrastructure(format!("publish protected runtime state: {}", error.error))
    })?;
    Ok(())
}

fn ensure_secure_directory(path: &Path, mode: u32) -> Result<(), BackendError> {
    fs::create_dir_all(path).map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 {
        return Err(BackendError::Infrastructure(format!(
            "runtime directory is not root-owned: {}",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| BackendError::Infrastructure(error.to_string()))
}

fn derived_instance_id(deployment: Uuid, label: &[u8]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(deployment.as_bytes());
    digest.update(label);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn run_compose(arguments: &[&str]) -> Result<std::process::Output, BackendError> {
    let mut fixed = vec![
        "compose",
        "--project-name",
        COMPOSE_PROJECT,
        "--file",
        COMPOSE_PATH,
    ];
    fixed.extend_from_slice(arguments);
    run_program("/usr/bin/docker", &fixed)
}

#[derive(Deserialize)]
struct BootstrapCredentials {
    access_token: String,
    agent_token: String,
}

struct BootstrapSecrets {
    access_token: Zeroizing<String>,
    agent_token: Zeroizing<String>,
}

#[derive(Deserialize)]
struct TurnResponse {
    uris: Vec<String>,
    username: String,
    password: String,
    ttl: u64,
}

fn read_bootstrap_credentials() -> Result<BootstrapSecrets, BackendError> {
    let output = run_compose(&["ps", "--quiet", "message-server"])?;
    let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendError::Infrastructure(
            "message-server container identity is invalid".into(),
        ));
    }
    verify_exact_container(&id, "message-server", true)?;
    let output = run_program(
        "/usr/bin/docker",
        &[
            "exec",
            &id,
            "/bin/cat",
            "/var/dirextalk-message-server/p2p/bootstrap.json",
        ],
    )?;
    verify_exact_container(&id, "message-server", true)?;
    if output.stdout.len() > 64 * 1024 {
        return Err(BackendError::Infrastructure(
            "message-server bootstrap is too large".into(),
        ));
    }
    let credentials: BootstrapCredentials = serde_json::from_slice(&output.stdout)
        .map_err(|_| BackendError::Infrastructure("message-server bootstrap is invalid".into()))?;
    for token in [&credentials.access_token, &credentials.agent_token] {
        if token.is_empty()
            || token.len() > 4096
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(BackendError::Infrastructure(
                "message-server bootstrap token is invalid".into(),
            ));
        }
    }
    Ok(BootstrapSecrets {
        access_token: Zeroizing::new(credentials.access_token),
        agent_token: Zeroizing::new(credentials.agent_token),
    })
}

fn verify_exact_container(
    id: &str,
    service: &str,
    require_healthy: bool,
) -> Result<(), BackendError> {
    let output = run_program("/usr/bin/docker", &["inspect", id])?;
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| BackendError::Infrastructure("container inspection is invalid".into()))?;
    let value = values
        .first()
        .filter(|_| values.len() == 1)
        .ok_or_else(|| {
            BackendError::Infrastructure("container inspection identity is ambiguous".into())
        })?;
    let label = |name: &str| {
        value
            .pointer(&format!("/Config/Labels/{name}"))
            .and_then(serde_json::Value::as_str)
    };
    let healthy = value
        .pointer("/State/Health/Status")
        .and_then(serde_json::Value::as_str);
    if value.get("Id").and_then(serde_json::Value::as_str) != Some(id)
        || label("com.docker.compose.project") != Some(COMPOSE_PROJECT)
        || label("com.docker.compose.service") != Some(service)
        || value
            .pointer("/State/Status")
            .and_then(serde_json::Value::as_str)
            != Some("running")
        || (require_healthy && healthy != Some("healthy"))
    {
        return Err(BackendError::Infrastructure(format!(
            "exact {service} container is not healthy"
        )));
    }
    Ok(())
}

fn refresh_agent_token() -> Result<(), BackendError> {
    let credentials = read_bootstrap_credentials()?;
    atomic_write(
        &runtime_secret_path("message_mcp_token"),
        credentials.agent_token.as_bytes(),
        0o600,
    )
}

fn verify_dns(request: &InstallRequest) -> Result<(), BackendError> {
    for (server, label) in [
        (request.authoritative_dns_ipv4, "authoritative"),
        (request.public_recursive_dns_ipv4, "public-recursive"),
    ] {
        let server = format!("@{server}");
        let output = run_program(
            "/usr/bin/dig",
            &[
                "+time=5",
                "+tries=1",
                "+short",
                "A",
                &server,
                &request.domain,
            ],
        )?;
        let answers = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<Ipv4Addr>().ok())
            .collect::<BTreeSet<_>>();
        if !answers.contains(&request.public_ipv4) {
            return Err(BackendError::WaitingUser(format!(
                "{label} DNS has not published the expected A record"
            )));
        }
    }
    Ok(())
}

fn verify_https(runtime: RuntimeSpec<'_>) -> Result<(), BackendError> {
    let request = runtime.request;
    let resolve = format!("{}:443:{}", request.domain, request.public_ipv4);
    let matrix_url = format!("https://{}/_matrix/client/versions", request.domain);
    run_program(
        "/usr/bin/curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--resolve",
            &resolve,
            &matrix_url,
        ],
    )?;
    let agent_url = format!("https://{}/agent/v1/health", request.domain);
    let output = run_program(
        "/usr/bin/curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--resolve",
            &resolve,
            &agent_url,
        ],
    )?;
    let health: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| BackendError::Infrastructure("public Agent health is invalid".into()))?;
    let expected_release = runtime
        .images
        .get(&ImageRole::Agent)
        .and_then(|image| image.tag.as_deref())
        .ok_or_else(|| BackendError::Infrastructure("signed Agent identity is missing".into()))?;
    if json_string(&health, "status") != Some("ok")
        || json_string(&health, "release_version") != Some(expected_release)
    {
        return Err(BackendError::Infrastructure(
            "public Agent health does not match the signed release".into(),
        ));
    }
    Ok(())
}

fn verify_turn_acceptance(request: &InstallRequest) -> Result<(), BackendError> {
    let credentials = read_bootstrap_credentials()?;
    let url = format!(
        "https://{}/_matrix/client/v3/voip/turnServer",
        request.domain
    );
    let resolve = format!("{}:443:{}", request.domain, request.public_ipv4);
    let config = Zeroizing::new(format!(
        "silent\nshow-error\nfail\nmax-time = 15\nresolve = \"{resolve}\"\nheader = \"Authorization: Bearer {}\"\nurl = \"{url}\"\n",
        *credentials.access_token
    ));
    let output = run_program_with_input("/usr/bin/curl", &["--config", "-"], config.as_bytes())?;
    let response: TurnResponse = serde_json::from_slice(&output.stdout)
        .map_err(|_| BackendError::Infrastructure("Matrix TURN response is invalid".into()))?;
    let expected = BTreeSet::from([
        format!("turn:{}:3478?transport=tcp", request.domain),
        format!("turn:{}:3478?transport=udp", request.domain),
    ]);
    if response.uris.into_iter().collect::<BTreeSet<_>>() != expected
        || response.username.is_empty()
        || response.password.is_empty()
        || response.ttl == 0
    {
        return Err(BackendError::Infrastructure(
            "Matrix did not accept the credential-backed TURN 3478 contract".into(),
        ));
    }
    Ok(())
}

fn verify_runtime_services() -> Result<(), BackendError> {
    let output = run_compose(&["ps", "--all", "--format", "json"])?;
    let records = parse_compose_ps(&output.stdout)?;
    let expected = BTreeSet::from([
        "postgres",
        "coturn",
        "message-init",
        "message-server",
        "agent-secret-init",
        "agent-migrate",
        "agent",
        "caddy",
    ]);
    if records.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(BackendError::Infrastructure(
            "Compose service set is not canonical".into(),
        ));
    }
    for service in ["postgres", "coturn", "message-server", "agent"] {
        let value = &records[service];
        if json_string(value, "State") != Some("running")
            || json_string(value, "Health") != Some("healthy")
        {
            return Err(BackendError::Infrastructure(format!(
                "{service} is not healthy"
            )));
        }
    }
    if json_string(&records["caddy"], "State") != Some("running") {
        return Err(BackendError::Infrastructure("caddy is not running".into()));
    }
    for service in ["message-init", "agent-secret-init", "agent-migrate"] {
        let value = &records[service];
        let exit_code = value
            .get("ExitCode")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1);
        if json_string(value, "State") != Some("exited") || exit_code != 0 {
            return Err(BackendError::Infrastructure(format!(
                "{service} did not complete successfully"
            )));
        }
    }
    Ok(())
}

fn parse_compose_ps(bytes: &[u8]) -> Result<BTreeMap<String, serde_json::Value>, BackendError> {
    let values = if let Ok(values) = serde_json::from_slice::<Vec<serde_json::Value>>(bytes) {
        values
    } else {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| BackendError::Infrastructure("Compose status JSON is invalid".into()))?
    };
    let mut records = BTreeMap::new();
    for value in values {
        let service = json_string(&value, "Service")
            .ok_or_else(|| {
                BackendError::Infrastructure("Compose status omitted service identity".into())
            })?
            .to_owned();
        if records.insert(service, value).is_some() {
            return Err(BackendError::Infrastructure(
                "Compose status has duplicate services".into(),
            ));
        }
    }
    Ok(records)
}

fn json_string<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn verify_updater_binary(expected: &UpdaterIdentity) -> Result<(), BackendError> {
    let bytes = read_stable_regular(
        Path::new("/usr/local/bin/dirextalk-updater"),
        Some(0),
        Some(0o755),
        MAX_FILE_BYTES,
    )
    .map_err(|error| BackendError::Infrastructure(format!("verify updater binary: {error}")))?;
    if DigestHex::calculate(&bytes) != expected.sha256 {
        return Err(BackendError::Infrastructure(
            "installed updater digest changed".into(),
        ));
    }
    Ok(())
}

pub fn read_stable_regular(
    path: &Path,
    expected_uid: Option<u32>,
    expected_mode: Option<u32>,
    maximum_bytes: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file()
        || expected_uid.is_some_and(|uid| before.uid() != uid)
        || expected_mode.is_some_and(|mode| before.mode() & 0o777 != mode)
        || before.len() > u64::try_from(maximum_bytes).unwrap_or(u64::MAX)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "file identity, owner, mode, or size is invalid",
        ));
    }
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "file identity changed while opening",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(maximum_bytes));
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeded size limit while reading",
        ));
    }
    let after = file.metadata()?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.mtime() != after.mtime()
        || opened.mtime_nsec() != after.mtime_nsec()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file changed while reading",
        ));
    }
    Ok(bytes)
}

fn install_file(bytes: &[u8], destination: &str, mode: u32) -> Result<(), BackendError> {
    atomic_write(Path::new(destination), bytes, mode)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), BackendError> {
    let parent = path
        .parent()
        .ok_or_else(|| BackendError::Infrastructure("destination has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    let temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    let mut file = temporary.as_file();
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    temporary
        .persist(path)
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    let directory =
        fs::File::open(parent).map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    directory
        .sync_all()
        .map_err(|error| BackendError::Infrastructure(error.to_string()))
}

fn run_program(program: &str, arguments: &[&str]) -> Result<std::process::Output, BackendError> {
    let output = Command::new(program)
        .args(arguments)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(command_failure(program, &output))
    }
}

fn run_program_with_input(
    program: &str,
    arguments: &[&str],
    input: &[u8],
) -> Result<std::process::Output, BackendError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| BackendError::Infrastructure("child stdin is unavailable".into()))?
        .write_all(input)
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    let output = child
        .wait_with_output()
        .map_err(|error| BackendError::Infrastructure(error.to_string()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(command_failure(program, &output))
    }
}

fn command_failure(program: &str, output: &std::process::Output) -> BackendError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if program == "/usr/bin/apt-get"
        && (stderr.contains("Could not get lock")
            || stderr.contains("Unable to acquire the dpkg frontend lock"))
    {
        return BackendError::WaitingUser("package manager lock is held".into());
    }
    BackendError::Infrastructure(format!(
        "{program} failed with {}: {}",
        output.status,
        stderr.trim()
    ))
}

fn parse_os_release(source: &str) -> BTreeMap<String, String> {
    source
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((
                key.to_owned(),
                value
                    .trim_matches(|character| matches!(character, '\'' | '"'))
                    .to_owned(),
            ))
        })
        .collect()
}

fn validate_slug(value: &str, name: &'static str) -> Result<(), InstallError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Err(InstallError::InvalidRequest(name))
    } else {
        Ok(())
    }
}

fn validate_dns_name(value: &str) -> Result<(), InstallError> {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        Err(InstallError::InvalidRequest("domain"))
    } else {
        Ok(())
    }
}

fn validate_region(value: &str) -> Result<(), InstallError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Err(InstallError::InvalidRequest("region"))
    } else {
        Ok(())
    }
}

fn validate_https_origin(value: &str) -> Result<(), InstallError> {
    let Some(host) = value.strip_prefix("https://") else {
        return Err(InstallError::InvalidRequest("release_catalog_origin"));
    };
    if host.contains(['/', '?', '#', '@', ':']) || validate_dns_name(host).is_err() {
        Err(InstallError::InvalidRequest("release_catalog_origin"))
    } else {
        Ok(())
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !address.is_unspecified()
        && !address.is_multicast()
        && octets[0] != 0
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        && !(octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        && octets[0] < 224
}

fn validate_release(value: &str) -> Result<(), InstallError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        Err(InstallError::InvalidRequest("release"))
    } else {
        Ok(())
    }
}

fn valid_product_version(value: &str) -> bool {
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

fn valid_source_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex_array<const SIZE: usize>(value: &str) -> Result<[u8; SIZE], InstallError> {
    if value.len() != SIZE * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InstallError::InvalidHex);
    }
    let decoded = hex::decode(value).map_err(|_| InstallError::InvalidHex)?;
    decoded.try_into().map_err(|_| InstallError::InvalidHex)
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("invalid install request field: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid fixed-length lowercase hexadecimal value")]
    InvalidHex,
    #[error("invalid Ed25519 release public key")]
    InvalidReleasePublicKey,
    #[error("request bytes do not match the approved request digest")]
    RequestDigestMismatch,
    #[error("release bundle does not match the request digest")]
    BundleDigestMismatch,
    #[error("bundle manifest does not match its request digest")]
    ManifestDigestMismatch,
    #[error("bundle manifest release signature is invalid")]
    ManifestSignatureMismatch,
    #[error("receipt key does not match the request digest")]
    ReceiptKeyMismatch,
    #[error("bundle manifest does not match the install request")]
    ManifestMismatch,
    #[error("updater release identity is invalid")]
    InvalidUpdaterIdentity,
    #[error("updater binary digest does not match its signed identity")]
    UpdaterIdentityMismatch,
    #[error("bundle does not contain the exact canonical production topology")]
    NonCanonicalTopology,
    #[error("bundle does not contain the exact canonical image set")]
    NonCanonicalImages,
    #[error("image reference is invalid for role {0:?}")]
    InvalidImageReference(ImageRole),
    #[error("third-party image does not match the frozen release pin for role {0:?}")]
    ThirdPartyImagePinMismatch(ImageRole),
    #[error("bundle is too large")]
    BundleTooLarge,
    #[error("bundle contains a non-regular or unsafe entry")]
    UnsafeBundleEntry,
    #[error("bundle contains duplicate entries")]
    DuplicateBundleEntry,
    #[error("bundle contains unexpected entry: {0}")]
    UnexpectedBundleEntry(String),
    #[error("bundle manifest is missing")]
    MissingManifest,
    #[error("bundle file is missing for role {0:?}")]
    MissingBundleFile(BundleRole),
    #[error("bundle file size mismatch: {0}")]
    FileSizeMismatch(String),
    #[error("bundle file digest mismatch for role {0:?}")]
    FileDigestMismatch(BundleRole),
    #[error("unsupported host platform: {0:?}")]
    UnsupportedPlatform(PlatformInfo),
    #[error("an existing receipt belongs to a different installation")]
    ExistingReceiptConflict,
    #[error("receipt signature is invalid")]
    ReceiptSignatureMismatch,
    #[error("receipt signing key must contain at least 32 bytes")]
    WeakReceiptKey,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("JSON is not in canonical form")]
    NonCanonicalJson,
    #[error("JSON failed: {0}")]
    Json(serde_json::Error),
    #[error("bundle I/O failed: {0}")]
    Io(std::io::Error),
    #[error("host backend failed: {0:?}")]
    Backend(BackendError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        platform: Option<PlatformInfo>,
        receipt: Option<Vec<u8>>,
        steps: Vec<FixedStep>,
        writes: usize,
        fail: Option<BackendError>,
        fail_at: Option<(FixedStep, BackendError)>,
    }

    impl InstallBackend for FakeBackend {
        fn platform(&mut self) -> Result<PlatformInfo, BackendError> {
            if let Some(error) = self.fail.clone() {
                return Err(error);
            }
            Ok(self.platform.clone().unwrap_or_else(supported_platform))
        }

        fn read_receipt(&mut self) -> Result<Option<Vec<u8>>, BackendError> {
            Ok(self.receipt.clone())
        }

        fn apply_step(
            &mut self,
            step: FixedStep,
            _input: StepInput<'_>,
        ) -> Result<(), BackendError> {
            self.steps.push(step);
            if let Some((failed_step, error)) = &self.fail_at
                && *failed_step == step
            {
                return Err(error.clone());
            }
            Ok(())
        }

        fn write_receipt(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
            self.writes += 1;
            self.receipt = Some(bytes.to_vec());
            Ok(())
        }
    }

    fn supported_platform() -> PlatformInfo {
        PlatformInfo {
            os_id: "ubuntu".into(),
            version_id: "24.04".into(),
            architecture: "x86_64".into(),
            systemd_version: 255,
        }
    }

    fn images(release: &str) -> Vec<ImageReference> {
        ImageRole::required()
            .iter()
            .map(|role| ImageReference {
                role: *role,
                repository: role.allowed_repository().into(),
                tag: match role {
                    ImageRole::Postgres | ImageRole::Utility => Some("pg18".into()),
                    ImageRole::MessageServer | ImageRole::Agent => Some(release.into()),
                    ImageRole::Caddy => None,
                    ImageRole::Coturn => Some("4.6.3-alpine".into()),
                },
                digest: DigestHex::parse(match role {
                    ImageRole::Postgres | ImageRole::Utility => POSTGRES_UTILITY_DIGEST,
                    ImageRole::Caddy => CADDY_DIGEST,
                    ImageRole::Coturn => COTURN_DIGEST,
                    ImageRole::MessageServer | ImageRole::Agent => {
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                })
                .unwrap(),
                source_revision: if matches!(role, ImageRole::MessageServer | ImageRole::Agent) {
                    Some("0123456789abcdef0123456789abcdef01234567".into())
                } else {
                    None
                },
            })
            .collect()
    }

    fn fixture() -> (Vec<u8>, DigestHex, Vec<u8>, Vec<u8>) {
        let key = vec![42; 32];
        let built = build_bundle(
            "v1.2.3",
            images("v1.2.3"),
            BundleAssets {
                compose_file: b"services: {}".to_vec(),
                caddyfile: b"{$DOMAIN}".to_vec(),
                message_server_initializer: b"#!/bin/sh".to_vec(),
                agent_secret_materializer: b"#!/bin/sh".to_vec(),
                message_server_entrypoint: b"#!/bin/sh".to_vec(),
                capability_ca_initializer: b"#!/bin/sh".to_vec(),
                postgres_entrypoint: b"#!/bin/sh".to_vec(),
                postgres_initializer: b"#!/bin/sh".to_vec(),
                updater_binary: b"updater".to_vec(),
                updater_unit: b"[Service]".to_vec(),
                updater_version: "v1.0.0".into(),
                updater_source_url: "https://releases.example/updater".into(),
            },
            &[7; 32],
        )
        .unwrap();
        let request = InstallRequest {
            schema_version: 1,
            deployment_uuid: Uuid::nil(),
            service_id: "service-1".into(),
            release: "v1.2.3".into(),
            target: HostTarget::LinuxAmd64,
            bundle_sha256: built.bundle_sha256,
            manifest_sha256: built.manifest_sha256,
            release_signing_public_key: built.release_signing_public_key,
            receipt_key_sha256: DigestHex::calculate(&key),
            domain: "node.example.com".into(),
            public_ipv4: "8.8.4.4".parse().unwrap(),
            region: "us-central1".into(),
            release_catalog_origin: "https://imadmin.dirextalk.ai".into(),
            account_generation: 1,
            authoritative_dns_ipv4: "9.9.9.9".parse().unwrap(),
            public_recursive_dns_ipv4: "8.8.8.8".parse().unwrap(),
            updater: UpdaterIdentity {
                version: "v1.0.0".into(),
                source_url: "https://releases.example/updater".into(),
                sha256: DigestHex::calculate(b"updater"),
            },
        };
        let request = canonical_json(&request).unwrap();
        let digest = DigestHex::calculate(&request);
        (request, digest, built.bytes, key)
    }

    #[test]
    fn rejects_request_and_bundle_tamper() {
        let (request, request_digest, bundle, key) = fixture();
        let mut tampered_request = request.clone();
        tampered_request[5] ^= 1;
        let mut installer = Installer::new(FakeBackend::default());
        assert!(matches!(
            installer.install(&request_digest, &tampered_request, &bundle, &key),
            InstallOutcome::Failure {
                error: InstallFailure {
                    kind: FailureKind::Contract,
                    ..
                }
            }
        ));

        let mut tampered_bundle = bundle.clone();
        tampered_bundle[512] ^= 1;
        assert!(matches!(
            installer.install(&request_digest, &request, &tampered_bundle, &key),
            InstallOutcome::Failure {
                error: InstallFailure {
                    kind: FailureKind::Contract,
                    ..
                }
            }
        ));
    }

    #[test]
    fn rejects_wrong_platform_before_mutation() {
        let (request, request_digest, bundle, key) = fixture();
        let backend = FakeBackend {
            platform: Some(PlatformInfo {
                os_id: "ubuntu".into(),
                version_id: "22.04".into(),
                architecture: "x86_64".into(),
                systemd_version: 255,
            }),
            ..FakeBackend::default()
        };
        let mut installer = Installer::new(backend);
        assert_eq!(
            installer
                .install(&request_digest, &request, &bundle, &key)
                .exit_code(),
            1
        );
        assert!(installer.into_backend().steps.is_empty());
    }

    #[test]
    fn exposes_all_three_outcome_classes() {
        let (request, request_digest, bundle, key) = fixture();
        let mut success = Installer::new(FakeBackend::default());
        assert_eq!(
            success
                .install(&request_digest, &request, &bundle, &key)
                .exit_code(),
            0
        );

        let mut waiting = Installer::new(FakeBackend {
            fail: Some(BackendError::WaitingUser("apt lock held".into())),
            ..FakeBackend::default()
        });
        assert_eq!(
            waiting
                .install(&request_digest, &request, &bundle, &key)
                .exit_code(),
            2
        );

        let mut failure = Installer::new(FakeBackend {
            fail: Some(BackendError::Infrastructure("disk error".into())),
            ..FakeBackend::default()
        });
        assert_eq!(
            failure
                .install(&request_digest, &request, &bundle, &key)
                .exit_code(),
            1
        );
    }

    #[test]
    fn reuses_valid_receipt_without_mutating() {
        let (request, request_digest, bundle, key) = fixture();
        let mut first = Installer::new(FakeBackend::default());
        let expected = first.install(&request_digest, &request, &bundle, &key);
        let receipt = first.into_backend().receipt;
        let mut second = Installer::new(FakeBackend {
            receipt,
            ..FakeBackend::default()
        });
        let actual = second.install(&request_digest, &request, &bundle, &key);
        assert_eq!(actual, expected);
        let backend = second.into_backend();
        assert!(backend.steps.is_empty());
        assert_eq!(backend.writes, 0);
    }

    #[test]
    fn rejects_unknown_fields_and_noncanonical_json() {
        let (request, _, _, _) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&request).unwrap();
        value["arbitrary_command"] = serde_json::Value::String("rm -rf /".into());
        let expanded = serde_json::to_vec(&value).unwrap();
        assert!(parse_canonical_json::<InstallRequest>(&expanded).is_err());

        let mut whitespace = request;
        whitespace.push(b'\n');
        assert!(parse_canonical_json::<InstallRequest>(&whitespace).is_err());
    }

    #[test]
    fn rejects_non_allowlisted_image_and_wrong_manifest_signer() {
        let mut invalid_images = images("v1.2.3");
        invalid_images[0].repository = "evil.example/postgres".into();
        assert!(matches!(
            build_bundle(
                "v1.2.3",
                invalid_images,
                BundleAssets {
                    compose_file: b"services: {}".to_vec(),
                    caddyfile: b"{$DOMAIN}".to_vec(),
                    message_server_initializer: b"#!/bin/sh".to_vec(),
                    agent_secret_materializer: b"#!/bin/sh".to_vec(),
                    message_server_entrypoint: b"#!/bin/sh".to_vec(),
                    capability_ca_initializer: b"#!/bin/sh".to_vec(),
                    postgres_entrypoint: b"#!/bin/sh".to_vec(),
                    postgres_initializer: b"#!/bin/sh".to_vec(),
                    updater_binary: b"updater".to_vec(),
                    updater_unit: b"[Service]".to_vec(),
                    updater_version: "v1.0.0".into(),
                    updater_source_url: "https://releases.example/updater".into(),
                },
                &[7; 32],
            ),
            Err(InstallError::NonCanonicalImages)
        ));

        let (request, _, bundle, key) = fixture();
        let mut request_value: InstallRequest = parse_canonical_json(&request).unwrap();
        request_value.release_signing_public_key =
            PublicKeyHex::from_key(&SigningKey::from_bytes(&[8; 32]).verifying_key());
        let request = canonical_json(&request_value).unwrap();
        let request_digest = DigestHex::calculate(&request);
        let mut installer = Installer::new(FakeBackend::default());
        assert!(matches!(
            installer.install(&request_digest, &request, &bundle, &key),
            InstallOutcome::Failure {
                error: InstallFailure {
                    kind: FailureKind::Contract,
                    ..
                }
            }
        ));
        assert!(installer.into_backend().steps.is_empty());
    }

    #[test]
    fn canonical_image_contract_uses_split_release_roles_and_pins() {
        assert_eq!(
            ImageRole::required(),
            &[
                ImageRole::Postgres,
                ImageRole::Utility,
                ImageRole::MessageServer,
                ImageRole::Agent,
                ImageRole::Caddy,
                ImageRole::Coturn,
            ]
        );
        let mut resolved = images("v1.2.3");
        resolved
            .iter_mut()
            .find(|image| image.role == ImageRole::Agent)
            .unwrap()
            .tag = Some("v2.0.0".into());
        build_bundle(
            "stable-2026-08-20",
            resolved.clone(),
            BundleAssets {
                compose_file: b"services: {}".to_vec(),
                caddyfile: b"{$DOMAIN}".to_vec(),
                message_server_initializer: b"#!/bin/sh".to_vec(),
                agent_secret_materializer: b"#!/bin/sh".to_vec(),
                message_server_entrypoint: b"#!/bin/sh".to_vec(),
                capability_ca_initializer: b"#!/bin/sh".to_vec(),
                postgres_entrypoint: b"#!/bin/sh".to_vec(),
                postgres_initializer: b"#!/bin/sh".to_vec(),
                updater_binary: b"updater".to_vec(),
                updater_unit: b"[Service]".to_vec(),
                updater_version: "v1.0.0".into(),
                updater_source_url: "https://releases.example/updater".into(),
            },
            &[7; 32],
        )
        .unwrap();

        resolved
            .iter_mut()
            .find(|image| image.role == ImageRole::MessageServer)
            .unwrap()
            .tag = Some("latest".into());
        assert!(matches!(
            build_bundle(
                "stable-2026-08-20",
                resolved,
                BundleAssets {
                    compose_file: b"services: {}".to_vec(),
                    caddyfile: b"{$DOMAIN}".to_vec(),
                    message_server_initializer: b"#!/bin/sh".to_vec(),
                    agent_secret_materializer: b"#!/bin/sh".to_vec(),
                    message_server_entrypoint: b"#!/bin/sh".to_vec(),
                    capability_ca_initializer: b"#!/bin/sh".to_vec(),
                    postgres_entrypoint: b"#!/bin/sh".to_vec(),
                    postgres_initializer: b"#!/bin/sh".to_vec(),
                    updater_binary: b"updater".to_vec(),
                    updater_unit: b"[Service]".to_vec(),
                    updater_version: "v1.0.0".into(),
                    updater_source_url: "https://releases.example/updater".into(),
                },
                &[7; 32],
            ),
            Err(InstallError::NonCanonicalImages)
        ));
    }

    #[test]
    fn final_receipt_is_written_only_after_every_runtime_gate() {
        let (request, request_digest, bundle, key) = fixture();
        for (step, error, expected_code) in [
            (
                FixedStep::VerifyDns,
                BackendError::WaitingUser("DNS is pending".into()),
                2,
            ),
            (
                FixedStep::VerifyTurn,
                BackendError::Infrastructure("TURN failed".into()),
                1,
            ),
            (
                FixedStep::VerifyUpdater,
                BackendError::Infrastructure("updater failed".into()),
                1,
            ),
        ] {
            let mut installer = Installer::new(FakeBackend {
                fail_at: Some((step, error)),
                ..FakeBackend::default()
            });
            assert_eq!(
                installer
                    .install(&request_digest, &request, &bundle, &key)
                    .exit_code(),
                expected_code
            );
            assert_eq!(installer.into_backend().writes, 0);
        }

        let mut installer = Installer::new(FakeBackend::default());
        let outcome = installer.install(&request_digest, &request, &bundle, &key);
        let InstallOutcome::Success(receipt) = outcome else {
            panic!("all-green runtime did not produce a receipt");
        };
        assert_eq!(
            receipt.receipt.runtime_status,
            RuntimeStatus::RuntimeHealthy
        );
        assert_eq!(
            receipt.receipt.completed_steps.last(),
            Some(&FixedStep::VerifyUpdater)
        );
        assert_eq!(installer.into_backend().writes, 1);
    }

    #[test]
    fn turn_contract_is_credential_backed_3478_without_tls_listener() {
        let (request, _, _, _) = fixture();
        let request: InstallRequest = parse_canonical_json(&request).unwrap();
        let config = render_turn_config(
            &request,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(config.contains("listening-port=3478\n"));
        assert!(config.contains("use-auth-secret\nstatic-auth-secret="));
        assert!(config.contains("no-tls\nno-dtls\n"));
        assert!(config.contains(&format!("external-ip={}\n", request.public_ipv4)));
        assert!(!config.contains("5349"));
    }

    #[test]
    fn runtime_bundle_roles_have_exact_paths_and_modes() {
        let expected = [
            (BundleRole::ComposeFile, "runtime/docker-compose.yml", 0o644),
            (BundleRole::Caddyfile, "runtime/Caddyfile", 0o444),
            (
                BundleRole::MessageServerInitializer,
                "runtime/initialize-message-server.sh",
                0o555,
            ),
            (
                BundleRole::AgentSecretMaterializer,
                "runtime/materialize-agent-secrets.sh",
                0o555,
            ),
            (
                BundleRole::MessageServerEntrypoint,
                "runtime/message-server-entrypoint.sh",
                0o555,
            ),
            (
                BundleRole::CapabilityCaInitializer,
                "runtime/initialize-capability-ca.sh",
                0o555,
            ),
            (
                BundleRole::PostgresEntrypoint,
                "runtime/postgres-entrypoint.sh",
                0o555,
            ),
            (
                BundleRole::PostgresInitializer,
                "runtime/initialize-postgres.sh",
                0o555,
            ),
            (
                BundleRole::UpdaterBinary,
                "updater/dirextalk-updater",
                0o755,
            ),
            (
                BundleRole::UpdaterUnit,
                "updater/dirextalk-updater.service",
                0o644,
            ),
        ];
        assert_eq!(BundleRole::required().len(), expected.len());
        for (actual, (role, path, mode)) in BundleRole::required().iter().zip(expected) {
            assert_eq!(*actual, role);
            assert_eq!(actual.archive_path(), path);
            assert_eq!(actual.mode(), mode);
        }
    }

    #[test]
    fn strict_runtime_request_rejects_untrusted_network_fields() {
        let (request, _, _, _) = fixture();
        let mut request: InstallRequest = parse_canonical_json(&request).unwrap();
        request.domain = "node.example.com;reboot".into();
        assert!(request.validate().is_err());
        request.domain = "node.example.com".into();
        request.release_catalog_origin = "http://imadmin.dirextalk.ai".into();
        assert!(request.validate().is_err());
        request.release_catalog_origin = "https://imadmin.dirextalk.ai".into();
        request.public_recursive_dns_ipv4 = request.authoritative_dns_ipv4;
        assert!(request.validate().is_err());
    }
}
