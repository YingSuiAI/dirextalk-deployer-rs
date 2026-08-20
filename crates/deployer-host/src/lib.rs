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
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const REQUEST_PATH: &str = "/var/tmp/dirextalk-install-request.json";
pub const BUNDLE_PATH: &str = "/var/tmp/dirextalk-release-bundle.tar";
pub const RECEIPT_KEY_PATH: &str = "/var/tmp/dirextalk-receipt.key";
pub const RECEIPT_PATH: &str = "/var/lib/dirextalk/install-receipt.json";

pub const MAX_RELEASE_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_INSTALL_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RECEIPT_KEY_BYTES: usize = 4 * 1024;
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
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
    UpdaterBinary,
    UpdaterUnit,
}

impl BundleRole {
    const REQUIRED: [Self; 3] = [Self::ComposeFile, Self::UpdaterBinary, Self::UpdaterUnit];

    #[must_use]
    pub const fn required() -> &'static [Self] {
        &Self::REQUIRED
    }

    #[must_use]
    pub const fn archive_path(self) -> &'static str {
        match self {
            Self::ComposeFile => "runtime/docker-compose.yml",
            Self::UpdaterBinary => "updater/dirextalk-updater",
            Self::UpdaterUnit => "updater/dirextalk-updater.service",
        }
    }

    const fn mode(self) -> u32 {
        match self {
            Self::UpdaterBinary => 0o755,
            _ => 0o644,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRole {
    Postgres,
    Matrix,
    MessageServer,
    Agent,
    Caddy,
    Coturn,
}

impl ImageRole {
    const REQUIRED: [Self; 6] = [
        Self::Postgres,
        Self::Matrix,
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
            Self::Postgres => "docker.io/library/postgres",
            Self::Matrix => "docker.io/matrixdotorg/synapse",
            Self::MessageServer => "ghcr.io/yingsuiai/dirextalk-message-server",
            Self::Agent => "ghcr.io/yingsuiai/dirextalk-agent",
            Self::Caddy => "docker.io/library/caddy",
            Self::Coturn => "docker.io/coturn/coturn",
        }
    }

    const fn is_application(self) -> bool {
        matches!(self, Self::MessageServer | Self::Agent)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageReference {
    pub role: ImageRole,
    pub repository: String,
    pub tag: String,
    pub digest: DigestHex,
}

impl ImageReference {
    fn validate(&self, release: &str) -> Result<(), InstallError> {
        if self.repository != self.role.allowed_repository() || !valid_tag(&self.tag) {
            return Err(InstallError::InvalidImageReference(self.role));
        }
        if self.role.is_application() && self.tag != release {
            return Err(InstallError::ApplicationImageReleaseMismatch(self.role));
        }
        Ok(())
    }

    fn digest_reference(&self) -> String {
        format!("{}@sha256:{}", self.repository, self.digest.as_str())
    }

    fn tagged_reference(&self) -> String {
        format!("{}:{}", self.repository, self.tag)
    }

    fn validate_repository_and_tag(&self) -> Result<(), InstallError> {
        if self.repository != self.role.allowed_repository() || !valid_tag(&self.tag) {
            Err(InstallError::InvalidImageReference(self.role))
        } else {
            Ok(())
        }
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
    PullMatrixImage,
    PullMessageServerImage,
    PullAgentImage,
    PullCaddyImage,
    PullCoturnImage,
    InstallComposeFile,
    InstallUpdaterBinary,
    InstallUpdaterConfig,
    InstallUpdaterControlToken,
    InstallUpdaterUnit,
}

impl FixedStep {
    const ALL: [Self; 12] = [
        Self::InstallDocker,
        Self::PullPostgresImage,
        Self::PullMatrixImage,
        Self::PullMessageServerImage,
        Self::PullAgentImage,
        Self::PullCaddyImage,
        Self::PullCoturnImage,
        Self::InstallComposeFile,
        Self::InstallUpdaterBinary,
        Self::InstallUpdaterConfig,
        Self::InstallUpdaterControlToken,
        Self::InstallUpdaterUnit,
    ];

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &Self::ALL
    }

    const fn bundle_role(self) -> Option<BundleRole> {
        match self {
            Self::InstallComposeFile => Some(BundleRole::ComposeFile),
            Self::InstallUpdaterBinary => Some(BundleRole::UpdaterBinary),
            Self::InstallUpdaterUnit => Some(BundleRole::UpdaterUnit),
            _ => None,
        }
    }

    const fn image_role(self) -> Option<ImageRole> {
        match self {
            Self::PullPostgresImage => Some(ImageRole::Postgres),
            Self::PullMatrixImage => Some(ImageRole::Matrix),
            Self::PullMessageServerImage => Some(ImageRole::MessageServer),
            Self::PullAgentImage => Some(ImageRole::Agent),
            Self::PullCaddyImage => Some(ImageRole::Caddy),
            Self::PullCoturnImage => Some(ImageRole::Coturn),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StepInput<'a> {
    None,
    Artifact(&'a [u8]),
    Image(&'a ImageReference),
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
    pub platform: PlatformInfo,
    pub completed_steps: Vec<FixedStep>,
    pub cloud_worker: CloudWorkerStatus,
    pub completed_unix_seconds: u64,
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
            platform,
            completed_steps: FixedStep::all().to_vec(),
            cloud_worker: CloudWorkerStatus::DisabledByProductScope,
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
            && self.deployment_uuid == request.deployment_uuid
            && self.service_id == request.service_id
            && self.release == request.release
            && self.completed_steps == FixedStep::all()
            && self.cloud_worker == CloudWorkerStatus::DisabledByProductScope
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
    pub updater_binary: Vec<u8>,
    pub updater_unit: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltBundle {
    pub bytes: Vec<u8>,
    pub bundle_sha256: DigestHex,
    pub manifest_sha256: DigestHex,
    pub release_signing_public_key: PublicKeyHex,
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
    let manifest = BundleManifest {
        schema_version: 1,
        release: release.to_owned(),
        target: HostTarget::LinuxAmd64,
        images,
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
                let tagged_reference = image.tagged_reference();
                run_program("/usr/bin/docker", &["pull", &digest_reference])?;
                run_program(
                    "/usr/bin/docker",
                    &["image", "tag", &digest_reference, &tagged_reference],
                )?;
            }
            FixedStep::InstallComposeFile => {
                install_file(
                    input.artifact()?,
                    "/var/dirextalk-message-server/docker-compose.yml",
                    0o600,
                )?;
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
            _ => return Err(BackendError::Infrastructure("invalid fixed step".into())),
        }
        Ok(())
    }

    fn write_receipt(&mut self, canonical_receipt: &[u8]) -> Result<(), BackendError> {
        atomic_write(Path::new(RECEIPT_PATH), canonical_receipt, 0o600)
    }
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

fn valid_tag(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
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
    #[error("bundle does not contain the exact canonical production topology")]
    NonCanonicalTopology,
    #[error("bundle does not contain the exact canonical image set")]
    NonCanonicalImages,
    #[error("image reference is invalid for role {0:?}")]
    InvalidImageReference(ImageRole),
    #[error("application image tag does not match the exact release for role {0:?}")]
    ApplicationImageReleaseMismatch(ImageRole),
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
                tag: if role.is_application() {
                    release.into()
                } else {
                    "fixed-1".into()
                },
                digest: DigestHex::calculate(format!("image:{role:?}").as_bytes()),
            })
            .collect()
    }

    fn fixture() -> (Vec<u8>, DigestHex, Vec<u8>, Vec<u8>) {
        let key = vec![42; 32];
        let built = build_bundle(
            "1.2.3",
            images("1.2.3"),
            BundleAssets {
                compose_file: b"services: {}".to_vec(),
                updater_binary: b"updater".to_vec(),
                updater_unit: b"[Service]".to_vec(),
            },
            &[7; 32],
        )
        .unwrap();
        let request = InstallRequest {
            schema_version: 1,
            deployment_uuid: Uuid::nil(),
            service_id: "service-1".into(),
            release: "1.2.3".into(),
            target: HostTarget::LinuxAmd64,
            bundle_sha256: built.bundle_sha256,
            manifest_sha256: built.manifest_sha256,
            release_signing_public_key: built.release_signing_public_key,
            receipt_key_sha256: DigestHex::calculate(&key),
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
        let mut invalid_images = images("1.2.3");
        invalid_images[0].repository = "evil.example/postgres".into();
        assert!(matches!(
            build_bundle(
                "1.2.3",
                invalid_images,
                BundleAssets {
                    compose_file: b"services: {}".to_vec(),
                    updater_binary: b"updater".to_vec(),
                    updater_unit: b"[Service]".to_vec(),
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
}
