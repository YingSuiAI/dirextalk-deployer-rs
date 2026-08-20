#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use deployer_core::{
    ExactReleaseIdentity, LinuxAmd64ApplicationIdentity, LinuxAmd64UpdaterIdentity,
    ReleaseSelection, ReleaseTag, Sha256Digest, SigningKeyIdentity, SourceRevision,
};
use deployer_host::{
    BuiltBundle, BundleManifest, DigestHex, HostTarget, ImageReference, ImageRole, PublicKeyHex,
    UpdaterIdentity, canonical_json as host_canonical_json,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::engine::{EngineError, Result};

const REPOSITORY: &str = "YingSuiAI/dirextalk-deployer-rs";
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_SIGNED_MANIFEST: u64 = 4 * 1024 * 1024;
const MAX_INSTALLER: u64 = 64 * 1024 * 1024;
const MAX_GITHUB_PUBLICATION: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ResolvedRelease {
    pub identity: ExactReleaseIdentity,
    pub release_catalog_origin: String,
    installer: ExactAsset,
    bundle: ExactAsset,
    signed_manifest: ExactAsset,
    updater: UpdaterIdentity,
    signing_public_key: String,
}

pub struct HostPayload {
    pub installer: Vec<u8>,
    pub bundle: BuiltBundle,
    pub updater: UpdaterIdentity,
    pub release_catalog_origin: String,
}

#[async_trait]
pub trait ReleaseCatalog: Send + Sync {
    async fn resolve(&self, selection: &ReleaseSelection) -> Result<ResolvedRelease>;
    async fn load(&self, release: &ResolvedRelease) -> Result<HostPayload>;
}

pub struct GithubReleaseCatalog {
    client: reqwest::Client,
    audited_public_key: String,
}

impl GithubReleaseCatalog {
    pub fn new() -> Result<Self> {
        crate::ensure_tls_provider();
        let audited_public_key = option_env!("DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_HEX")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                EngineError::Backend("release build omitted the audited Ed25519 public key".into())
            })?
            .to_owned();
        decode_hex::<32>(&audited_public_key).map_err(|()| {
            EngineError::Backend("embedded release Ed25519 public key is invalid".into())
        })?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .user_agent(concat!("dirextalk-deployer/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| EngineError::Backend(format!("release client failed: {error}")))?;
        Ok(Self {
            client,
            audited_public_key,
        })
    }

    async fn publication(&self, selection: &ReleaseSelection) -> Result<GithubRelease> {
        let url = match selection {
            ReleaseSelection::Stable => {
                format!("https://api.github.com/repos/{REPOSITORY}/releases/latest")
            }
            ReleaseSelection::Exact(value) => {
                format!(
                    "https://api.github.com/repos/{REPOSITORY}/releases/tags/{}",
                    value.as_str()
                )
            }
        };
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| EngineError::Backend("GitHub release request failed".into()))?
            .error_for_status()
            .map_err(|error| {
                EngineError::Backend(format!("GitHub release request returned {error}"))
            })?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_GITHUB_PUBLICATION)
        {
            return Err(EngineError::Backend(
                "GitHub release response exceeds its size limit".into(),
            ));
        }
        let bytes = response.bytes().await.map_err(|_| {
            EngineError::Backend("GitHub release response could not be read".into())
        })?;
        if bytes.len() as u64 > MAX_GITHUB_PUBLICATION {
            return Err(EngineError::Backend(
                "GitHub release response exceeds its size limit".into(),
            ));
        }
        let publication: GithubRelease = serde_json::from_slice(&bytes)
            .map_err(|_| EngineError::Backend("GitHub release response is invalid".into()))?;
        ReleaseTag::parse(publication.tag_name.clone())?;
        if let ReleaseSelection::Exact(requested) = selection
            && publication.tag_name != requested.as_str()
        {
            return Err(EngineError::Backend(
                "GitHub returned a different exact release tag".into(),
            ));
        }
        if publication.draft || publication.prerelease {
            return Err(EngineError::Backend(
                "selected GitHub release is not stable".into(),
            ));
        }
        Ok(publication)
    }

    async fn download(&self, asset: &GithubAsset, maximum: u64) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(asset.browser_download_url.clone())
            .send()
            .await
            .map_err(|_| EngineError::Backend("release asset download failed".into()))?
            .error_for_status()
            .map_err(|error| {
                EngineError::Backend(format!("release asset download returned {error}"))
            })?;
        if response
            .content_length()
            .is_some_and(|length| length > maximum)
        {
            return Err(EngineError::Backend(
                "release asset exceeds its size limit".into(),
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| EngineError::Backend("release asset could not be read".into()))?;
        if bytes.len() as u64 > maximum {
            return Err(EngineError::Backend(
                "release asset exceeds its size limit".into(),
            ));
        }
        Ok(bytes.to_vec())
    }
}

#[async_trait]
impl ReleaseCatalog for GithubReleaseCatalog {
    async fn resolve(&self, selection: &ReleaseSelection) -> Result<ResolvedRelease> {
        let publication = self.publication(selection).await?;
        let outer_asset = unique_asset(&publication.assets, "release-manifest.json")?;
        validate_url(outer_asset, &publication.tag_name)?;
        let outer_bytes = self.download(outer_asset, MAX_MANIFEST).await?;
        let outer: ReleaseManifest = serde_json::from_slice(&outer_bytes)
            .map_err(|_| EngineError::Backend("release manifest is invalid".into()))?;
        validate_outer(&outer, &publication.tag_name, &self.audited_public_key)?;

        let installer_name = format!(
            "dirextalk-host-installer-{}-linux-amd64",
            publication.tag_name
        );
        let installer_artifact = unique_artifact(
            &outer.artifacts,
            "host-installer",
            "x86_64-unknown-linux-gnu",
            &installer_name,
        )?;
        let bundle_artifact = unique_artifact(
            &outer.artifacts,
            "runtime-bundle",
            "x86_64-unknown-linux-gnu",
            &outer.runtime_bundle.bundle_file,
        )?;
        let signed_artifact = unique_artifact(
            &outer.artifacts,
            "runtime-manifest",
            "x86_64-unknown-linux-gnu",
            &outer.runtime_bundle.signed_manifest_file,
        )?;
        if bundle_artifact.sha256 != outer.runtime_bundle.bundle_sha256
            || signed_artifact.sha256 != outer.runtime_bundle.manifest_sha256
        {
            return Err(EngineError::Backend(
                "release artifact hashes differ from runtime provenance".into(),
            ));
        }
        let installer = exact_asset(&publication, installer_artifact)?;
        let bundle = exact_asset(&publication, bundle_artifact)?;
        let signed_manifest = exact_asset(&publication, signed_artifact)?;
        let signed_bytes = self
            .download(&signed_manifest.github, MAX_SIGNED_MANIFEST)
            .await?;
        signed_manifest.verify(&signed_bytes)?;
        let signed = verify_signed(&signed_bytes, &self.audited_public_key, &outer.release)?;
        validate_signed(&signed.manifest, &outer)?;

        Ok(ResolvedRelease {
            identity: exact_identity(&outer, &outer_bytes, installer_artifact)?,
            release_catalog_origin: format!(
                "https://github.com/{REPOSITORY}/releases/download/{}",
                publication.tag_name
            ),
            installer,
            bundle,
            signed_manifest,
            updater: updater_identity(&outer.runtime_bundle.provenance.updater)?,
            signing_public_key: self.audited_public_key.clone(),
        })
    }

    async fn load(&self, release: &ResolvedRelease) -> Result<HostPayload> {
        let (installer, bundle_bytes, signed_bytes) = tokio::try_join!(
            self.download(&release.installer.github, MAX_INSTALLER),
            self.download(
                &release.bundle.github,
                deployer_host::MAX_RELEASE_BUNDLE_BYTES as u64
            ),
            self.download(&release.signed_manifest.github, MAX_SIGNED_MANIFEST),
        )?;
        release.installer.verify(&installer)?;
        release.bundle.verify(&bundle_bytes)?;
        release.signed_manifest.verify(&signed_bytes)?;
        verify_signed(
            &signed_bytes,
            &release.signing_public_key,
            release.identity.release_tag.as_str(),
        )?;
        if digest(&installer) != release.identity.host_installer_linux_amd64_sha256.as_str()
            || digest(&bundle_bytes) != release.identity.runtime_bundle_linux_amd64_sha256.as_str()
            || digest(&signed_bytes)
                != release
                    .identity
                    .signed_runtime_manifest_linux_amd64_sha256
                    .as_str()
        {
            return Err(EngineError::Backend(
                "downloaded assets differ from the approved release".into(),
            ));
        }
        Ok(HostPayload {
            installer,
            bundle: BuiltBundle {
                bytes: bundle_bytes,
                bundle_sha256: DigestHex::parse(
                    release.identity.runtime_bundle_linux_amd64_sha256.as_str(),
                )
                .map_err(host_error)?,
                manifest_sha256: DigestHex::parse(
                    release
                        .identity
                        .signed_runtime_manifest_linux_amd64_sha256
                        .as_str(),
                )
                .map_err(host_error)?,
                release_signing_public_key: PublicKeyHex::parse(&release.signing_public_key)
                    .map_err(host_error)?,
            },
            updater: release.updater.clone(),
            release_catalog_origin: release.release_catalog_origin.clone(),
        })
    }
}

#[derive(Clone, Debug)]
struct ExactAsset {
    github: GithubAsset,
    sha256: String,
    size_bytes: u64,
}

impl ExactAsset {
    fn verify(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size_bytes || digest(bytes) != self.sha256 {
            return Err(EngineError::Backend(
                "release asset differs from its manifest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: Url,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: u32,
    release: String,
    source_repository: String,
    source_revision: String,
    artifacts: Vec<ReleaseArtifact>,
    runtime_bundle: RuntimeBundle,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseArtifact {
    component: String,
    file: String,
    sha256: String,
    size_bytes: u64,
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBundle {
    bundle_file: String,
    bundle_sha256: String,
    manifest_sha256: String,
    provenance: RuntimeProvenance,
    release_signing_public_key: String,
    signed_manifest_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProvenance {
    schema_version: u32,
    release: String,
    release_signing_public_key: String,
    release_signing_public_key_audited_sha256: String,
    source_revision: String,
    runtime_assets: BTreeMap<String, RuntimeAsset>,
    updater: UpdaterProvenance,
    message_server: ApplicationProvenance,
    agent: ApplicationProvenance,
    images: Vec<ImageReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAsset {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdaterProvenance {
    version: String,
    source_revision: String,
    binary_url: String,
    binary_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationProvenance {
    version: String,
    digest: String,
    source_revision: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    manifest: BundleManifest,
    ed25519_signature: String,
}

#[allow(clippy::too_many_lines)]
fn validate_outer(manifest: &ReleaseManifest, tag: &str, key: &str) -> Result<()> {
    let provenance = &manifest.runtime_bundle.provenance;
    if manifest.schema_version != 1
        || manifest.release != tag
        || manifest.source_repository != REPOSITORY
        || manifest.artifacts.len() != 7
        || provenance.schema_version != 1
        || provenance.release != tag
        || provenance.source_revision != manifest.source_revision
        || manifest.runtime_bundle.release_signing_public_key != key
        || provenance.release_signing_public_key != key
    {
        return Err(EngineError::Backend(
            "release manifest violates the audited contract".into(),
        ));
    }
    SourceRevision::parse(&manifest.source_revision)?;
    Sha256Digest::parse(&manifest.runtime_bundle.bundle_sha256)?;
    Sha256Digest::parse(&manifest.runtime_bundle.manifest_sha256)?;
    SigningKeyIdentity::parse(key)?;
    let decoded_key = decode_hex::<32>(key)
        .map_err(|()| EngineError::Backend("release public key is invalid".into()))?;
    if digest(&decoded_key) != provenance.release_signing_public_key_audited_sha256 {
        return Err(EngineError::Backend(
            "release public key differs from its audited identity".into(),
        ));
    }
    let expected_assets = BTreeSet::from([
        "agent_secret_materializer",
        "caddyfile",
        "capability_ca_initializer",
        "compose_file",
        "message_server_entrypoint",
        "message_server_initializer",
        "postgres_entrypoint",
        "postgres_initializer",
        "updater_unit",
    ]);
    if provenance
        .runtime_assets
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_assets
    {
        return Err(EngineError::Backend(
            "runtime asset set is not canonical".into(),
        ));
    }
    for asset in provenance.runtime_assets.values() {
        if asset.path.is_empty() {
            return Err(EngineError::Backend("runtime asset path is empty".into()));
        }
        Sha256Digest::parse(&asset.sha256)?;
    }
    let expected_artifacts = BTreeSet::from([
        (
            "cli".to_owned(),
            format!("dirextalk-deployer-{tag}-windows-amd64.zip"),
            "x86_64-pc-windows-msvc".to_owned(),
        ),
        (
            "cli".to_owned(),
            format!("dirextalk-deployer-{tag}-linux-amd64.tar.gz"),
            "x86_64-unknown-linux-gnu".to_owned(),
        ),
        (
            "cli".to_owned(),
            format!("dirextalk-deployer-{tag}-macos-amd64.tar.gz"),
            "x86_64-apple-darwin".to_owned(),
        ),
        (
            "cli".to_owned(),
            format!("dirextalk-deployer-{tag}-macos-arm64.tar.gz"),
            "aarch64-apple-darwin".to_owned(),
        ),
        (
            "host-installer".to_owned(),
            format!("dirextalk-host-installer-{tag}-linux-amd64"),
            "x86_64-unknown-linux-gnu".to_owned(),
        ),
        (
            "runtime-bundle".to_owned(),
            manifest.runtime_bundle.bundle_file.clone(),
            "x86_64-unknown-linux-gnu".to_owned(),
        ),
        (
            "runtime-manifest".to_owned(),
            manifest.runtime_bundle.signed_manifest_file.clone(),
            "x86_64-unknown-linux-gnu".to_owned(),
        ),
    ]);
    let actual_artifacts = manifest
        .artifacts
        .iter()
        .map(|item| {
            (
                item.component.clone(),
                item.file.clone(),
                item.target.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    if actual_artifacts != expected_artifacts || actual_artifacts.len() != manifest.artifacts.len()
    {
        return Err(EngineError::Backend(
            "release manifest artifact set is not canonical".into(),
        ));
    }
    for item in &manifest.artifacts {
        Sha256Digest::parse(&item.sha256)?;
        if item.size_bytes == 0 || item.file.contains(['/', '\\']) {
            return Err(EngineError::Backend(
                "release manifest contains an unsafe artifact".into(),
            ));
        }
    }
    Ok(())
}

fn verify_signed(bytes: &[u8], public_key: &str, release: &str) -> Result<SignedManifest> {
    let signed: SignedManifest = serde_json::from_slice(bytes)
        .map_err(|_| EngineError::Backend("signed runtime manifest is invalid".into()))?;
    if signed.manifest.release != release {
        return Err(EngineError::Backend(
            "signed runtime release differs from approval".into(),
        ));
    }
    let key = VerifyingKey::from_bytes(
        &decode_hex::<32>(public_key)
            .map_err(|()| EngineError::Backend("release public key is invalid".into()))?,
    )
    .map_err(|_| EngineError::Backend("release public key is invalid".into()))?;
    let signature = Signature::from_bytes(
        &decode_hex::<64>(&signed.ed25519_signature)
            .map_err(|()| EngineError::Backend("runtime signature is invalid".into()))?,
    );
    key.verify(
        &host_canonical_json(&signed.manifest).map_err(host_error)?,
        &signature,
    )
    .map_err(|_| EngineError::Backend("runtime signature verification failed".into()))?;
    Ok(signed)
}

fn validate_signed(manifest: &BundleManifest, outer: &ReleaseManifest) -> Result<()> {
    let provenance = &outer.runtime_bundle.provenance;
    if manifest.schema_version != 1
        || manifest.target != HostTarget::LinuxAmd64
        || manifest.updater != updater_identity(&provenance.updater)?
        || manifest.images != provenance.images
    {
        return Err(EngineError::Backend(
            "signed runtime manifest differs from provenance".into(),
        ));
    }
    validate_image(
        &manifest.images,
        ImageRole::MessageServer,
        &provenance.message_server,
    )?;
    validate_image(&manifest.images, ImageRole::Agent, &provenance.agent)
}

fn validate_image(
    images: &[ImageReference],
    role: ImageRole,
    expected: &ApplicationProvenance,
) -> Result<()> {
    let mut matches = images.iter().filter(|image| image.role == role);
    let image = matches
        .next()
        .ok_or_else(|| EngineError::Backend("application image is missing".into()))?;
    if matches.next().is_some()
        || image.tag.as_deref() != Some(&expected.version)
        || image.digest.as_str() != expected.digest
        || image.source_revision.as_deref() != Some(&expected.source_revision)
    {
        return Err(EngineError::Backend(
            "application image identity differs from provenance".into(),
        ));
    }
    Ok(())
}

fn exact_identity(
    manifest: &ReleaseManifest,
    manifest_bytes: &[u8],
    installer: &ReleaseArtifact,
) -> Result<ExactReleaseIdentity> {
    let provenance = &manifest.runtime_bundle.provenance;
    Ok(ExactReleaseIdentity {
        release_tag: ReleaseTag::parse(&manifest.release)?,
        release_manifest_sha256: Sha256Digest::parse(digest(manifest_bytes))?,
        release_manifest_source_revision: SourceRevision::parse(&manifest.source_revision)?,
        host_installer_linux_amd64_sha256: Sha256Digest::parse(&installer.sha256)?,
        runtime_bundle_linux_amd64_sha256: Sha256Digest::parse(
            &manifest.runtime_bundle.bundle_sha256,
        )?,
        signed_runtime_manifest_linux_amd64_sha256: Sha256Digest::parse(
            &manifest.runtime_bundle.manifest_sha256,
        )?,
        runtime_manifest_signing_key: SigningKeyIdentity::parse(
            &manifest.runtime_bundle.release_signing_public_key,
        )?,
        message_server: app_identity(&provenance.message_server)?,
        agent: app_identity(&provenance.agent)?,
        updater: LinuxAmd64UpdaterIdentity {
            version: ReleaseTag::parse(&provenance.updater.version)?,
            source_revision: SourceRevision::parse(&provenance.updater.source_revision)?,
            asset_sha256: Sha256Digest::parse(&provenance.updater.binary_sha256)?,
        },
    })
}

fn app_identity(value: &ApplicationProvenance) -> Result<LinuxAmd64ApplicationIdentity> {
    Ok(LinuxAmd64ApplicationIdentity {
        version: ReleaseTag::parse(&value.version)?,
        source_revision: SourceRevision::parse(&value.source_revision)?,
        image_sha256: Sha256Digest::parse(&value.digest)?,
    })
}

fn updater_identity(value: &UpdaterProvenance) -> Result<UpdaterIdentity> {
    let url = Url::parse(&value.binary_url)
        .map_err(|_| EngineError::Backend("updater URL is invalid".into()))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(EngineError::Backend("updater URL is not safe HTTPS".into()));
    }
    Ok(UpdaterIdentity {
        version: ReleaseTag::parse(&value.version)?.to_string(),
        source_revision: SourceRevision::parse(&value.source_revision)?.to_string(),
        source_url: value.binary_url.clone(),
        sha256: DigestHex::parse(&value.binary_sha256).map_err(host_error)?,
    })
}

fn exact_asset(publication: &GithubRelease, item: &ReleaseArtifact) -> Result<ExactAsset> {
    let github = unique_asset(&publication.assets, &item.file)?.clone();
    validate_url(&github, &publication.tag_name)?;
    Ok(ExactAsset {
        github,
        sha256: item.sha256.clone(),
        size_bytes: item.size_bytes,
    })
}

fn unique_asset<'a>(assets: &'a [GithubAsset], name: &str) -> Result<&'a GithubAsset> {
    let mut matches = assets.iter().filter(|item| item.name == name);
    let asset = matches
        .next()
        .ok_or_else(|| EngineError::Backend(format!("release omitted asset {name}")))?;
    if matches.next().is_some() {
        return Err(EngineError::Backend(format!(
            "release repeats asset {name}"
        )));
    }
    Ok(asset)
}

fn unique_artifact<'a>(
    artifacts: &'a [ReleaseArtifact],
    component: &str,
    target: &str,
    name: &str,
) -> Result<&'a ReleaseArtifact> {
    let mut matches = artifacts
        .iter()
        .filter(|item| item.component == component && item.target == target && item.file == name);
    let item = matches
        .next()
        .ok_or_else(|| EngineError::Backend(format!("manifest omitted artifact {name}")))?;
    if matches.next().is_some() {
        return Err(EngineError::Backend(format!(
            "manifest repeats artifact {name}"
        )));
    }
    Ok(item)
}

fn validate_url(asset: &GithubAsset, tag: &str) -> Result<()> {
    let expected = format!(
        "https://github.com/{REPOSITORY}/releases/download/{tag}/{}",
        asset.name
    );
    if asset.browser_download_url.as_str() != expected {
        return Err(EngineError::Backend(format!(
            "asset {} has an unexpected URL",
            asset.name
        )));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_hex<const N: usize>(value: &str) -> std::result::Result<[u8; N], ()> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(output)
}

#[allow(clippy::needless_pass_by_value)]
fn host_error(error: deployer_host::InstallError) -> EngineError {
    EngineError::Backend(format!("host release contract failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_root_is_exact_lowercase_ed25519_key() {
        assert!(decode_hex::<32>(&"a".repeat(64)).is_ok());
        assert!(decode_hex::<32>(&"A".repeat(64)).is_err());
        assert!(decode_hex::<32>(&"a".repeat(63)).is_err());
    }
}
