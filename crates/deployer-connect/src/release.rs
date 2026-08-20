use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use crate::LocalPlatform;

pub const CONNECT_GITHUB_REPOSITORY: &str = "YingSuiAI/dirextalk-connect";
const MAX_RELEASE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseChannel {
    LatestStable,
    Exact(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAsset {
    pub tag: String,
    pub name: String,
    pub download_url: Url,
    pub sha256: [u8; 32],
}

impl ReleaseAsset {
    /// Verifies bytes against the checksums asset entry.
    ///
    /// # Errors
    ///
    /// Returns a digest mismatch when SHA-256 differs.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), ReleaseError> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual == self.sha256 {
            Ok(())
        } else {
            Err(ReleaseError::DigestMismatch {
                asset: self.name.clone(),
                expected: hex::encode(self.sha256),
                actual: hex::encode(actual),
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedAsset {
    pub asset: ReleaseAsset,
    pub bytes: Vec<u8>,
}

impl VerifiedAsset {
    /// Re-verifies and atomically installs the executable.
    ///
    /// # Errors
    ///
    /// Returns an error for digest mismatch or filesystem failure.
    pub fn install_binary(&self, destination: &Path) -> Result<(), ReleaseError> {
        self.asset.verify(&self.bytes)?;
        let parent = destination
            .parent()
            .ok_or_else(|| ReleaseError::Filesystem("destination has no parent".to_owned()))?;
        fs::create_dir_all(parent).map_err(io_error)?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(io_error)?;
        }
        temporary.write_all(&self.bytes).map_err(io_error)?;
        temporary.as_file().sync_all().map_err(io_error)?;
        temporary
            .persist(destination)
            .map_err(|error| io_error(error.error))?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    #[error("invalid release selection: {0}")]
    InvalidSelection(String),
    #[error("GitHub release request failed: {0}")]
    Request(String),
    #[error("GitHub release contract failed: {0}")]
    Contract(String),
    #[error("SHA-256 mismatch for {asset}: expected {expected}, got {actual}")]
    DigestMismatch {
        asset: String,
        expected: String,
        actual: String,
    },
    #[error("release filesystem operation failed: {0}")]
    Filesystem(String),
}

pub struct ReleaseResolver {
    client: reqwest::Client,
}

impl ReleaseResolver {
    /// Builds the HTTPS-only GitHub client.
    ///
    /// # Errors
    ///
    /// Returns an error when the client cannot be built.
    pub fn new() -> Result<Self, ReleaseError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_mins(1))
            .user_agent(concat!("dirextalk-deployer/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| ReleaseError::Request(error.to_string()))?;
        Ok(Self { client })
    }

    /// Resolves and verifies the exact bare executable plus `checksums.txt`.
    ///
    /// # Errors
    ///
    /// Returns an error for request failure, unstable/malformed release data,
    /// unexpected assets or URLs, and digest mismatch.
    pub async fn fetch_verified_asset(
        &self,
        channel: &ReleaseChannel,
        platform: LocalPlatform,
    ) -> Result<VerifiedAsset, ReleaseError> {
        let release = self.fetch_release(channel).await?;
        if release.draft || release.prerelease {
            return Err(ReleaseError::Contract(
                "release must be published and stable".to_owned(),
            ));
        }
        let canonical_tag = normalized_tag(&release.tag_name).map_err(|_| {
            ReleaseError::Contract(format!(
                "release tag {} is not canonical stable semver",
                release.tag_name
            ))
        })?;
        if canonical_tag != release.tag_name {
            return Err(ReleaseError::Contract(format!(
                "release tag {} is not canonical stable semver",
                release.tag_name
            )));
        }
        if let ReleaseChannel::Exact(requested) = channel {
            let requested = normalized_tag(requested)?;
            if release.tag_name != requested {
                return Err(ReleaseError::Contract(format!(
                    "GitHub returned tag {} for requested {requested}",
                    release.tag_name
                )));
            }
        }
        let executable_suffix = if platform == LocalPlatform::WindowsAmd64 {
            ".exe"
        } else {
            ""
        };
        let name = format!(
            "dirextalk-connect-{}-{}{}",
            release.tag_name,
            platform.release_target(),
            executable_suffix
        );
        let binary = unique_asset(&release.assets, &name)?;
        let checksums = unique_asset(&release.assets, "checksums.txt")?;
        validate_download_url(&binary.browser_download_url, &release.tag_name, &name)?;
        validate_download_url(
            &checksums.browser_download_url,
            &release.tag_name,
            "checksums.txt",
        )?;
        let checksum_bytes = self
            .download(&checksums.browser_download_url, MAX_CHECKSUM_BYTES)
            .await?;
        let checksum_text = std::str::from_utf8(&checksum_bytes).map_err(|error| {
            ReleaseError::Contract(format!("checksums.txt is not UTF-8: {error}"))
        })?;
        let sha256 = checksum_for(checksum_text, &name)?;
        let release_asset = ReleaseAsset {
            tag: release.tag_name,
            name,
            download_url: binary.browser_download_url.clone(),
            sha256,
        };
        let bytes = self
            .download(&release_asset.download_url, MAX_RELEASE_BYTES)
            .await?;
        release_asset.verify(&bytes)?;
        Ok(VerifiedAsset {
            asset: release_asset,
            bytes,
        })
    }

    async fn fetch_release(&self, channel: &ReleaseChannel) -> Result<GithubRelease, ReleaseError> {
        let url = match channel {
            ReleaseChannel::LatestStable => {
                format!("https://api.github.com/repos/{CONNECT_GITHUB_REPOSITORY}/releases/latest")
            }
            ReleaseChannel::Exact(value) => {
                let tag = normalized_tag(value)?;
                format!(
                    "https://api.github.com/repos/{CONNECT_GITHUB_REPOSITORY}/releases/tags/{tag}"
                )
            }
        };
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| ReleaseError::Request(error.to_string()))?
            .error_for_status()
            .map_err(|error| ReleaseError::Request(error.to_string()))?;
        response
            .json()
            .await
            .map_err(|error| ReleaseError::Contract(error.to_string()))
    }

    async fn download(&self, url: &Url, limit: u64) -> Result<Vec<u8>, ReleaseError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| ReleaseError::Request(error.to_string()))?
            .error_for_status()
            .map_err(|error| ReleaseError::Request(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > limit)
        {
            return Err(ReleaseError::Contract(
                "release asset is too large".to_owned(),
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| ReleaseError::Request(error.to_string()))?;
        if bytes.len() as u64 > limit {
            return Err(ReleaseError::Contract(
                "release asset is too large".to_owned(),
            ));
        }
        Ok(bytes.to_vec())
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: Url,
}

fn normalized_tag(value: &str) -> Result<String, ReleaseError> {
    let value = value.trim();
    let version = value.strip_prefix('v').unwrap_or(value);
    let components: Vec<_> = version.split('.').collect();
    let valid = components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (*component == "0" || !component.starts_with('0'))
        });
    if valid {
        Ok(format!("v{version}"))
    } else {
        Err(ReleaseError::InvalidSelection(value.to_owned()))
    }
}

fn unique_asset<'a>(
    assets: &'a [GithubAsset],
    name: &str,
) -> Result<&'a GithubAsset, ReleaseError> {
    let mut matches = assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .ok_or_else(|| ReleaseError::Contract(format!("release omitted asset {name}")))?;
    if matches.next().is_some() {
        return Err(ReleaseError::Contract(format!(
            "release contains duplicate asset {name}"
        )));
    }
    Ok(asset)
}

fn validate_download_url(url: &Url, tag: &str, name: &str) -> Result<(), ReleaseError> {
    let expected =
        format!("https://github.com/{CONNECT_GITHUB_REPOSITORY}/releases/download/{tag}/{name}");
    if url.as_str() == expected {
        Ok(())
    } else {
        Err(ReleaseError::Contract(format!(
            "asset {name} has an unexpected download URL"
        )))
    }
}

fn checksum_for(contents: &str, name: &str) -> Result<[u8; 32], ReleaseError> {
    let matches = contents.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let filename = fields.next()?.trim_start_matches('*');
        (filename == name && fields.next().is_none()).then_some(digest)
    });
    let digests: Vec<_> = matches.collect();
    if digests.len() != 1 {
        return Err(ReleaseError::Contract(format!(
            "checksums.txt must contain exactly one entry for {name}"
        )));
    }
    let decoded = hex::decode(digests[0])
        .map_err(|error| ReleaseError::Contract(format!("invalid SHA-256 for {name}: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| ReleaseError::Contract(format!("invalid SHA-256 length for {name}")))
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> ReleaseError {
    ReleaseError::Filesystem(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_mismatch_fails_closed() {
        let expected: [u8; 32] = Sha256::digest(b"expected").into();
        let asset = ReleaseAsset {
            tag: "v1.2.3".into(),
            name: "dirextalk-connect-v1.2.3-linux-amd64".into(),
            download_url: Url::parse(
                "https://github.com/YingSuiAI/dirextalk-connect/releases/download/v1.2.3/dirextalk-connect-v1.2.3-linux-amd64",
            )
            .unwrap(),
            sha256: expected,
        };
        assert!(matches!(
            asset.verify(b"tampered"),
            Err(ReleaseError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn checksum_parser_requires_one_exact_asset() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            checksum_for(&format!("{digest}  wanted\n{digest}  other\n"), "wanted").unwrap(),
            <[u8; 32]>::try_from(hex::decode(digest).unwrap()).unwrap()
        );
        assert!(checksum_for(&format!("{digest}  wanted\n{digest}  wanted\n"), "wanted").is_err());
    }

    #[test]
    fn exact_release_selection_accepts_only_stable_semver() {
        assert_eq!(normalized_tag("1.2.3").unwrap(), "v1.2.3");
        assert_eq!(normalized_tag("v1.2.3").unwrap(), "v1.2.3");
        for invalid in ["latest", "v1.2", "v1.2.3-rc.1", "../v1.2.3", "v01.2.3"] {
            assert!(normalized_tag(invalid).is_err());
        }
    }

    #[test]
    fn release_download_url_is_bound_to_repo_tag_and_asset() {
        let name = "dirextalk-connect-v1.2.3-linux-amd64";
        let exact = Url::parse(&format!(
            "https://github.com/{CONNECT_GITHUB_REPOSITORY}/releases/download/v1.2.3/{name}"
        ))
        .unwrap();
        assert!(validate_download_url(&exact, "v1.2.3", name).is_ok());

        let wrong_repo = Url::parse(&format!(
            "https://github.com/attacker/dirextalk-connect/releases/download/v1.2.3/{name}"
        ))
        .unwrap();
        assert!(validate_download_url(&wrong_repo, "v1.2.3", name).is_err());
    }
}
