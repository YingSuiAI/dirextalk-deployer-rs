use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{CoreError, Result};

macro_rules! fixed_hex_identity {
    ($name:ident, $length:expr, $reason:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses a lowercase, fixed-width, non-zero hexadecimal identity.
            ///
            /// # Errors
            ///
            /// Returns [`CoreError::InvalidReleaseIdentity`] for abbreviated,
            /// uppercase, non-hexadecimal, or zero identities.
            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.len() != $length
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || value.bytes().all(|byte| byte == b'0')
                {
                    return Err(CoreError::InvalidReleaseIdentity($reason));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            fn from_str(value: &str) -> Result<Self> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_hex_identity!(Sha256Digest, 64, "SHA-256 digest is invalid");
fixed_hex_identity!(SourceRevision, 40, "source revision is not a full revision");
fixed_hex_identity!(SigningKeyIdentity, 64, "signing-key identity is invalid");

/// Strict immutable `vMAJOR.MINOR.PATCH` release tag.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReleaseTag(String);

impl ReleaseTag {
    /// Parses a canonical release tag without aliases or prerelease selectors.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidReleaseIdentity`] unless `value` is exactly
    /// `vMAJOR.MINOR.PATCH` with canonical decimal components.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some(version) = value.strip_prefix('v') else {
            return Err(CoreError::InvalidReleaseIdentity("release tag is invalid"));
        };
        let components: Vec<_> = version.split('.').collect();
        if components.len() != 3
            || components.iter().any(|component| {
                component.is_empty()
                    || !component.bytes().all(|byte| byte.is_ascii_digit())
                    || (component.len() > 1 && component.starts_with('0'))
                    || component.parse::<u64>().is_err()
            })
        {
            return Err(CoreError::InvalidReleaseIdentity("release tag is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ReleaseTag {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for ReleaseTag {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ReleaseTag {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Exact application image built for `linux/amd64`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxAmd64ApplicationIdentity {
    pub version: ReleaseTag,
    pub source_revision: SourceRevision,
    /// Raw lowercase SHA-256 portion of the immutable OCI digest.
    pub image_sha256: Sha256Digest,
}

/// Exact updater executable built for `linux/amd64`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxAmd64UpdaterIdentity {
    pub version: ReleaseTag,
    pub source_revision: SourceRevision,
    pub asset_sha256: Sha256Digest,
}

/// Complete immutable stable-release identity used by planning, resume, and
/// host-install receipt verification. It intentionally contains no URLs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReleaseIdentity {
    pub release_tag: ReleaseTag,
    pub release_manifest_sha256: Sha256Digest,
    pub release_manifest_source_revision: SourceRevision,
    pub host_installer_linux_amd64_sha256: Sha256Digest,
    pub runtime_bundle_linux_amd64_sha256: Sha256Digest,
    pub signed_runtime_manifest_linux_amd64_sha256: Sha256Digest,
    pub runtime_manifest_signing_key: SigningKeyIdentity,
    pub message_server: LinuxAmd64ApplicationIdentity,
    pub agent: LinuxAmd64ApplicationIdentity,
    pub updater: LinuxAmd64UpdaterIdentity,
}

#[cfg(test)]
pub(crate) fn test_release_identity() -> ExactReleaseIdentity {
    fn sha(character: char) -> Sha256Digest {
        Sha256Digest::parse(character.to_string().repeat(64)).unwrap()
    }

    fn revision(character: char) -> SourceRevision {
        SourceRevision::parse(character.to_string().repeat(40)).unwrap()
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_reject_aliases_uppercase_abbreviations_and_zeroes() {
        assert!(ReleaseTag::parse("latest").is_err());
        assert!(ReleaseTag::parse("v01.2.3").is_err());
        assert!(ReleaseTag::parse("v18446744073709551616.2.3").is_err());
        assert!(ReleaseTag::parse("v1.2.3-rc.1").is_err());
        assert!(Sha256Digest::parse("A".repeat(64)).is_err());
        assert!(Sha256Digest::parse("a".repeat(63)).is_err());
        assert!(Sha256Digest::parse("0".repeat(64)).is_err());
        assert!(SourceRevision::parse("a".repeat(12)).is_err());
        assert!(SigningKeyIdentity::parse("0".repeat(64)).is_err());
    }

    #[test]
    fn identities_round_trip_only_as_narrow_strings() {
        let digest = Sha256Digest::parse("a".repeat(64)).unwrap();
        let encoded = serde_json::to_string(&digest).unwrap();
        assert_eq!(encoded, format!("\"{}\"", "a".repeat(64)));
        assert_eq!(
            serde_json::from_str::<Sha256Digest>(&encoded).unwrap(),
            digest
        );
    }

    #[test]
    fn complete_identity_rejects_unknown_fields() {
        let mut value = serde_json::to_value(test_release_identity()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("download_url".to_owned(), "https://example.invalid".into());
        assert!(serde_json::from_value::<ExactReleaseIdentity>(value).is_err());
    }
}
