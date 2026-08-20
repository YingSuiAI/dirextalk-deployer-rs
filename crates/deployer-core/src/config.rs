use serde::{Deserialize, Deserializer, Serialize};

use crate::{CoreError, ReleaseTag, Result};

/// The only configuration schema supported by the fresh-only v0.1 deployer.
pub const SCHEMA_VERSION: u32 = 1;

fn default_machine_type() -> String {
    "e2-custom-2-4096".to_owned()
}

const fn default_boot_disk_size_gib() -> u32 {
    50
}

fn default_boot_disk_type() -> String {
    "pd-balanced".to_owned()
}

fn default_connect_agent() -> String {
    "auto".to_owned()
}

const fn default_install_connect() -> bool {
    true
}

/// How the required public DNS record is managed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    #[default]
    Auto,
    CloudDns,
    External,
}

/// Stable-channel or immutable exact release selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseSelection {
    Stable,
    Exact(ReleaseTag),
}

impl Serialize for ReleaseSelection {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Stable => serializer.serialize_str("stable"),
            Self::Exact(value) => serializer.serialize_str(value.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for ReleaseSelection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == "stable" {
            Ok(Self::Stable)
        } else {
            ReleaseTag::parse(value)
                .map(Self::Exact)
                .map_err(serde::de::Error::custom)
        }
    }
}

/// Strict schema-v1 deployment configuration.
///
/// Unknown fields are rejected. Defaults are applied only to the documented
/// v0.1 defaults; identity, placement, domain, budget, and SSH boundary must be
/// explicit.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub schema_version: u32,
    pub deployment_name: String,
    pub project_id: String,
    pub region: String,
    pub zone: String,
    pub domain: String,
    #[serde(default)]
    pub dns_mode: DnsMode,
    #[serde(default = "default_machine_type")]
    pub machine_type: String,
    #[serde(default = "default_boot_disk_size_gib")]
    pub boot_disk_size_gib: u32,
    #[serde(default = "default_boot_disk_type")]
    pub boot_disk_type: String,
    pub operator_ssh_cidr: String,
    pub maximum_monthly_usd: f64,
    pub release: ReleaseSelection,
    /// Agent implementation selected by `deployer-connect`; `auto` requests
    /// its fail-closed capability selection.
    #[serde(default = "default_connect_agent")]
    pub connect_agent: String,
    /// Whether service-scoped local `dirextalk-connect` should be installed.
    #[serde(default = "default_install_connect")]
    pub install_connect: bool,
}

impl DeploymentConfig {
    /// Parses TOML without ever returning input text in an error.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::ConfigParse`] for malformed, mistyped, or unknown
    /// fields, and [`CoreError::ConfigValidation`] for invalid values.
    pub fn parse(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input).map_err(|_| CoreError::ConfigParse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks cross-field and GCP naming constraints.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::ConfigValidation`] when a field or cross-field
    /// relationship violates schema-v1.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return invalid("schema_version", "must equal 1");
        }
        if self.deployment_name.len() < 3 || !valid_label(&self.deployment_name, 40) {
            return invalid(
                "deployment_name",
                "must be a lowercase DNS label of at most 40 characters",
            );
        }
        if !valid_project_id(&self.project_id) {
            return invalid("project_id", "must be a valid GCP project id");
        }
        if !valid_gcp_location(&self.region) {
            return invalid("region", "must be a lowercase GCP region name");
        }
        if !valid_gcp_location(&self.zone)
            || !self
                .zone
                .strip_prefix(&self.region)
                .is_some_and(|suffix| suffix.starts_with('-') && suffix.len() > 1)
        {
            return invalid("zone", "must be a zone inside the configured region");
        }
        if !valid_domain(&self.domain) {
            return invalid("domain", "must be a canonical lowercase DNS name");
        }
        if !valid_machine_type(&self.machine_type) {
            return invalid("machine_type", "must be a valid GCP machine type name");
        }
        if !(50..=65_536).contains(&self.boot_disk_size_gib) {
            return invalid("boot_disk_size_gib", "must be between 50 and 65536 GiB");
        }
        if !matches!(
            self.boot_disk_type.as_str(),
            "pd-balanced" | "pd-ssd" | "pd-standard"
        ) {
            return invalid(
                "boot_disk_type",
                "must be pd-balanced, pd-ssd, or pd-standard",
            );
        }
        if !valid_ipv4_host_cidr(&self.operator_ssh_cidr) {
            return invalid("operator_ssh_cidr", "must be a canonical IPv4 /32 CIDR");
        }
        self.maximum_monthly_microusd()?;
        if !valid_agent_token(&self.connect_agent) {
            return invalid(
                "connect_agent",
                "must be a lowercase Agent token of at most 63 characters",
            );
        }
        Ok(())
    }

    /// Returns the budget as exact millionths of one USD for canonical plans.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::ConfigValidation`] if the amount is non-positive,
    /// non-finite, out of range, or has more than six fractional digits.
    pub fn maximum_monthly_microusd(&self) -> Result<u64> {
        let amount = self.maximum_monthly_usd;
        if !amount.is_finite() || amount <= 0.0 {
            return invalid("maximum_monthly_usd", "must be a finite positive amount");
        }
        let scaled = amount * 1_000_000.0;
        let rounded = scaled.round();
        if rounded > 9_007_199_254_740_991.0 || (scaled - rounded).abs() > 1e-6 {
            return invalid(
                "maximum_monthly_usd",
                "must fit unsigned micro-USD with at most six fractional digits",
            );
        }
        format!("{rounded:.0}")
            .parse()
            .map_err(|_| CoreError::ConfigValidation {
                field: "maximum_monthly_usd",
                reason: "must fit exact micro-USD",
            })
    }
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T> {
    Err(CoreError::ConfigValidation { field, reason })
}

fn valid_label(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_project_id(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && valid_label(value, 30)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_gcp_location(value: &str) -> bool {
    (3..=63).contains(&value.len()) && valid_label(value, 63) && value.contains('-')
}

fn valid_machine_type(value: &str) -> bool {
    valid_label(value, 63)
}

fn valid_domain(value: &str) -> bool {
    if value.len() > 253 || value.ends_with('.') || !value.contains('.') {
        return false;
    }
    value.split('.').all(|label| valid_label(label, 63))
}

fn valid_ipv4_host_cidr(value: &str) -> bool {
    let Some(address) = value.strip_suffix("/32") else {
        return false;
    };
    let Ok(parsed) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    parsed.to_string() == address
}

fn valid_agent_token(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version = 1
deployment_name = "production"
project_id = "dirextalk-prod"
region = "us-central1"
zone = "us-central1-a"
domain = "talk.example.com"
operator_ssh_cidr = "203.0.113.7/32"
maximum_monthly_usd = 150.0
release = "stable"
"#;

    #[test]
    fn parses_defaults() {
        let config = DeploymentConfig::parse(MINIMAL).unwrap();
        assert_eq!(config.dns_mode, DnsMode::Auto);
        assert_eq!(config.machine_type, "e2-custom-2-4096");
        assert_eq!(config.boot_disk_size_gib, 50);
        assert_eq!(config.boot_disk_type, "pd-balanced");
        assert_eq!(config.connect_agent, "auto");
        assert!(config.install_connect);
    }

    #[test]
    fn accepts_the_explicit_e2_small_shared_core_choice() {
        let configured = format!("{MINIMAL}\nmachine_type = \"e2-small\"\n");
        let config = DeploymentConfig::parse(&configured).expect("e2-small config");
        assert_eq!(config.machine_type, "e2-small");
    }

    #[test]
    fn rejects_unknown_fields_without_echoing_input() {
        let secret = "top-secret-refresh-token";
        let input = format!("{MINIMAL}\nrefresh_token = \"{secret}\"\n");
        let error = DeploymentConfig::parse(&input).unwrap_err();
        assert!(matches!(error, CoreError::ConfigParse));
        assert!(!error.to_string().contains(secret));
    }

    #[test]
    fn rejects_wrong_schema_and_non_host_cidr() {
        let wrong_schema = MINIMAL.replace("schema_version = 1", "schema_version = 2");
        assert!(matches!(
            DeploymentConfig::parse(&wrong_schema),
            Err(CoreError::ConfigValidation {
                field: "schema_version",
                ..
            })
        ));

        let wide_cidr = MINIMAL.replace("203.0.113.7/32", "203.0.113.0/24");
        assert!(matches!(
            DeploymentConfig::parse(&wide_cidr),
            Err(CoreError::ConfigValidation {
                field: "operator_ssh_cidr",
                ..
            })
        ));
    }

    #[test]
    fn rejects_zone_outside_region_and_noncanonical_domain() {
        let bad_zone = MINIMAL.replace("us-central1-a", "us-east1-b");
        assert!(DeploymentConfig::parse(&bad_zone).is_err());
        let bad_domain = MINIMAL.replace("talk.example.com", "Talk.example.com.");
        assert!(DeploymentConfig::parse(&bad_domain).is_err());
    }

    #[test]
    fn exact_release_must_be_bounded_and_identifier_safe() {
        let exact = MINIMAL.replace("release = \"stable\"", "release = \"v0.1.7+build.3\"");
        assert!(matches!(
            DeploymentConfig::parse(&exact),
            Err(CoreError::ConfigParse)
        ));
        let unsafe_release = MINIMAL.replace("release = \"stable\"", "release = \"../latest\"");
        assert!(matches!(
            DeploymentConfig::parse(&unsafe_release),
            Err(CoreError::ConfigParse)
        ));
    }

    #[test]
    fn exact_release_serializes_back_to_the_public_string_shape() {
        let exact = ReleaseSelection::Exact(ReleaseTag::parse("v0.1.7").unwrap());
        assert_eq!(serde_json::to_string(&exact).unwrap(), "\"v0.1.7\"");
    }

    #[test]
    fn connect_agent_type_and_install_intent_are_independent() {
        let configured =
            format!("{MINIMAL}\nconnect_agent = \"codex_local\"\ninstall_connect = false\n");
        let config = DeploymentConfig::parse(&configured).unwrap();
        assert_eq!(config.connect_agent, "codex_local");
        assert!(!config.install_connect);

        let uppercase = format!("{MINIMAL}\nconnect_agent = \"Codex\"\n");
        assert!(matches!(
            DeploymentConfig::parse(&uppercase),
            Err(CoreError::ConfigValidation {
                field: "connect_agent",
                ..
            })
        ));
    }

    #[test]
    fn superseded_boolean_agent_field_is_rejected() {
        let legacy = format!("{MINIMAL}\nlocal_connect_agent = true\n");
        assert!(matches!(
            DeploymentConfig::parse(&legacy),
            Err(CoreError::ConfigParse)
        ));
    }

    #[test]
    fn budget_has_an_exact_canonical_integer_form() {
        let config = DeploymentConfig::parse(MINIMAL).unwrap();
        assert_eq!(config.maximum_monthly_microusd().unwrap(), 150_000_000);
        let excessive_precision = MINIMAL.replace("150.0", "0.1234567");
        assert!(matches!(
            DeploymentConfig::parse(&excessive_precision),
            Err(CoreError::ConfigValidation {
                field: "maximum_monthly_usd",
                ..
            })
        ));
    }
}
