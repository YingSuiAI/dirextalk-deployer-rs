use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use crate::{DnsRecordSet, GcpError, GoogleRestClient, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectStatus {
    pub project_id: String,
    pub project_number: String,
    pub display_name: String,
    pub lifecycle_state: String,
}

impl ProjectStatus {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.lifecycle_state == "ACTIVE"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingStatus {
    pub billing_account: Option<String>,
    pub billing_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredService {
    pub name: String,
}

impl RequiredService {
    #[must_use]
    pub fn gcp_v01() -> Vec<Self> {
        [
            "cloudbilling.googleapis.com",
            "cloudresourcemanager.googleapis.com",
            "compute.googleapis.com",
            "dns.googleapis.com",
            "serviceusage.googleapis.com",
        ]
        .into_iter()
        .map(|name| Self { name: name.into() })
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Quota {
    pub metric: String,
    pub limit: f64,
    pub usage: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequiredQuota {
    pub metric: String,
    pub required: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuotaAssessment {
    pub metric: String,
    pub required: f64,
    pub available: f64,
    pub sufficient: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsZone {
    pub name: String,
    pub dns_name: String,
    pub visibility: String,
    pub id: String,
}

impl DnsZone {
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.visibility.eq_ignore_ascii_case("public")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SkuPrice {
    pub sku_id: String,
    pub description: String,
    pub service_regions: Vec<String>,
    pub currency_code: String,
    pub usage_unit: String,
    pub usage_unit_description: String,
    pub base_unit: String,
    pub base_unit_conversion_factor: f64,
    pub display_quantity: f64,
    pub tiers: Vec<PriceTier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PriceTier {
    pub start_usage_amount: f64,
    pub units: i64,
    pub nanos: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreflightReport {
    pub project: ProjectStatus,
    pub billing: BillingStatus,
    pub granted_permissions: Vec<String>,
    pub services: Vec<ServiceStatus>,
    pub quotas: Vec<Quota>,
    pub quota_assessments: Vec<QuotaAssessment>,
    pub zones: Vec<DnsZone>,
    pub prices: Vec<SkuPrice>,
    pub unpriced_costs: Vec<String>,
}

#[async_trait]
pub trait GcpDiscovery: Send + Sync {
    async fn list_projects(&self) -> Result<Vec<ProjectStatus>>;
    async fn project(&self, project_id: &str) -> Result<ProjectStatus>;
    async fn billing(&self, project_id: &str) -> Result<BillingStatus>;
    async fn iam_permissions(
        &self,
        project_id: &str,
        permissions: &[String],
    ) -> Result<Vec<String>>;
    async fn service(&self, project_number: &str, service: &str) -> Result<ServiceStatus>;
    async fn regional_quotas(&self, project_id: &str, region: &str) -> Result<Vec<Quota>>;
    async fn public_dns_zones(&self, project_id: &str) -> Result<Vec<DnsZone>>;
    async fn dns_record_set(
        &self,
        project_id: &str,
        managed_zone: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Option<DnsRecordSet>>;
    async fn prices(&self, billing_service: &str, region: &str) -> Result<Vec<SkuPrice>>;
}

pub struct Preflight<'a, D> {
    discovery: &'a D,
    required_services: Vec<RequiredService>,
    billing_service: String,
    required_permissions: Vec<String>,
    required_quotas: Vec<RequiredQuota>,
}

impl<'a, D: GcpDiscovery> Preflight<'a, D> {
    #[must_use]
    pub fn new(
        discovery: &'a D,
        required_services: Vec<RequiredService>,
        billing_service: impl Into<String>,
    ) -> Self {
        Self {
            discovery,
            required_services: if required_services.is_empty() {
                RequiredService::gcp_v01()
            } else {
                required_services
            },
            billing_service: billing_service.into(),
            required_permissions: required_permissions(),
            required_quotas: vec![
                RequiredQuota {
                    metric: "CPUS".into(),
                    required: 2.0,
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
                    required: 50.0,
                },
            ],
        }
    }

    #[must_use]
    pub fn with_required_quotas(mut self, quotas: Vec<RequiredQuota>) -> Self {
        self.required_quotas = quotas;
        self
    }

    #[must_use]
    pub fn with_required_permissions(mut self, permissions: Vec<String>) -> Self {
        self.required_permissions = permissions;
        self
    }

    pub async fn inspect(&self, project_id: &str, region: &str) -> Result<PreflightReport> {
        let project = self.discovery.project(project_id).await?;
        if !project.is_active() {
            return Err(GcpError::Contract(format!(
                "project {project_id} is not ACTIVE (state {})",
                project.lifecycle_state
            )));
        }
        if project.project_number.is_empty() {
            return Err(GcpError::Contract("project number is missing".into()));
        }
        let billing = self.discovery.billing(project_id).await?;
        if !billing.billing_enabled || billing.billing_account.is_none() {
            return Err(GcpError::Contract(format!(
                "project {project_id} does not have enabled billing"
            )));
        }
        let granted_permissions = self
            .discovery
            .iam_permissions(project_id, &self.required_permissions)
            .await?;
        let missing: Vec<_> = self
            .required_permissions
            .iter()
            .filter(|permission| !granted_permissions.contains(permission))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(GcpError::Contract(format!(
                "OAuth principal lacks required project permissions: {}",
                missing.join(", ")
            )));
        }
        let mut services = Vec::with_capacity(self.required_services.len());
        for required in &self.required_services {
            let service = self
                .discovery
                .service(&project.project_number, &required.name)
                .await?;
            if !service.enabled {
                return Err(GcpError::Contract(format!(
                    "required API {} is not enabled",
                    service.name
                )));
            }
            services.push(service);
        }
        let (quotas, zones, prices) = tokio::try_join!(
            self.discovery.regional_quotas(project_id, region),
            self.discovery.public_dns_zones(project_id),
            self.discovery.prices(&self.billing_service, region),
        )?;
        let quota_assessments: Vec<_> = self
            .required_quotas
            .iter()
            .map(|required| {
                let available = quotas
                    .iter()
                    .find(|quota| quota.metric == required.metric)
                    .map_or(0.0, |quota| quota.limit - quota.usage);
                QuotaAssessment {
                    metric: required.metric.clone(),
                    required: required.required,
                    available,
                    sufficient: available >= required.required,
                }
            })
            .collect();
        let insufficient: Vec<_> = quota_assessments
            .iter()
            .filter(|assessment| !assessment.sufficient)
            .map(|assessment| assessment.metric.as_str())
            .collect();
        if !insufficient.is_empty() {
            return Err(GcpError::Contract(format!(
                "regional quota is insufficient or unavailable: {}",
                insufficient.join(", ")
            )));
        }
        Ok(PreflightReport {
            project,
            billing,
            granted_permissions,
            services,
            quotas,
            quota_assessments,
            zones,
            prices,
            unpriced_costs: vec![
                "internet egress varies by destination and usage".into(),
                "Cloud DNS query charges vary by live query volume".into(),
            ],
        })
    }
}

fn required_permissions() -> Vec<String> {
    [
        "compute.addresses.create",
        "compute.addresses.delete",
        "compute.addresses.get",
        "compute.disks.create",
        "compute.disks.delete",
        "compute.disks.get",
        "compute.firewalls.create",
        "compute.firewalls.delete",
        "compute.firewalls.get",
        "compute.instances.create",
        "compute.instances.delete",
        "compute.instances.get",
        "compute.networks.create",
        "compute.networks.delete",
        "compute.networks.get",
        "compute.subnetworks.create",
        "compute.subnetworks.delete",
        "compute.subnetworks.get",
        "compute.globalOperations.get",
        "compute.regionOperations.get",
        "compute.zoneOperations.get",
        "dns.changes.create",
        "dns.managedZones.list",
        "dns.resourceRecordSets.list",
        "resourcemanager.projects.get",
        "serviceusage.services.get",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Selects the public zone with the most DNS labels that is an ancestor of the
/// requested record. Both inputs are normalized to lowercase absolute names.
#[must_use]
pub fn longest_matching_zone<'a>(record: &str, zones: &'a [DnsZone]) -> Option<&'a DnsZone> {
    let record = absolute_dns_name(record)?;
    zones
        .iter()
        .filter(|zone| zone.is_public())
        .filter_map(|zone| {
            let suffix = absolute_dns_name(&zone.dns_name)?;
            let matches = record == suffix
                || record
                    .strip_suffix(&suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'));
            matches.then_some((suffix.matches('.').count(), zone))
        })
        .max_by_key(|(labels, _)| *labels)
        .map(|(_, zone)| zone)
}

fn absolute_dns_name(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        None
    } else {
        Some(format!("{value}."))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectWire {
    project_id: String,
    project_number: String,
    #[serde(default)]
    name: String,
    lifecycle_state: String,
}

impl From<ProjectWire> for ProjectStatus {
    fn from(value: ProjectWire) -> Self {
        Self {
            project_id: value.project_id,
            project_number: value.project_number,
            display_name: value.name,
            lifecycle_state: value.lifecycle_state,
        }
    }
}

#[async_trait]
impl GcpDiscovery for GoogleRestClient {
    async fn list_projects(&self) -> Result<Vec<ProjectStatus>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            projects: Vec<ProjectWire>,
        }
        let url = Url::parse("https://cloudresourcemanager.googleapis.com/v1/projects")?;
        let response: Response = self.get(url).await?;
        Ok(response.projects.into_iter().map(Into::into).collect())
    }

    async fn project(&self, project_id: &str) -> Result<ProjectStatus> {
        let url = Url::parse(&format!(
            "https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
        ))?;
        Ok(self.get::<ProjectWire>(url).await?.into())
    }

    async fn billing(&self, project_id: &str) -> Result<BillingStatus> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            billing_account_name: Option<String>,
            billing_enabled: bool,
        }
        let url = Url::parse(&format!(
            "https://cloudbilling.googleapis.com/v1/projects/{project_id}/billingInfo"
        ))?;
        let response: Response = self.get(url).await?;
        Ok(BillingStatus {
            billing_account: response.billing_account_name,
            billing_enabled: response.billing_enabled,
        })
    }

    async fn iam_permissions(
        &self,
        project_id: &str,
        permissions: &[String],
    ) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            permissions: Vec<String>,
        }
        let url = Url::parse(&format!(
            "https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:testIamPermissions"
        ))?;
        let response: Response = self
            .mutate(
                http::Method::POST,
                url,
                Some(serde_json::json!({ "permissions": permissions })),
            )
            .await?;
        Ok(response.permissions)
    }

    async fn service(&self, project_number: &str, service: &str) -> Result<ServiceStatus> {
        #[derive(Deserialize)]
        struct Response {
            name: String,
            state: String,
        }
        let url = Url::parse(&format!(
            "https://serviceusage.googleapis.com/v1/projects/{project_number}/services/{service}"
        ))?;
        let response: Response = self.get(url).await?;
        Ok(ServiceStatus {
            name: response.name,
            enabled: response.state == "ENABLED",
        })
    }

    async fn regional_quotas(&self, project_id: &str, region: &str) -> Result<Vec<Quota>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            quotas: Vec<QuotaWire>,
        }
        #[derive(Deserialize)]
        struct QuotaWire {
            metric: String,
            limit: f64,
            usage: f64,
        }
        let url = Url::parse(&format!(
            "https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}"
        ))?;
        let response: Response = self.get(url).await?;
        Ok(response
            .quotas
            .into_iter()
            .map(|quota| Quota {
                metric: quota.metric,
                limit: quota.limit,
                usage: quota.usage,
            })
            .collect())
    }

    async fn public_dns_zones(&self, project_id: &str) -> Result<Vec<DnsZone>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            #[serde(default)]
            managed_zones: Vec<ZoneWire>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ZoneWire {
            name: String,
            dns_name: String,
            visibility: String,
            id: String,
        }
        let url = Url::parse(&format!(
            "https://dns.googleapis.com/dns/v1/projects/{project_id}/managedZones"
        ))?;
        let response: Response = self.get(url).await?;
        Ok(response
            .managed_zones
            .into_iter()
            .filter(|zone| zone.visibility.eq_ignore_ascii_case("public"))
            .map(|zone| DnsZone {
                name: zone.name,
                dns_name: zone.dns_name,
                visibility: zone.visibility,
                id: zone.id,
            })
            .collect())
    }

    async fn dns_record_set(
        &self,
        project_id: &str,
        managed_zone: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Option<DnsRecordSet>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(default, rename = "rrsets")]
            records: Vec<DnsRecordSetWire>,
        }
        #[derive(Deserialize)]
        struct DnsRecordSetWire {
            name: String,
            #[serde(rename = "type")]
            record_type: String,
            ttl: u32,
            #[serde(default)]
            rrdatas: Vec<String>,
        }
        let mut url = Url::parse(&format!(
            "https://dns.googleapis.com/dns/v1/projects/{project_id}/managedZones/{managed_zone}/rrsets"
        ))?;
        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("type", record_type);
        let response: Response = self.get(url).await?;
        Ok(response
            .records
            .into_iter()
            .next()
            .map(|record| DnsRecordSet {
                name: record.name,
                record_type: record.record_type,
                ttl: record.ttl,
                rrdatas: record.rrdatas,
            }))
    }

    async fn prices(&self, billing_service: &str, region: &str) -> Result<Vec<SkuPrice>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            skus: Vec<SkuWire>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SkuWire {
            sku_id: String,
            description: String,
            #[serde(default)]
            service_regions: Vec<String>,
            #[serde(default)]
            pricing_info: Vec<PricingInfo>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PricingInfo {
            pricing_expression: PricingExpression,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PricingExpression {
            #[serde(default)]
            usage_unit: String,
            #[serde(default)]
            usage_unit_description: String,
            #[serde(default)]
            base_unit: String,
            #[serde(default)]
            base_unit_conversion_factor: f64,
            #[serde(default)]
            display_quantity: f64,
            #[serde(default)]
            tiered_rates: Vec<Tier>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Tier {
            #[serde(default)]
            start_usage_amount: f64,
            unit_price: Money,
        }
        #[derive(Clone, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Money {
            currency_code: String,
            #[serde(default, deserialize_with = "deserialize_i64")]
            units: i64,
            #[serde(default)]
            nanos: i32,
        }
        let mut url = Url::parse(&format!(
            "https://cloudbilling.googleapis.com/v1/services/{billing_service}/skus"
        ))?;
        url.query_pairs_mut().append_pair("currencyCode", "USD");
        let response: Response = self.get(url).await?;
        Ok(response
            .skus
            .into_iter()
            .filter(|sku| {
                sku.service_regions.is_empty()
                    || sku
                        .service_regions
                        .iter()
                        .any(|value| value == region || value == "global")
            })
            .filter_map(|sku| {
                let expression = &sku.pricing_info.first()?.pricing_expression;
                let first_money = expression.tiered_rates.first()?.unit_price.clone();
                Some(SkuPrice {
                    sku_id: sku.sku_id,
                    description: sku.description,
                    service_regions: sku.service_regions,
                    currency_code: first_money.currency_code,
                    usage_unit: expression.usage_unit.clone(),
                    usage_unit_description: expression.usage_unit_description.clone(),
                    base_unit: expression.base_unit.clone(),
                    base_unit_conversion_factor: expression.base_unit_conversion_factor,
                    display_quantity: expression.display_quantity,
                    tiers: expression
                        .tiered_rates
                        .iter()
                        .map(|tier| PriceTier {
                            start_usage_amount: tier.start_usage_amount,
                            units: tier.unit_price.units,
                            nanos: tier.unit_price.nanos,
                        })
                        .collect(),
                })
            })
            .collect())
    }
}

fn deserialize_i64<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Integer(i64),
        String(String),
    }
    match Number::deserialize(deserializer)? {
        Number::Integer(value) => Ok(value),
        Number::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    #[derive(Clone)]
    struct Fake {
        project_state: &'static str,
        billing_enabled: bool,
        iam_granted: bool,
        quota_sufficient: bool,
    }

    #[async_trait]
    impl GcpDiscovery for Fake {
        async fn list_projects(&self) -> Result<Vec<ProjectStatus>> {
            Ok(vec![])
        }
        async fn project(&self, project_id: &str) -> Result<ProjectStatus> {
            Ok(ProjectStatus {
                project_id: project_id.into(),
                project_number: "123".into(),
                display_name: "test".into(),
                lifecycle_state: self.project_state.into(),
            })
        }
        async fn billing(&self, _project_id: &str) -> Result<BillingStatus> {
            Ok(BillingStatus {
                billing_account: self.billing_enabled.then(|| "billingAccounts/1".into()),
                billing_enabled: self.billing_enabled,
            })
        }
        async fn iam_permissions(
            &self,
            _project_id: &str,
            permissions: &[String],
        ) -> Result<Vec<String>> {
            Ok(if self.iam_granted {
                permissions.to_vec()
            } else {
                vec![]
            })
        }
        async fn service(&self, _project_number: &str, service: &str) -> Result<ServiceStatus> {
            Ok(ServiceStatus {
                name: service.into(),
                enabled: true,
            })
        }
        async fn regional_quotas(&self, _project_id: &str, _region: &str) -> Result<Vec<Quota>> {
            let available = if self.quota_sufficient { 100.0 } else { 0.0 };
            Ok(["CPUS", "INSTANCES", "IN_USE_ADDRESSES", "SSD_TOTAL_GB"]
                .into_iter()
                .map(|metric| Quota {
                    metric: metric.into(),
                    limit: available,
                    usage: 0.0,
                })
                .collect())
        }
        async fn public_dns_zones(&self, _project_id: &str) -> Result<Vec<DnsZone>> {
            Ok(vec![])
        }
        async fn dns_record_set(
            &self,
            _project_id: &str,
            _managed_zone: &str,
            _name: &str,
            _record_type: &str,
        ) -> Result<Option<DnsRecordSet>> {
            Ok(None)
        }
        async fn prices(&self, _billing_service: &str, _region: &str) -> Result<Vec<SkuPrice>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn preflight_rejects_inactive_project_before_billing() {
        let fake = Fake {
            project_state: "DELETE_REQUESTED",
            billing_enabled: true,
            iam_granted: true,
            quota_sufficient: true,
        };
        let error = Preflight::new(&fake, vec![], "compute")
            .inspect("project", "us-central1")
            .await
            .expect_err("inactive");
        assert!(matches!(error, GcpError::Contract(message) if message.contains("not ACTIVE")));
    }

    #[tokio::test]
    async fn preflight_rejects_unlinked_billing() {
        let fake = Fake {
            project_state: "ACTIVE",
            billing_enabled: false,
            iam_granted: true,
            quota_sufficient: true,
        };
        let error = Preflight::new(&fake, vec![], "compute")
            .inspect("project", "us-central1")
            .await
            .expect_err("billing");
        assert!(matches!(error, GcpError::Contract(message) if message.contains("billing")));
    }

    #[tokio::test]
    async fn preflight_rejects_missing_iam_permissions() {
        let fake = Fake {
            project_state: "ACTIVE",
            billing_enabled: true,
            iam_granted: false,
            quota_sufficient: true,
        };
        let error = Preflight::new(&fake, vec![], "compute")
            .inspect("project", "us-central1")
            .await
            .expect_err("IAM");
        assert!(matches!(error, GcpError::Contract(message) if message.contains("permissions")));
    }

    #[tokio::test]
    async fn preflight_rejects_insufficient_quota() {
        let fake = Fake {
            project_state: "ACTIVE",
            billing_enabled: true,
            iam_granted: true,
            quota_sufficient: false,
        };
        let error = Preflight::new(&fake, vec![], "compute")
            .inspect("project", "us-central1")
            .await
            .expect_err("quota");
        assert!(matches!(error, GcpError::Contract(message) if message.contains("quota")));
    }

    #[test]
    fn chooses_longest_public_zone_on_label_boundary() {
        let zones = vec![
            DnsZone {
                name: "root".into(),
                dns_name: "example.com.".into(),
                visibility: "public".into(),
                id: "1".into(),
            },
            DnsZone {
                name: "sub".into(),
                dns_name: "prod.example.com.".into(),
                visibility: "public".into(),
                id: "2".into(),
            },
            DnsZone {
                name: "private".into(),
                dns_name: "app.prod.example.com.".into(),
                visibility: "private".into(),
                id: "3".into(),
            },
        ];
        assert_eq!(
            longest_matching_zone("api.prod.example.com", &zones).map(|zone| zone.name.as_str()),
            Some("sub")
        );
        assert!(longest_matching_zone("notexample.com", &zones).is_none());
    }
}
