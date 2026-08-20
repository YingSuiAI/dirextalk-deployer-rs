use google_cloud_auth::credentials::{
    CacheableResource, Credentials, CredentialsProvider, EntityTag,
};
use http::header::AUTHORIZATION;
use http::{Extensions, HeaderMap, HeaderValue};
use secrecy::{ExposeSecret as _, SecretString};

use async_trait::async_trait;

use crate::{
    BillingStatus, DnsRecordSet, DnsZone, GcpDiscovery, GcpError, GoogleRestClient, PriceTier,
    ProjectStatus, Quota, Result, ServiceStatus, SkuPrice,
};

#[derive(Clone)]
struct InstalledAppAccessToken {
    authorization: HeaderValue,
}

impl std::fmt::Debug for InstalledAppAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledAppAccessToken")
            .field("authorization", &"[REDACTED]")
            .finish()
    }
}

impl CredentialsProvider for InstalledAppAccessToken {
    async fn headers(
        &self,
        _extensions: Extensions,
    ) -> std::result::Result<
        CacheableResource<HeaderMap>,
        google_cloud_auth::errors::CredentialsError,
    > {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());
        Ok(CacheableResource::New {
            entity_tag: EntityTag::new(),
            data: headers,
        })
    }

    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

/// Stable Google API surfaces use Google's generated Rust clients. The only
/// custom REST member is Service Usage, for which Google does not publish a
/// generated Rust client in the stable cloud library set.
#[derive(Clone, Debug)]
pub struct GoogleCloudClient {
    pub(crate) project_id: String,
    pub(crate) project_number: String,
    pub(crate) networks: google_cloud_compute_v1::client::Networks,
    pub(crate) subnetworks: google_cloud_compute_v1::client::Subnetworks,
    pub(crate) firewalls: google_cloud_compute_v1::client::Firewalls,
    pub(crate) addresses: google_cloud_compute_v1::client::Addresses,
    pub(crate) disks: google_cloud_compute_v1::client::Disks,
    pub(crate) instances: google_cloud_compute_v1::client::Instances,
    pub(crate) global_operations: google_cloud_compute_v1::client::GlobalOperations,
    pub(crate) region_operations: google_cloud_compute_v1::client::RegionOperations,
    pub(crate) zone_operations: google_cloud_compute_v1::client::ZoneOperations,
    pub(crate) regions: google_cloud_compute_v1::client::Regions,
    pub(crate) dns_changes: google_cloud_dns_v1::client::Changes,
    pub(crate) dns_zones: google_cloud_dns_v1::client::ManagedZones,
    pub(crate) dns_records: google_cloud_dns_v1::client::ResourceRecordSets,
    pub(crate) billing: google_cloud_billing_v1::client::CloudBilling,
    pub(crate) catalog: google_cloud_billing_v1::client::CloudCatalog,
    pub(crate) projects: google_cloud_resourcemanager_v3::client::Projects,
    pub(crate) service_usage: GoogleRestClient,
}

impl GoogleCloudClient {
    pub async fn new(
        project_id: impl Into<String>,
        project_number: impl Into<String>,
        access_token: SecretString,
    ) -> Result<Self> {
        let project_id = project_id.into();
        let project_number = project_number.into();
        let token = access_token.expose_secret();
        if token.is_empty() || !token.bytes().all(|byte| byte > 0x20 && byte < 0x7f) {
            return Err(GcpError::Authentication(
                "OAuth access token is invalid".into(),
            ));
        }
        let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| GcpError::Authentication("OAuth access token is invalid".into()))?;
        let credentials = Credentials::from(InstalledAppAccessToken { authorization });
        macro_rules! build {
            ($client:path) => {
                <$client>::builder()
                    .with_credentials(credentials.clone())
                    .with_retry_policy(google_cloud_gax::retry_policy::NeverRetry)
                    .build()
                    .await
                    .map_err(|error| {
                        GcpError::Infrastructure(format!(
                            "official Google client initialization failed: {error}"
                        ))
                    })?
            };
        }
        let service_usage =
            GoogleRestClient::new(project_id.clone(), project_number.clone(), access_token);
        Ok(Self {
            project_id,
            project_number,
            networks: build!(google_cloud_compute_v1::client::Networks),
            subnetworks: build!(google_cloud_compute_v1::client::Subnetworks),
            firewalls: build!(google_cloud_compute_v1::client::Firewalls),
            addresses: build!(google_cloud_compute_v1::client::Addresses),
            disks: build!(google_cloud_compute_v1::client::Disks),
            instances: build!(google_cloud_compute_v1::client::Instances),
            global_operations: build!(google_cloud_compute_v1::client::GlobalOperations),
            region_operations: build!(google_cloud_compute_v1::client::RegionOperations),
            zone_operations: build!(google_cloud_compute_v1::client::ZoneOperations),
            regions: build!(google_cloud_compute_v1::client::Regions),
            dns_changes: build!(google_cloud_dns_v1::client::Changes),
            dns_zones: build!(google_cloud_dns_v1::client::ManagedZones),
            dns_records: build!(google_cloud_dns_v1::client::ResourceRecordSets),
            billing: build!(google_cloud_billing_v1::client::CloudBilling),
            catalog: build!(google_cloud_billing_v1::client::CloudCatalog),
            projects: build!(google_cloud_resourcemanager_v3::client::Projects),
            service_usage,
        })
    }
}

pub(crate) fn official_error(error: impl std::fmt::Display) -> GcpError {
    GcpError::Infrastructure(format!("official Google API request failed: {error}"))
}

fn project_status(project: google_cloud_resourcemanager_v3::model::Project) -> ProjectStatus {
    ProjectStatus {
        project_id: project.project_id,
        project_number: project
            .name
            .strip_prefix("projects/")
            .unwrap_or(&project.name)
            .to_owned(),
        display_name: project.display_name,
        lifecycle_state: project
            .state
            .name()
            .unwrap_or("STATE_UNSPECIFIED")
            .to_owned(),
    }
}

#[async_trait]
impl GcpDiscovery for GoogleCloudClient {
    async fn list_projects(&self) -> Result<Vec<ProjectStatus>> {
        let mut token = String::new();
        let mut projects = Vec::new();
        loop {
            let response = self
                .projects
                .search_projects()
                .set_page_token(&token)
                .send()
                .await
                .map_err(official_error)?;
            projects.extend(response.projects.into_iter().map(project_status));
            token = response.next_page_token;
            if token.is_empty() {
                return Ok(projects);
            }
        }
    }

    async fn project(&self, project_id: &str) -> Result<ProjectStatus> {
        let project = self
            .projects
            .get_project()
            .set_name(format!("projects/{project_id}"))
            .send()
            .await
            .map_err(official_error)?;
        Ok(project_status(project))
    }

    async fn billing(&self, project_id: &str) -> Result<BillingStatus> {
        let info = self
            .billing
            .get_project_billing_info()
            .set_name(format!("projects/{project_id}"))
            .send()
            .await
            .map_err(official_error)?;
        Ok(BillingStatus {
            billing_account: (!info.billing_account_name.is_empty())
                .then_some(info.billing_account_name),
            billing_enabled: info.billing_enabled,
        })
    }

    async fn iam_permissions(
        &self,
        project_id: &str,
        permissions: &[String],
    ) -> Result<Vec<String>> {
        let response = self
            .projects
            .test_iam_permissions()
            .set_resource(format!("projects/{project_id}"))
            .set_permissions(permissions.iter().cloned())
            .send()
            .await
            .map_err(official_error)?;
        Ok(response.permissions)
    }

    async fn service(&self, project_number: &str, service: &str) -> Result<ServiceStatus> {
        self.service_usage.service(project_number, service).await
    }

    async fn regional_quotas(&self, project_id: &str, region: &str) -> Result<Vec<Quota>> {
        let response = self
            .regions
            .get()
            .set_project(project_id)
            .set_region(region)
            .send()
            .await
            .map_err(official_error)?;
        Ok(response
            .quotas
            .into_iter()
            .map(|quota| Quota {
                metric: quota
                    .metric
                    .and_then(|metric| metric.name().map(str::to_owned))
                    .unwrap_or_default(),
                limit: quota.limit.unwrap_or_default(),
                usage: quota.usage.unwrap_or_default(),
            })
            .collect())
    }

    async fn public_dns_zones(&self, project_id: &str) -> Result<Vec<DnsZone>> {
        let mut token = String::new();
        let mut zones = Vec::new();
        loop {
            let response = self
                .dns_zones
                .list()
                .set_project(project_id)
                .set_page_token(&token)
                .send()
                .await
                .map_err(official_error)?;
            zones.extend(response.managed_zones.into_iter().filter_map(|zone| {
                let visibility = zone
                    .visibility
                    .and_then(|value| value.name().map(str::to_ascii_lowercase))
                    .unwrap_or_default();
                (visibility == "public").then(|| DnsZone {
                    name: zone.name.unwrap_or_default(),
                    dns_name: zone.dns_name.unwrap_or_default(),
                    visibility,
                    id: zone.id.unwrap_or_default().to_string(),
                })
            }));
            token = response.next_page_token.unwrap_or_default();
            if token.is_empty() {
                return Ok(zones);
            }
        }
    }

    async fn dns_record_set(
        &self,
        project_id: &str,
        managed_zone: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Option<DnsRecordSet>> {
        let response = self
            .dns_records
            .get()
            .set_project(project_id)
            .set_managed_zone(managed_zone)
            .set_name(name)
            .set_type(record_type)
            .send()
            .await;
        match response {
            Ok(record) => Ok(Some(DnsRecordSet {
                name: record.name.unwrap_or_default(),
                record_type: record.r#type.unwrap_or_default(),
                ttl: u32::try_from(record.ttl.unwrap_or_default()).map_err(|_| {
                    GcpError::Infrastructure("Cloud DNS returned an invalid TTL".into())
                })?,
                rrdatas: record.rrdatas,
            })),
            Err(error) if error.http_status_code() == Some(404) => Ok(None),
            Err(error) => Err(official_error(error)),
        }
    }

    async fn prices(&self, billing_service: &str, region: &str) -> Result<Vec<SkuPrice>> {
        let mut token = String::new();
        let mut prices = Vec::new();
        loop {
            let response = self
                .catalog
                .list_skus()
                .set_parent(format!("services/{billing_service}"))
                .set_currency_code("USD")
                .set_page_token(&token)
                .send()
                .await
                .map_err(official_error)?;
            prices.extend(
                response
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
                        let expression = sku.pricing_info.first()?.pricing_expression.as_ref()?;
                        let money = expression.tiered_rates.first()?.unit_price.as_ref()?;
                        Some(SkuPrice {
                            sku_id: sku.sku_id,
                            description: sku.description,
                            service_regions: sku.service_regions,
                            currency_code: money.currency_code.clone(),
                            usage_unit: expression.usage_unit.clone(),
                            usage_unit_description: expression.usage_unit_description.clone(),
                            base_unit: expression.base_unit.clone(),
                            base_unit_conversion_factor: expression.base_unit_conversion_factor,
                            display_quantity: expression.display_quantity,
                            tiers: expression
                                .tiered_rates
                                .iter()
                                .filter_map(|tier| {
                                    let price = tier.unit_price.as_ref()?;
                                    Some(PriceTier {
                                        start_usage_amount: tier.start_usage_amount,
                                        units: price.units,
                                        nanos: price.nanos,
                                    })
                                })
                                .collect(),
                        })
                    }),
            );
            token = response.next_page_token;
            if token.is_empty() {
                return Ok(prices);
            }
        }
    }
}
