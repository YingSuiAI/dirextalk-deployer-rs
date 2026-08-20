//! GCP-specific authentication, discovery, and resource APIs.
//!
//! Mutations intentionally expose operation creation and polling separately.
//! The caller must persist its pending effect before calling `start_*`, then
//! persist the returned operation before polling it.
#![allow(clippy::missing_errors_doc)]

mod error;
mod lifecycle;
mod oauth;
mod official;
mod preflight;
mod rest;

pub use error::{GcpError, Result};
pub use lifecycle::{
    AddressSpec, DiskSpec, DnsChange, DnsRecordSet, DnsZoneIdentity, FirewallAllowance,
    FirewallSpec, GcpLifecycle, InstanceSpec, NetworkSpec, Operation, OperationFailure,
    OperationScope, OperationState, ResourceIdentity, ResourceKind, ResourceReceipt,
    ResourceSpecRef, SubnetworkSpec, require_dns_change_applied, require_resource_absent,
    validate_dns_zone_identity, validate_resource_identity, validate_resource_properties,
};
pub use oauth::{GcloudAuthBroker, OAuthToken, require_oauth_principal};
pub use official::{GcpImageDiscovery, GoogleCloudClient, ImageIdentity, validate_image_identity};
pub use preflight::{
    BillingStatus, DnsPreflightMode, DnsPreflightStatus, DnsZone, GcpDiscovery, Preflight,
    PreflightReport, PriceTier, ProjectStatus, Quota, QuotaAssessment, RequiredQuota,
    RequiredService, ServiceStatus, SkuPrice, longest_matching_zone,
};
pub use rest::{GoogleRestClient, HttpTransport, ReqwestTransport, RestResponse};
pub(crate) fn ensure_tls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
