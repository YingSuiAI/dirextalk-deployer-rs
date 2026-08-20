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
mod secret;

pub use error::{GcpError, Result};
pub use lifecycle::{
    AddressSpec, DiskSpec, DnsChange, DnsRecordSet, FirewallAllowance, FirewallSpec, GcpLifecycle,
    InstanceSpec, NetworkSpec, Operation, OperationFailure, OperationScope, OperationState,
    ResourceIdentity, ResourceKind, ResourceReceipt, SubnetworkSpec, validate_resource_identity,
};
pub use oauth::{
    BrowserLauncher, GoogleInstalledApp, InstalledAppConfig, LoginRequest, OAuthToken,
    SystemBrowser,
};
pub use official::GoogleCloudClient;
pub use preflight::{
    BillingStatus, DnsZone, GcpDiscovery, Preflight, PreflightReport, PriceTier, ProjectStatus,
    Quota, QuotaAssessment, RequiredQuota, RequiredService, ServiceStatus, SkuPrice,
    longest_matching_zone,
};
pub use rest::{GoogleRestClient, HttpTransport, ReqwestTransport, RestResponse};
pub use secret::{
    CredentialStore, EncryptedFileStore, KeyringStore, PassphraseProvider, SecretStore,
};
