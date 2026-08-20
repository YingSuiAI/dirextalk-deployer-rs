//! Stable, secret-free contracts shared by the Dirextalk GCP deployer.
//!
//! The crate owns schema-v1 configuration, canonical plan digests, durable
//! deployment state, and the locked atomic state store. It deliberately has no
//! cloud client or credential API.

mod config;
mod digest;
mod error;
mod model;
mod paths;
mod plan;
mod state_store;

pub use config::{DeploymentConfig, DnsMode, ReleaseSelection, SCHEMA_VERSION};
pub use digest::{PlanDigest, canonical_json, canonical_plan_digest};
pub use error::{CoreError, Result};
pub use model::{
    DeploymentPhase, DeploymentState, EffectAction, GcpResources, HostReceipt, LocalWiringStatus,
    OperationRef, PendingEffect, ProgressEvent, ProgressOperation, ProgressStatus, ProjectIdentity,
    ResourceKind, ResourceRef, SshHostIdentity,
};
pub use paths::{NodePaths, service_id, validate_service_id};
pub use plan::{
    BootDiskDisposition, CanonicalDeploymentSpec, CloudWorkerDisposition, DeploymentPlan,
    DeploymentPlanStage, DestroyPlan, DestroyTarget, DnsChangeApproval, PlanDnsObservation,
    PlannedEffect,
};
pub use state_store::StateStore;
