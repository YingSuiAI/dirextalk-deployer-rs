use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use fs4::{FileExt, TryLockError};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CoreError, DeploymentState, NodePaths, PlanDigest, Result, canonical_json};

/// A process-exclusive, atomic state store for one deployment.
///
/// The exclusive lock is held until this value is dropped. State is written by
/// same-directory atomic replacement, is mode-restricted on Unix, and carries
/// a canonical SHA-256 integrity digest.
pub struct StateStore {
    paths: NodePaths,
    lock: File,
    seal_key: Zeroizing<[u8; 32]>,
    directory_identity: FilesystemIdentity,
    lock_identity: FilesystemIdentity,
    seal_key_identity: FilesystemIdentity,
}

impl StateStore {
    /// Opens and exclusively locks a service store below `nodes_root`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, wrong owner, conflicting lock, or
    /// filesystem failure.
    pub fn open(nodes_root: impl AsRef<Path>, service_id: &str) -> Result<Self> {
        let paths = NodePaths::new(nodes_root, service_id)?;
        prepare_directory(paths.root())?;
        reject_symlink(&paths.lock_file())?;
        let lock = open_restricted(&paths.lock_file(), true)?;
        FileExt::try_lock(&lock).map_err(|error| match error {
            TryLockError::WouldBlock => CoreError::Locked,
            TryLockError::Error(error) => CoreError::io("lock", error),
        })?;
        validate_owner(paths.root())?;
        validate_owner_file(&lock)?;
        let directory_identity = path_identity(paths.root())?;
        let lock_identity = file_identity(&lock)?;
        let seal_key = load_or_create_seal_key(&paths)?;
        let seal_key_identity = path_identity(&paths.state_seal_key_file())?;
        let store = Self {
            paths,
            lock,
            seal_key,
            directory_identity,
            lock_identity,
            seal_key_identity,
        };
        store.revalidate_filesystem_identity()?;
        Ok(store)
    }

    #[must_use]
    pub fn paths(&self) -> &NodePaths {
        &self.paths
    }

    /// Reads and authenticates current state. Missing state returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe files, wrong ownership, malformed state,
    /// broken invariants, failed integrity, or filesystem failure.
    pub fn read(&self) -> Result<Option<DeploymentState>> {
        self.revalidate_filesystem_identity()?;
        let path = self.paths.state_file();
        reject_symlink(&path)?;
        let mut file = match open_read_restricted(&path) {
            Ok(file) => file,
            Err(CoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        validate_owner_file(&file)?;
        restrict_file(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| CoreError::io("read", error))?;
        let mut state: DeploymentState =
            serde_json::from_slice(&bytes).map_err(|_| CoreError::StateDecode)?;
        let persisted_digest = decode_state_digest(&state.integrity_digest)?;
        state.integrity_digest.clear();
        verify_state_digest(&state, &self.seal_key, &persisted_digest)?;
        state.validate()?;
        state.integrity_digest = format!("hmac-sha256:{}", hex::encode(persisted_digest));
        Ok(Some(state))
    }

    /// Validates, seals, synchronizes, and atomically replaces state.
    ///
    /// # Errors
    ///
    /// Returns an error if state invariants fail, the service id differs from
    /// the locked path, or an atomic filesystem operation fails.
    pub fn write(&self, state: &DeploymentState) -> Result<()> {
        self.revalidate_filesystem_identity()?;
        state.validate()?;
        if state.service_id
            != self
                .paths
                .root()
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
        {
            return Err(CoreError::InvalidState(
                "service id does not match state path",
            ));
        }
        let mut sealed = state.clone();
        sealed.integrity_digest.clear();
        sealed.integrity_digest = encode_state_digest(&sealed, &self.seal_key)?;
        let bytes = canonical_json(&sealed)?;

        reject_symlink(&self.paths.state_file())?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".state-")
            .suffix(".tmp")
            .tempfile_in(self.paths.root())
            .map_err(|error| CoreError::io("create temporary state", error))?;
        restrict_file(temporary.as_file())?;
        temporary
            .write_all(&bytes)
            .map_err(|error| CoreError::io("write temporary state", error))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| CoreError::io("synchronize temporary state", error))?;
        temporary
            .persist(self.paths.state_file())
            .map_err(|error| CoreError::io("replace state", error.error))?;
        sync_directory(self.paths.root())?;
        self.revalidate_filesystem_identity()?;
        Ok(())
    }

    fn revalidate_filesystem_identity(&self) -> Result<()> {
        reject_symlink(self.paths.root())?;
        reject_symlink(&self.paths.lock_file())?;
        reject_symlink(&self.paths.state_seal_key_file())?;
        if path_identity(self.paths.root())? != self.directory_identity
            || path_identity(&self.paths.lock_file())? != self.lock_identity
            || path_identity(&self.paths.state_seal_key_file())? != self.seal_key_identity
        {
            return Err(CoreError::UnsafeFilesystemObject);
        }
        validate_owner(self.paths.root())?;
        validate_owner(&self.paths.state_seal_key_file())?;
        validate_owner_file(&self.lock)
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilesystemIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilesystemIdentity;

#[cfg(unix)]
fn path_identity(path: &Path) -> Result<FilesystemIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path).map_err(|error| CoreError::io("inspect identity", error))?;
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn path_identity(path: &Path) -> Result<FilesystemIdentity> {
    fs::metadata(path).map_err(|error| CoreError::io("inspect identity", error))?;
    Ok(FilesystemIdentity)
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<FilesystemIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|error| CoreError::io("inspect identity", error))?;
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn file_identity(file: &File) -> Result<FilesystemIdentity> {
    file.metadata()
        .map_err(|error| CoreError::io("inspect identity", error))?;
    Ok(FilesystemIdentity)
}

#[derive(Serialize)]
struct StateForDigest<'a> {
    schema_version: u32,
    deployment_uuid: uuid::Uuid,
    service_id: &'a str,
    project_identity: &'a crate::ProjectIdentity,
    phase: crate::DeploymentPhase,
    approved_plan_digest: &'a Option<PlanDigest>,
    pending_effect: &'a Option<crate::PendingEffect>,
    active_destroy: &'a Option<crate::ActiveDestroyPlan>,
    release_identity: &'a Option<crate::ExactReleaseIdentity>,
    gcp_resources: &'a crate::GcpResources,
    ssh_host_identity: &'a Option<crate::SshHostIdentity>,
    host_receipt: &'a Option<crate::HostReceipt>,
    local_wiring: &'a crate::LocalWiringStatus,
}

fn state_digest_input(state: &DeploymentState) -> Result<Vec<u8>> {
    canonical_json(&StateForDigest {
        schema_version: state.schema_version,
        deployment_uuid: state.deployment_uuid,
        service_id: &state.service_id,
        project_identity: &state.project_identity,
        phase: state.phase,
        approved_plan_digest: &state.approved_plan_digest,
        pending_effect: &state.pending_effect,
        active_destroy: &state.active_destroy,
        release_identity: &state.release_identity,
        gcp_resources: &state.gcp_resources,
        ssh_host_identity: &state.ssh_host_identity,
        host_receipt: &state.host_receipt,
        local_wiring: &state.local_wiring,
    })
}

fn encode_state_digest(state: &DeploymentState, key: &[u8; 32]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CoreError::Integrity)?;
    mac.update(&state_digest_input(state)?);
    Ok(format!(
        "hmac-sha256:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

fn decode_state_digest(value: &str) -> Result<[u8; 32]> {
    let encoded = value
        .strip_prefix("hmac-sha256:")
        .ok_or(CoreError::Integrity)?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::Integrity);
    }
    let bytes = hex::decode(encoded).map_err(|_| CoreError::Integrity)?;
    bytes.try_into().map_err(|_| CoreError::Integrity)
}

fn verify_state_digest(state: &DeploymentState, key: &[u8; 32], digest: &[u8; 32]) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CoreError::Integrity)?;
    mac.update(&state_digest_input(state)?);
    mac.verify_slice(digest).map_err(|_| CoreError::Integrity)
}

fn load_or_create_seal_key(paths: &NodePaths) -> Result<Zeroizing<[u8; 32]>> {
    let path = paths.state_seal_key_file();
    reject_symlink(&path)?;
    match open_read_restricted(&path) {
        Ok(file) => {
            validate_owner_file(&file)?;
            restrict_file(&file)?;
            let mut bytes = Zeroizing::new(Vec::new());
            file.take(33)
                .read_to_end(&mut bytes)
                .map_err(|error| CoreError::io("read state seal key", error))?;
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::Integrity)?;
            Ok(Zeroizing::new(key))
        }
        Err(CoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            create_seal_key(&path)
        }
        Err(error) => Err(error),
    }
}

fn create_seal_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(rand::random::<[u8; 32]>());
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_secure_open(&mut options, 0o600);
    let mut file = options
        .open(path)
        .map_err(|error| CoreError::io("create state seal key", error))?;
    restrict_file(&file)?;
    file.write_all(key.as_ref())
        .map_err(|error| CoreError::io("write state seal key", error))?;
    file.sync_all()
        .map_err(|error| CoreError::io("synchronize state seal key", error))?;
    Ok(key)
}

fn prepare_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| CoreError::io("inspect directory", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CoreError::UnsafeFilesystemObject);
        }
    } else {
        fs::create_dir_all(path).map_err(|error| CoreError::io("create directory", error))?;
    }
    restrict_directory(path)
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CoreError::UnsafeFilesystemObject),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoreError::io("inspect path", error)),
    }
}

fn open_restricted(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    configure_secure_open(&mut options, 0o600);
    let file = options
        .open(path)
        .map_err(|error| CoreError::io("open lock", error))?;
    restrict_file(&file)?;
    Ok(file)
}

fn open_read_restricted(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_open(&mut options, 0o600);
    options
        .open(path)
        .map_err(|error| CoreError::io("open state", error))
}

#[cfg(unix)]
fn configure_secure_open(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    options
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(not(unix))]
fn configure_secure_open(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| CoreError::io("restrict directory", error))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| CoreError::io("restrict file", error))
}

#[cfg(not(unix))]
fn restrict_file(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).map_err(|error| CoreError::io("inspect owner", error))?;
    if metadata.uid() != effective_uid() {
        return Err(CoreError::WrongOwner);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_owner_file(file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::io("inspect owner", error))?;
    if metadata.uid() != effective_uid() {
        return Err(CoreError::WrongOwner);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_file(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path).map_err(|error| CoreError::io("open directory", error))?;
    directory
        .sync_all()
        .map_err(|error| CoreError::io("synchronize directory", error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use uuid::Uuid;

    use super::*;
    use crate::release::test_release_identity;
    use crate::{
        ActiveDestroyPlan, DeploymentPhase, DestroyPlan, GcpResources, GoogleSubject,
        LocalWiringStatus, ProjectIdentity, ResourceKind, ResourceRef,
    };

    fn state(service_id: &str) -> DeploymentState {
        DeploymentState {
            schema_version: 1,
            deployment_uuid: Uuid::new_v4(),
            service_id: service_id.to_owned(),
            project_identity: ProjectIdentity {
                project_id: "dirextalk-prod".to_owned(),
                project_number: 42,
                oauth_principal: GoogleSubject::parse("operator.example").unwrap(),
            },
            phase: DeploymentPhase::Applying,
            approved_plan_digest: Some(
                "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
                    .parse()
                    .unwrap(),
            ),
            pending_effect: None,
            active_destroy: None,
            release_identity: Some(test_release_identity()),
            gcp_resources: GcpResources::default(),
            ssh_host_identity: None,
            host_receipt: None,
            local_wiring: LocalWiringStatus::default(),
            integrity_digest: String::new(),
        }
    }

    #[test]
    fn atomically_reopens_and_detects_tampering() {
        let temporary = tempfile::tempdir().unwrap();
        let service_id = "production-0123456789ab";
        {
            let store = StateStore::open(temporary.path(), service_id).unwrap();
            assert!(store.read().unwrap().is_none());
            store.write(&state(service_id)).unwrap();
            let read = store.read().unwrap().unwrap();
            assert!(read.integrity_digest.starts_with("hmac-sha256:"));
            assert_eq!(read.release_identity, Some(test_release_identity()));
        }
        {
            let store = StateStore::open(temporary.path(), service_id).unwrap();
            assert_eq!(
                store.read().unwrap().unwrap().phase,
                DeploymentPhase::Applying
            );
        }

        let state_path = temporary.path().join(service_id).join("state.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        value["phase"] = serde_json::Value::String("complete".to_owned());
        fs::write(&state_path, serde_json::to_vec(&value).unwrap()).unwrap();
        let store = StateStore::open(temporary.path(), service_id).unwrap();
        assert!(matches!(store.read(), Err(CoreError::Integrity)));
    }

    #[test]
    fn sealed_round_trip_preserves_active_destroy_cursor() {
        let temporary = tempfile::tempdir().unwrap();
        let service_id = "production-0123456789ab";
        let mut state = state(service_id);
        state.gcp_resources.network = Some(ResourceRef {
            resource_kind: ResourceKind::Network,
            name: "network".to_owned(),
            project_number: 42,
            location: "global".to_owned(),
            numeric_id: 11,
            self_link: "https://compute.googleapis.com/network/11".to_owned(),
            deployment_uuid: state.deployment_uuid,
            observed_attributes: BTreeMap::from([("name".to_owned(), "network".to_owned())]),
        });
        let plan = DestroyPlan::from_state(&state, None).unwrap();
        let digest = plan.digest().unwrap();
        state.phase = DeploymentPhase::Destroying;
        state.active_destroy = Some(ActiveDestroyPlan::new(plan, digest).unwrap());

        let store = StateStore::open(temporary.path(), service_id).unwrap();
        store.write(&state).unwrap();
        let reopened = store.read().unwrap().unwrap();
        assert_eq!(reopened.active_destroy, state.active_destroy);
    }

    #[test]
    fn second_store_cannot_acquire_lock() {
        let temporary = tempfile::tempdir().unwrap();
        let service_id = "production-0123456789ab";
        let _first = StateStore::open(temporary.path(), service_id).unwrap();
        assert!(matches!(
            StateStore::open(temporary.path(), service_id),
            Err(CoreError::Locked)
        ));
    }

    #[test]
    fn write_rejects_cross_service_state() {
        let temporary = tempfile::tempdir().unwrap();
        let store = StateStore::open(temporary.path(), "production-0123456789ab").unwrap();
        assert!(matches!(
            store.write(&state("different-0123456789ab")),
            Err(CoreError::InvalidState(
                "service id does not match state path"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let service_id = "production-0123456789ab";
        let store = StateStore::open(temporary.path(), service_id).unwrap();
        store.write(&state(service_id)).unwrap();
        let root_mode = fs::metadata(store.paths().root())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let state_mode = fs::metadata(store.paths().state_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let lock_mode = fs::metadata(store.paths().lock_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = fs::metadata(store.paths().state_seal_key_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(state_mode, 0o600);
        assert_eq!(lock_mode, 0o600);
        assert_eq!(key_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_same_name_directory_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let service_id = "production-0123456789ab";
        let store = StateStore::open(temporary.path(), service_id).unwrap();
        let original = temporary.path().join(service_id);
        let displaced = temporary.path().join("displaced-service");
        fs::rename(&original, &displaced).unwrap();
        fs::create_dir(&original).unwrap();
        assert!(matches!(
            store.write(&state(service_id)),
            Err(CoreError::UnsafeFilesystemObject)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_same_name_seal_key_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let service_id = "production-0123456789ab";
        let store = StateStore::open(temporary.path(), service_id).unwrap();
        let key_path = store.paths().state_seal_key_file();
        let displaced = store.paths().root().join("displaced-state.key");
        fs::rename(&key_path, displaced).unwrap();
        fs::write(&key_path, [7_u8; 32]).unwrap();
        assert!(matches!(
            store.write(&state(service_id)),
            Err(CoreError::UnsafeFilesystemObject)
        ));
    }

    #[test]
    fn state_json_has_no_secret_bearing_fields() {
        let serialized = serde_json::to_value(state("production-0123456789ab")).unwrap();
        let object = serialized.as_object().unwrap();
        for forbidden in [
            "access_token",
            "refresh_token",
            "matrix_token",
            "agent_token",
            "private_key",
            "initialization_code",
        ] {
            assert!(!object.contains_key(forbidden));
        }
        let _ = BTreeMap::<String, String>::new();
    }
}
