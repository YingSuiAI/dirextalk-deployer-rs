#[cfg(not(target_os = "linux"))]
use std::fs;
use std::fs::File;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{GcpError, Result};

pub trait SecretStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<SecretString>>;
    fn set(&self, account: &str, value: &SecretString) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

pub trait PassphraseProvider: Send + Sync {
    fn passphrase(&self) -> Result<SecretString>;
}

#[derive(Clone)]
struct FixedPassphraseProvider {
    passphrase: SecretString,
}

impl PassphraseProvider for FixedPassphraseProvider {
    fn passphrase(&self) -> Result<SecretString> {
        Ok(self.passphrase.clone())
    }
}

#[derive(Debug, Clone)]
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, account).map_err(classify_keyring_error)
    }
}

impl SecretStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        match self.entry(account)?.get_password() {
            Ok(value) => Ok(Some(SecretString::from(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(classify_keyring_error(error)),
        }
    }

    fn set(&self, account: &str, value: &SecretString) -> Result<()> {
        self.entry(account)?
            .set_password(value.expose_secret())
            .map_err(classify_keyring_error)
    }

    fn delete(&self, account: &str) -> Result<()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(classify_keyring_error(error)),
        }
    }
}

#[derive(Clone)]
pub struct EncryptedFileStore {
    directory: PathBuf,
    service: String,
    passphrase_provider: Arc<dyn PassphraseProvider>,
}

impl std::fmt::Debug for EncryptedFileStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedFileStore")
            .field("directory", &self.directory)
            .field("service", &self.service)
            .field("passphrase_provider", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptedFileStore {
    #[must_use]
    pub fn new(
        directory: impl Into<PathBuf>,
        service: impl Into<String>,
        passphrase: SecretString,
    ) -> Self {
        Self::with_passphrase_provider(
            directory,
            service,
            Arc::new(FixedPassphraseProvider { passphrase }),
        )
    }

    #[must_use]
    pub fn with_passphrase_provider(
        directory: impl Into<PathBuf>,
        service: impl Into<String>,
        passphrase_provider: Arc<dyn PassphraseProvider>,
    ) -> Self {
        Self {
            directory: directory.into(),
            service: service.into(),
            passphrase_provider,
        }
    }

    fn path(&self, account: &str) -> PathBuf {
        let digest = Sha256::digest(format!("{}\0{account}", self.service).as_bytes());
        self.directory
            .join(format!("{}.credential", hex_lower(&digest)))
    }

    fn aad(&self, account: &str) -> Vec<u8> {
        format!("dirextalk-gcp-credential-v1\0{}\0{account}", self.service).into_bytes()
    }

    fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let passphrase = self.passphrase_provider.passphrase()?;
        if passphrase.expose_secret().chars().count() < 16 {
            return Err(GcpError::CredentialStorage(
                "encrypted credential fallback requires a passphrase of at least 16 characters"
                    .into(),
            ));
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase.expose_secret().as_bytes(), salt, key.as_mut())
            .map_err(|_| GcpError::CredentialStorage("Argon2id key derivation failed".into()))?;
        Ok(key)
    }

    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        atomic_write_secure(&self.directory, path, bytes)
    }
}

impl SecretStore for EncryptedFileStore {
    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        let path = self.path(account);
        let Some(bytes) = read_secure(&self.directory, &path)? else {
            return Ok(None);
        };
        let envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| GcpError::CredentialStorage("credential envelope is invalid".into()))?;
        if envelope.version != 1 {
            return Err(GcpError::CredentialStorage(
                "unsupported credential envelope version".into(),
            ));
        }
        let salt = decode_field("salt", &envelope.salt)?;
        let nonce = decode_field("nonce", &envelope.nonce)?;
        let ciphertext = decode_field("ciphertext", &envelope.ciphertext)?;
        if nonce.len() != 12 {
            return Err(GcpError::CredentialStorage(
                "credential nonce has invalid length".into(),
            ));
        }
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| GcpError::CredentialStorage("invalid encryption key".into()))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &self.aad(account),
                },
            )
            .map_err(|_| GcpError::CredentialStorage("credential decryption failed".into()))?;
        let plaintext = Zeroizing::new(plaintext);
        let value = String::from_utf8(plaintext.to_vec())
            .map_err(|_| GcpError::CredentialStorage("credential is not valid UTF-8".into()))?;
        Ok(Some(SecretString::from(value)))
    }

    fn set(&self, account: &str, value: &SecretString) -> Result<()> {
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| GcpError::CredentialStorage("invalid encryption key".into()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value.expose_secret().as_bytes(),
                    aad: &self.aad(account),
                },
            )
            .map_err(|_| GcpError::CredentialStorage("credential encryption failed".into()))?;
        let envelope = Envelope {
            version: 1,
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        self.atomic_write(&self.path(account), &serde_json::to_vec(&envelope)?)
    }

    fn delete(&self, account: &str) -> Result<()> {
        delete_secure(&self.directory, &self.path(account))
    }
}

/// OS credentials are preferred. A configured Argon2id + AES-256-GCM file
/// store is used only when the platform keyring is unavailable.
pub struct CredentialStore {
    primary: Box<dyn SecretStore>,
    fallback: Box<dyn SecretStore>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialStore")
            .field("primary", &"OS keyring")
            .field("fallback", &"encrypted file")
            .finish()
    }
}

impl CredentialStore {
    #[must_use]
    pub fn new(primary: impl SecretStore + 'static, fallback: impl SecretStore + 'static) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
        }
    }
}

impl SecretStore for CredentialStore {
    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        match self.primary.get(account) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => Ok(None),
            Err(GcpError::CredentialStorageUnavailable(_)) => self.fallback.get(account),
            Err(error) => Err(error),
        }
    }

    fn set(&self, account: &str, value: &SecretString) -> Result<()> {
        match self.primary.set(account, value) {
            Ok(()) => {
                self.fallback.delete(account)?;
                Ok(())
            }
            Err(GcpError::CredentialStorageUnavailable(_)) => self.fallback.set(account, value),
            Err(error) => Err(error),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        match self.primary.delete(account) {
            Ok(()) | Err(GcpError::CredentialStorageUnavailable(_)) => {
                self.fallback.delete(account)
            }
            Err(error) => Err(error),
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "keyring map_err callbacks consume their error value"
)]
fn classify_keyring_error(error: keyring::Error) -> GcpError {
    match error {
        keyring::Error::NoDefaultStore | keyring::Error::NotSupportedByStore(_) => {
            GcpError::CredentialStorageUnavailable(error.to_string())
        }
        _ => GcpError::CredentialStorage(error.to_string()),
    }
}

fn decode_field(name: &str, value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| GcpError::CredentialStorage(format!("credential {name} is invalid")))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(target_os = "linux")]
fn open_secure_directory(directory: &Path, create: bool) -> Result<std::os::fd::OwnedFd> {
    use std::path::Component;

    use rustix::fs::{CWD, Mode, OFlags, fchmod, mkdirat, openat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut descriptor = openat(
        CWD,
        if directory.is_absolute() { "/" } else { "." },
        flags,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    let mut saw_normal_component = false;
    for component in directory.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(GcpError::CredentialStorage(
                    "credential directory may not contain parent or platform-prefix components"
                        .into(),
                ));
            }
        };
        saw_normal_component = true;
        let next = match openat(&descriptor, name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(error) if create && error == rustix::io::Errno::NOENT => {
                match mkdirat(&descriptor, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(rustix_io(error)),
                }
                openat(&descriptor, name, flags, Mode::empty()).map_err(rustix_io)?
            }
            Err(error) => return Err(rustix_io(error)),
        };
        descriptor = next;
    }
    if !saw_normal_component {
        return Err(GcpError::CredentialStorage(
            "credential directory must name a dedicated directory".into(),
        ));
    }
    validate_directory_descriptor(&descriptor, false)?;
    if create {
        fchmod(&descriptor, Mode::from_raw_mode(0o700)).map_err(rustix_io)?;
    }
    validate_directory_descriptor(&descriptor, true)?;
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn validate_directory_descriptor(
    descriptor: &impl std::os::fd::AsFd,
    require_restricted_mode: bool,
) -> Result<()> {
    use rustix::fs::{FileType, fstat};

    let metadata = fstat(descriptor).map_err(rustix_io)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || (require_restricted_mode && metadata.st_mode & 0o077 != 0)
    {
        return Err(GcpError::CredentialStorage(
            "credential directory has an unsafe type, owner, or mode".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_file_descriptor(descriptor: &impl std::os::fd::AsFd) -> Result<()> {
    use rustix::fs::{FileType, fstat};

    let metadata = fstat(descriptor).map_err(rustix_io)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_nlink != 1
    {
        return Err(GcpError::CredentialStorage(
            "credential file has an unsafe type, owner, mode, or link count".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn credential_name(path: &Path) -> Result<&std::ffi::OsStr> {
    path.file_name()
        .ok_or_else(|| GcpError::CredentialStorage("credential path has no file name".into()))
}

#[cfg(target_os = "linux")]
fn read_secure(directory: &Path, path: &Path) -> Result<Option<Vec<u8>>> {
    use rustix::fs::{Mode, OFlags, openat};

    let directory = match open_secure_directory(directory, false) {
        Ok(directory) => directory,
        Err(GcpError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let descriptor = match openat(
        &directory,
        credential_name(path)?,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(rustix_io(error)),
    };
    validate_file_descriptor(&descriptor)?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn atomic_write_secure(directory: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, fchmod, fsync, openat, renameat, unlinkat};

    let directory = open_secure_directory(directory, true)?;
    let destination = credential_name(path)?;
    match openat(
        &directory,
        destination,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(existing) => validate_file_descriptor(&existing)?,
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => return Err(rustix_io(error)),
    }
    let temporary = format!(".credential-{:032x}.tmp", rand::random::<u128>());
    let descriptor = openat(
        &directory,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(rustix_io)?;
    let result = (|| {
        fchmod(&descriptor, Mode::from_raw_mode(0o600)).map_err(rustix_io)?;
        validate_file_descriptor(&descriptor)?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_directory_descriptor(&directory, true)?;
        renameat(&directory, &temporary, &directory, destination).map_err(rustix_io)?;
        fsync(&directory).map_err(rustix_io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(&directory, &temporary, AtFlags::empty());
    }
    result
}

#[cfg(target_os = "linux")]
fn delete_secure(directory: &Path, path: &Path) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, fsync, openat, unlinkat};

    let directory = match open_secure_directory(directory, false) {
        Ok(directory) => directory,
        Err(GcpError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let name = credential_name(path)?;
    let descriptor = match openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
        Err(error) => return Err(rustix_io(error)),
    };
    validate_file_descriptor(&descriptor)?;
    validate_directory_descriptor(&directory, true)?;
    unlinkat(&directory, name, AtFlags::empty()).map_err(rustix_io)?;
    fsync(&directory).map_err(rustix_io)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn rustix_io(error: rustix::io::Errno) -> GcpError {
    std::io::Error::from_raw_os_error(error.raw_os_error()).into()
}

#[cfg(not(target_os = "linux"))]
fn read_secure(_directory: &Path, path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn atomic_write_secure(directory: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(directory)?;
    set_directory_permissions(directory)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    set_file_permissions(path)
}

#[cfg(not(target_os = "linux"))]
fn delete_secure(_directory: &Path, path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use secrecy::{ExposeSecret as _, SecretString};

    use super::{CredentialStore, EncryptedFileStore, PassphraseProvider, SecretStore};
    use crate::{GcpError, Result};

    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        passphrase: &'static str,
    }

    impl PassphraseProvider for CountingProvider {
        fn passphrase(&self) -> Result<SecretString> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from(self.passphrase))
        }
    }

    enum PrimaryValue {
        Present(&'static str),
        Missing,
        Unavailable,
        Failure,
    }

    struct FakePrimaryStore(PrimaryValue);

    impl SecretStore for FakePrimaryStore {
        fn get(&self, _account: &str) -> Result<Option<SecretString>> {
            match self.0 {
                PrimaryValue::Present(value) => Ok(Some(SecretString::from(value))),
                PrimaryValue::Missing => Ok(None),
                PrimaryValue::Unavailable => Err(GcpError::CredentialStorageUnavailable(
                    "no keyring backend".into(),
                )),
                PrimaryValue::Failure => Err(GcpError::CredentialStorage("keyring locked".into())),
            }
        }

        fn set(&self, _account: &str, _value: &SecretString) -> Result<()> {
            Ok(())
        }

        fn delete(&self, _account: &str) -> Result<()> {
            Ok(())
        }
    }

    struct SetPrimaryStore {
        unavailable: bool,
    }

    impl SecretStore for SetPrimaryStore {
        fn get(&self, _account: &str) -> Result<Option<SecretString>> {
            Ok(None)
        }

        fn set(&self, _account: &str, _value: &SecretString) -> Result<()> {
            if self.unavailable {
                Err(GcpError::CredentialStorageUnavailable(
                    "no keyring backend".into(),
                ))
            } else {
                Err(GcpError::CredentialStorage("keyring locked".into()))
            }
        }

        fn delete(&self, _account: &str) -> Result<()> {
            Ok(())
        }
    }

    fn counting_provider(
        calls: &Arc<AtomicUsize>,
        passphrase: &'static str,
    ) -> Arc<dyn PassphraseProvider> {
        Arc::new(CountingProvider {
            calls: Arc::clone(calls),
            passphrase,
        })
    }

    #[test]
    fn primary_secret_does_not_request_fallback_passphrase() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let store = CredentialStore::new(
            FakePrimaryStore(PrimaryValue::Present("keyring-secret")),
            fallback,
        );

        let loaded = store
            .get("operator@example.com")
            .expect("load")
            .expect("present");

        assert_eq!(loaded.expose_secret(), "keyring-secret");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_primary_does_not_read_stale_fallback() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        fallback
            .set(
                "operator@example.com",
                &SecretString::from("stale-fallback-secret"),
            )
            .expect("seed fallback");
        calls.store(0, Ordering::SeqCst);
        let store = CredentialStore::new(FakePrimaryStore(PrimaryValue::Missing), fallback);

        assert!(store.get("operator@example.com").expect("load").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn explicitly_unavailable_primary_uses_existing_fallback() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        fallback
            .set(
                "operator@example.com",
                &SecretString::from("fallback-secret"),
            )
            .expect("seed fallback");
        calls.store(0, Ordering::SeqCst);
        let store = CredentialStore::new(FakePrimaryStore(PrimaryValue::Unavailable), fallback);

        let loaded = store
            .get("operator@example.com")
            .expect("fallback load")
            .expect("fallback present");

        assert_eq!(loaded.expose_secret(), "fallback-secret");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn primary_failure_does_not_read_or_write_fallback() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let get_store = CredentialStore::new(FakePrimaryStore(PrimaryValue::Failure), fallback);
        assert!(matches!(
            get_store.get("operator@example.com"),
            Err(GcpError::CredentialStorage(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let write_fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-write-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let set_store =
            CredentialStore::new(SetPrimaryStore { unavailable: false }, write_fallback);
        assert!(matches!(
            set_store.set("operator@example.com", &SecretString::from("new-secret")),
            Err(GcpError::CredentialStorage(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn primary_unavailable_allows_fallback_write() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let store = CredentialStore::new(SetPrimaryStore { unavailable: true }, fallback);

        store
            .set(
                "operator@example.com",
                &SecretString::from("fallback-secret"),
            )
            .expect("fallback write");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fallback_requests_passphrase_only_when_encrypting_or_decrypting() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let store = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let secret = SecretString::from("refresh-token-super-secret");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        store.set("operator@example.com", &secret).expect("store");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let loaded = store
            .get("operator@example.com")
            .expect("load")
            .expect("present");

        assert_eq!(loaded.expose_secret(), secret.expose_secret());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn encrypted_file_round_trip_does_not_contain_secret() {
        let directory = tempfile::tempdir().expect("tempdir");
        let passphrase = "correct horse battery staple";
        let store = EncryptedFileStore::new(
            directory.path(),
            "dirextalk-test",
            SecretString::from(passphrase),
        );
        let secret = SecretString::from("refresh-token-super-secret");
        store.set("operator@example.com", &secret).expect("store");

        let raw = std::fs::read_to_string(
            std::fs::read_dir(directory.path())
                .expect("read dir")
                .next()
                .expect("entry")
                .expect("valid entry")
                .path(),
        )
        .expect("read envelope");
        assert!(!raw.contains(secret.expose_secret()));
        assert!(!raw.contains(passphrase));
        let loaded = store
            .get("operator@example.com")
            .expect("load")
            .expect("present");
        assert_eq!(loaded.expose_secret(), secret.expose_secret());
        let debug = format!("{store:?}");
        assert!(!debug.contains(secret.expose_secret()));
        assert!(!debug.contains(passphrase));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn encrypted_file_rejects_weak_provider_passphrase_when_used() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let store = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "too-short"),
        );
        assert!(
            store
                .set("operator@example.com", &SecretString::from("refresh-token"))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn encrypted_file_rejects_symlinked_directory_without_prompting() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("real");
        std::fs::create_dir(&real).expect("real directory");
        let link = root.path().join("credentials");
        symlink(&real, &link).expect("directory symlink");
        let calls = Arc::new(AtomicUsize::new(0));
        let store = EncryptedFileStore::with_passphrase_provider(
            &link,
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );

        assert!(store.get("operator@example.com").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_directory_creation_never_follows_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("real");
        std::fs::create_dir(&real).expect("real directory");
        let link = root.path().join("link");
        symlink(&real, &link).expect("directory symlink");
        let target = link.join("nested");

        assert!(super::open_secure_directory(&target, true).is_err());
        assert!(!real.join("nested").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn encrypted_file_rejects_symlinked_or_insecure_credential() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let store = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let external = directory.path().join("external");
        std::fs::write(&external, b"not a credential").expect("external file");
        std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o600))
            .expect("external mode");
        let credential = store.path("operator@example.com");
        symlink(&external, &credential).expect("credential symlink");
        assert!(store.get("operator@example.com").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        std::fs::remove_file(&credential).expect("remove symlink");
        std::fs::write(&credential, b"not a credential").expect("credential file");
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o644))
            .expect("insecure mode");
        assert!(store.get("operator@example.com").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
